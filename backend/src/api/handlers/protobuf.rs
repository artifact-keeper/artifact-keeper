//! Protobuf/BSR (Buf Schema Registry) format handlers.
//!
//! Implements Connect RPC endpoints compatible with `buf push`, `buf pull`,
//! and the BSR module/commit/label services.
//!
//! Each endpoint serves both Connect codecs: the JSON shapes defined below,
//! and the binary protobuf codec the `buf` CLI actually speaks, whose
//! messages, identifiers and digests live in `protobuf_wire` (#5066).
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

use std::io::Write;

use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::header::CONTENT_TYPE;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::Extension;
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

use crate::api::handlers::protobuf_wire as wire;
use crate::api::handlers::protobuf_wire::proto::{v1 as pb1, v1beta1 as pb1b};
use crate::api::handlers::protobuf_wire::{ids, Codec};
use crate::api::handlers::proxy_helpers::{self, RepoInfo};
use crate::api::middleware::auth::{require_auth_basic_scope, AuthExtension};
use crate::api::SharedState;
use crate::models::repository::RepositoryType;

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
            "/:repo_key/buf.registry.module.v1.UploadService/Upload",
            post(upload_v1),
        )
        .route(
            "/:repo_key/buf.registry.module.v1beta1.UploadService/Upload",
            post(upload_v1beta1),
        )
        .route(
            "/:repo_key/buf.registry.module.v1.DownloadService/Download",
            post(download_v1),
        )
        .route(
            "/:repo_key/buf.registry.module.v1beta1.DownloadService/Download",
            post(download_v1beta1),
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
        .route(
            "/:repo_key/buf.registry.owner.v1.OwnerService/GetOwners",
            post(get_owners),
        )
        .route("/:repo_key/*bsr_path", post(catch_all_bsr))
        .layer(DefaultBodyLimit::max(256 * 1024 * 1024)) // 256 MB
}

/// Which `buf.registry.module` package a push or pull arrived on.
///
/// The CLI chooses per call, not per registry: `buf push` uses v1beta1's
/// Upload only when the module depends on a second registry (legacy
/// federation), and Download is chosen by the digest type asked for. A
/// repository answering b5 therefore has to serve both packages and answer
/// each in its own, since the two differ in more than the package name --
/// v1beta1 carries a registry per dependency and the pre-v2 buf.yaml and
/// buf.lock of a module, and numbers its DigestType differently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BsrApi {
    V1,
    V1Beta1,
}

async fn catch_all_bsr(
    State(state): State<SharedState>,
    Path((repo_key, bsr_path)): Path<(String, String)>,
    headers: HeaderMap,
    Extension(auth): Extension<Option<AuthExtension>>,
    body: Bytes,
) -> Result<Response, Response> {
    super::protobuf_bsr::dispatch_unknown_bsr(state, repo_key, bsr_path, headers, body, auth).await
}

// ---------------------------------------------------------------------------
// POST GetOwners
// ---------------------------------------------------------------------------

/// Resolving a dependency the CLI holds only ids for ends here: it asks for
/// the module by id and the owner by id, and composes the module's full name
/// from the two. Reached when a consumer pins a module whose own dependencies
/// it never named, so without this a dependency chain stops with
/// `unimplemented: 'buf.registry.owner.v1.OwnerService/GetOwners'`.
async fn get_owners(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Response> {
    let codec = Codec::from_headers(&headers)?;
    let body: GetOwnersRequest = codec.decode(&body, GetOwnersRequest::from_pb)?;
    let repo = resolve_protobuf_repo(&state.db, &repo_key).await?;

    let mut owners = Vec::with_capacity(body.owner_refs.len());
    for owner_ref in &body.owner_refs {
        let name = resolve_owner_ref(&state, &repo, owner_ref).await?;
        owners.push(OwnerInfo {
            organization: OrganizationInfo {
                id: ids::owner(&name),
                name,
            },
        });
    }

    let resp = GetOwnersResponse { owners };
    if codec.is_proto() {
        return Ok(wire::respond_proto(
            &wire::proto::owner_v1::GetOwnersResponse {
                owners: resp
                    .owners
                    .iter()
                    .map(|owner| wire::proto::owner_v1::Owner {
                        value: Some(wire::proto::owner_v1::owner::Value::Organization(
                            wire::proto::owner_v1::Organization {
                                id: owner.organization.id.clone(),
                                create_time: None,
                                update_time: None,
                                name: owner.organization.name.clone(),
                            },
                        )),
                    })
                    .collect(),
            },
        ));
    }
    Ok(wire::respond_json(&resp))
}

/// The owner an `OwnerRef` names: the first segment of a module name this
/// repository holds.
///
/// An owner id is derived from that segment and resolved like the other ids
/// -- from what was recorded at push time, falling back to deriving the id of
/// each owner the repository holds. The reply is positional, so an owner that
/// owns nothing here is `not_found` rather than an entry the CLI would pair
/// with the wrong reference.
async fn resolve_owner_ref(
    state: &SharedState,
    repo: &RepoInfo,
    owner_ref: &OwnerRef,
) -> Result<String, Response> {
    if let Some(name) = owner_ref.name.as_deref().filter(|n| !n.is_empty()) {
        let exists: Option<String> = sqlx::query_scalar(
            r#"SELECT name
            FROM artifacts
            WHERE repository_id = $1
              AND name LIKE $2 || '/%'
              AND is_deleted = false
            LIMIT 1"#,
        )
        .bind(repo.id)
        .bind(name)
        .fetch_optional(&state.db)
        .await
        .map_err(connect_db_error)?;
        if exists.is_none() {
            return Err(connect_error(
                StatusCode::NOT_FOUND,
                "not_found",
                &format!("owner {name} owns no module in this repository"),
            ));
        }
        return Ok(name.to_string());
    }

    let id = owner_ref.id.as_deref().ok_or_else(|| {
        connect_error(
            StatusCode::BAD_REQUEST,
            "invalid_argument",
            "Owner reference must specify id or name",
        )
    })?;

    let recorded: Option<String> = sqlx::query_scalar(
        r#"SELECT m.metadata->>'module'
        FROM artifacts a
        JOIN artifact_metadata m ON m.artifact_id = a.id
        WHERE a.repository_id = $1
          AND a.is_deleted = false
          AND m.metadata->>'ownerId' = $2
        LIMIT 1"#,
    )
    .bind(repo.id)
    .bind(id)
    .fetch_optional(&state.db)
    .await
    .map_err(connect_db_error)?;
    if let Some(module_name) = recorded {
        return Ok(owner_of(&module_name).to_string());
    }

    let names: Vec<String> = sqlx::query_scalar(
        r#"SELECT DISTINCT name
        FROM artifacts
        WHERE repository_id = $1
          AND version IS DISTINCT FROM '_labels'
          AND is_deleted = false"#,
    )
    .bind(repo.id)
    .fetch_all(&state.db)
    .await
    .map_err(connect_db_error)?;

    names
        .iter()
        .map(|name| owner_of(name))
        .find(|owner| ids::owner(owner) == id)
        .map(str::to_string)
        .ok_or_else(|| {
            connect_error(
                StatusCode::NOT_FOUND,
                "not_found",
                &format!("owner {id} not found"),
            )
        })
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
    /// The schema's `name`, which is the module alone: `buf` composes
    /// `registry/owner/name` itself and rejects a name containing a slash
    /// ("name \"acme/payments\" cannot contain slashes"), which stopped a
    /// consumer resolving a dependency it held only ids for.
    name: String,
    /// `owner/module`: what the repository keys on and what every derived id
    /// is a function of, so it is not interchangeable with `name`. Not part
    /// of any reply.
    #[serde(skip)]
    full_name: String,
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

// -- GetOwners

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct OwnerRef {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    name: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GetOwnersRequest {
    #[serde(default)]
    owner_refs: Vec<OwnerRef>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct OrganizationInfo {
    id: String,
    name: String,
}

/// The reply's oneof as JSON names it. An owner here is the first segment of
/// a module name -- a namespace, not a person -- so it is an organization.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct OwnerInfo {
    organization: OrganizationInfo,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct GetOwnersResponse {
    owners: Vec<OwnerInfo>,
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

pub(crate) fn connect_error(status: StatusCode, code: &str, message: &str) -> Response {
    // The database sites pass `db_status(&e)` with `internal`; a 503 there
    // (saturated pool, unreachable database) is Connect's retryable
    // `unavailable`, the code Connect itself maps HTTP 503 to (#4765).
    let code = if status == StatusCode::SERVICE_UNAVAILABLE && code == "internal" {
        "unavailable"
    } else {
        code
    };
    let body = serde_json::json!({ "code": code, "message": message });
    super::with_retry_after_on_503(
        Response::builder()
            .status(status)
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_string(&body).unwrap()))
            .unwrap(),
    )
}

/// A database failure as the Connect `internal` error.
fn connect_db_error(e: sqlx::Error) -> Response {
    connect_error(
        crate::api::handlers::db_status(&e),
        "internal",
        crate::api::handlers::db_err_message(&e),
    )
}

/// #4422: a storage-quota decision as the Connect error an upload answers:
/// `507 resource_exhausted` naming the repository or project quota that
/// refuses it, or `internal` when the check itself failed.
#[allow(clippy::result_large_err)]
fn connect_quota_decision(
    decision: crate::error::Result<Option<crate::services::repository_service::QuotaScope>>,
) -> Result<(), Response> {
    match decision {
        Ok(None) => Ok(()),
        Ok(Some(scope)) => Err(connect_error(
            StatusCode::INSUFFICIENT_STORAGE,
            "resource_exhausted",
            scope.exceeded_message(),
        )),
        Err(e) => {
            tracing::error!("storage quota check failed: {e}");
            Err(connect_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal",
                "storage quota check failed",
            ))
        }
    }
}

// ---------------------------------------------------------------------------
// Repository resolution
// ---------------------------------------------------------------------------

pub(crate) async fn resolve_protobuf_repo(
    db: &PgPool,
    repo_key: &str,
) -> Result<RepoInfo, Response> {
    use sqlx::Row;
    let row = sqlx::query(
        r#"SELECT id, key, storage_backend, storage_path, format::text AS format, repo_type::text AS repo_type, upstream_url, promotion_only
        FROM repositories WHERE key = $1"#,
    )
    .bind(repo_key)
    .fetch_optional(db)
    .await
    .map_err(|e| {
        connect_error(
            crate::api::handlers::db_status(&e),
            "internal",
            crate::api::handlers::db_err_message(&e),
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
        key: row.get("key"),
        storage_path: row.get("storage_path"),
        storage_backend: row.get("storage_backend"),
        repo_type: row.get("repo_type"),
        upstream_url: row.get("upstream_url"),
        promotion_only: row.try_get("promotion_only").unwrap_or(false),
        format: "generic".to_string(),
        age_gate_enabled: false,
        age_gate_min_age_days: 7,
        age_gate_mode: "upstream_publish_time".to_string(),
        curation_enabled: false,
        curation_default_action: "allow".to_string(),
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

/// The module a `ModuleRef` names.
///
/// Like a commit id, a module id is a one-way function of the name
/// (`protobuf_wire::ids`), so it is matched by deriving the id of each module
/// the repository holds -- `buf dep update` asks for its dependency's module
/// by id, and reading the id as a name answered "module <tuuid> not found".
/// An id that matches nothing is left to mean a module name, which is what
/// the JSON callers send.
async fn resolve_module_ref(
    state: &SharedState,
    repo: &RepoInfo,
    module_ref: &ModuleRef,
) -> Result<String, Response> {
    if let (Some(owner), Some(module)) = (&module_ref.owner, &module_ref.module) {
        return Ok(format!("{}/{}", owner, module));
    }
    let id = module_ref.id.as_deref().ok_or_else(|| {
        connect_error(
            StatusCode::BAD_REQUEST,
            "invalid_argument",
            "Module reference must specify owner/module or id",
        )
    })?;

    let recorded: Option<String> = sqlx::query_scalar(
        r#"SELECT a.name
        FROM artifacts a
        JOIN artifact_metadata m ON m.artifact_id = a.id
        WHERE a.repository_id = $1
          AND a.is_deleted = false
          AND m.metadata->>'moduleId' = $2
        LIMIT 1"#,
    )
    .bind(repo.id)
    .bind(id)
    .fetch_optional(&state.db)
    .await
    .map_err(connect_db_error)?;
    if let Some(name) = recorded {
        return Ok(name);
    }

    // A commit pushed before the id was recorded has nothing to match, so the
    // id is derived for each module the repository holds. This is a scan on a
    // path a public repository serves unauthenticated, bounded by the number
    // of modules; it is a fallback for those commits, not the way a reference
    // by id is normally resolved.
    let names: Vec<String> = sqlx::query_scalar(
        r#"SELECT DISTINCT name
        FROM artifacts
        WHERE repository_id = $1
          AND version IS DISTINCT FROM '_labels'
          AND is_deleted = false"#,
    )
    .bind(repo.id)
    .fetch_all(&state.db)
    .await
    .map_err(connect_db_error)?;

    Ok(names
        .into_iter()
        .find(|name| ids::module(name) == id)
        .unwrap_or_else(|| id.to_string()))
}

/// The module and commit a `ResourceRef` names.
///
/// The CLI addresses a commit by the tuuid this repository derives, and that
/// derivation is one-way, so an id is resolved through the `commitId`
/// recorded next to the commit at push time rather than from any column --
/// `buf dep update` asks for its dependency this way and was answered
/// "Module '<tuuid>' not found" when the id was read as a module name. A
/// `ref` is a label or a commit id and the CLI does not say which, so the
/// label index is consulted first and the id second. An id that is neither
/// is left to mean a module name, which is what the JSON callers send.
async fn resolve_resource_ref(
    state: &SharedState,
    repo: &RepoInfo,
    resource_ref: &ResourceRef,
) -> Result<(String, Option<String>), Response> {
    if let (Some(owner), Some(module)) = (&resource_ref.owner, &resource_ref.module) {
        let module_name = format!("{}/{}", owner, module);
        let digest = match &resource_ref.label {
            // A `ref` that is neither a label nor a commit id of this
            // repository resolves to nothing, and the reply is positional, so
            // a mistyped label would otherwise be served the module's latest
            // commit as though it had been asked for.
            Some(r) => match resolve_commit_by_label(&state.db, repo.id, &module_name, r).await {
                Some(digest) => Some(digest),
                None => match commit_by_derived_id(state, repo, r).await? {
                    Some((_, version)) => Some(version),
                    None => {
                        return Err(connect_error(
                            StatusCode::NOT_FOUND,
                            "not_found",
                            &format!("module {module_name} has no label or commit '{r}'"),
                        ));
                    }
                },
            },
            None => None,
        };
        return Ok((module_name, digest));
    }

    let id = resource_ref.id.as_deref().ok_or_else(|| {
        connect_error(
            StatusCode::BAD_REQUEST,
            "invalid_argument",
            "Resource reference must specify owner/module or id",
        )
    })?;
    if let Some((module_name, version)) = commit_by_derived_id(state, repo, id).await? {
        return Ok((module_name, Some(version)));
    }
    Ok((id.to_string(), None))
}

/// The module name and stored digest of the commit a derived tuuid names.
async fn commit_by_derived_id(
    state: &SharedState,
    repo: &RepoInfo,
    commit_id: &str,
) -> Result<Option<(String, String)>, Response> {
    let row = sqlx::query(
        r#"SELECT a.name, a.version
        FROM artifacts a
        JOIN artifact_metadata m ON m.artifact_id = a.id
        WHERE a.repository_id = $1
          AND a.is_deleted = false
          AND m.metadata->>'commitId' = $2
        LIMIT 1"#,
    )
    .bind(repo.id)
    .bind(commit_id)
    .fetch_optional(&state.db)
    .await
    .map_err(connect_db_error)?;

    Ok(row.map(|r| (r.get("name"), r.get("version"))))
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
                    crate::api::handlers::internal_err_message("Failed to build tar archive", &e),
                )
            })?;
    }

    let tar_data = tar_builder.into_inner().map_err(|e| {
        connect_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            crate::api::handlers::internal_err_message("Failed to finalize tar archive", &e),
        )
    })?;

    let mut gz_encoder = GzEncoder::new(Vec::new(), Compression::default());
    gz_encoder.write_all(&tar_data).map_err(|e| {
        connect_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            crate::api::handlers::internal_err_message("Failed to compress bundle", &e),
        )
    })?;

    gz_encoder.finish().map_err(|e| {
        connect_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            crate::api::handlers::internal_err_message("Failed to finalize gzip", &e),
        )
    })
}

#[allow(clippy::result_large_err)]
fn extract_files_from_bundle(data: &[u8]) -> Result<Vec<DownloadFile>, Response> {
    use crate::util::bounded_archive::{
        budgeted, max_ingest_archive_entries, read_capped, MAX_INGEST_METADATA_ENTRY_BYTES,
    };

    // This extractor reads EVERY entry into memory and base64-encodes it (~1.33x
    // amplification on top of decompression), so it is the worst in-memory site.
    // Wrap the gzip stream in the shared total-byte budget (#2556) so a crafted
    // bundle aborts mid-inflate, and enforce the entry-count + per-entry caps so
    // worst-case buffered memory is deterministic.
    let gz_decoder = GzDecoder::new(data);
    let mut archive = tar::Archive::new(budgeted(gz_decoder));

    let mut files = Vec::new();
    let max_entries = max_ingest_archive_entries();
    let mut entries_seen: u64 = 0;

    for entry_result in archive.entries().map_err(|e| {
        connect_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            crate::api::handlers::internal_err_message("Failed to read tar archive", &e),
        )
    })? {
        let mut entry = entry_result.map_err(|e| {
            connect_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal",
                crate::api::handlers::internal_err_message("Failed to read tar entry", &e),
            )
        })?;

        entries_seen += 1;
        if entries_seen > max_entries {
            return Err(connect_error(
                StatusCode::BAD_REQUEST,
                "invalid_argument",
                &format!(
                    "Bundle contains too many entries (> {}); refusing suspected decompression bomb",
                    max_entries
                ),
            ));
        }

        let path = entry
            .path()
            .map_err(|e| {
                connect_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal",
                    crate::api::handlers::internal_err_message("Failed to read entry path", &e),
                )
            })?
            .to_string_lossy()
            .to_string();

        let content_bytes =
            read_capped(&mut entry, MAX_INGEST_METADATA_ENTRY_BYTES, "bundle entry").map_err(
                |e| connect_error(StatusCode::BAD_REQUEST, "invalid_argument", &e.to_string()),
            )?;

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
    let label_path = build_label_path(module_name);

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
            crate::api::handlers::db_status(&e),
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

/// Save the label index for a module. Creates or updates the `_labels` artifact.
///
/// #4889: the index used to be a zero-byte row with checksum `none`, so the
/// push-sync worker had no object to transfer and a label move never reached
/// peers. Store the rendered label document in content-addressed storage and
/// queue a normal push after the row and metadata are committed. The peer's
/// generic upload path refreshes the row in place (the `_labels` path is a
/// known mutable index) so an updated label map replaces the old one.
async fn save_label_index(
    state: &SharedState,
    repo: &RepoInfo,
    module_name: &str,
    labels: &serde_json::Map<String, serde_json::Value>,
    user_id: uuid::Uuid,
    headers: &HeaderMap,
) -> Result<(), Response> {
    let label_path = build_label_path(module_name);
    let storage = state.storage_for_repo_or_500(&repo.storage_location())?;

    // Write the row and its metadata together: a sync task must never observe
    // a row whose label document is still the previous revision.
    let mut tx = state.db.begin().await.map_err(|e| {
        connect_error(
            crate::api::handlers::db_status(&e),
            "internal",
            crate::api::handlers::db_err_message(&e),
        )
    })?;

    // #4916: the label document carries a monotonic revision so a peer that
    // receives a delayed or simultaneous move can compare it with the index it
    // already holds instead of blindly applying the last writer. Allocate the
    // revision under a per-module advisory lock and store the doc in the same
    // transaction, so two local moves cannot both claim the same revision
    // (the row lock alone does not serialise the first write, when no row
    // exists yet).
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(format!(
            "protobuf-label\u{1f}{}\u{1f}{}",
            repo.id, label_path
        ))
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            connect_error(
                crate::api::handlers::db_status(&e),
                "internal",
                crate::api::handlers::db_err_message(&e),
            )
        })?;
    let previous: Option<(uuid::Uuid, String, Option<serde_json::Value>)> = sqlx::query_as(
        r#"SELECT a.id, a.storage_key, am.metadata
        FROM artifacts a
        LEFT JOIN artifact_metadata am ON am.artifact_id = a.id
        WHERE a.repository_id = $1
          AND a.path = $2
        FOR UPDATE OF a"#,
    )
    .bind(repo.id)
    .bind(&label_path)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| {
        connect_error(
            crate::api::handlers::db_status(&e),
            "internal",
            crate::api::handlers::db_err_message(&e),
        )
    })?;
    let previous_storage_key = previous.as_ref().map(|(_, key, _)| key.clone());
    let revision = previous
        .as_ref()
        .and_then(|(_, _, metadata)| metadata.as_ref())
        .and_then(|metadata| metadata.get("revision"))
        .and_then(|revision| revision.as_i64())
        .unwrap_or(0)
        + 1;
    let metadata = serde_json::json!({ "labels": labels, "revision": revision });
    let bytes = Bytes::from(serde_json::to_vec(&metadata).map_err(|e| {
        connect_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            crate::api::handlers::internal_err_message("Failed to serialize label index", &e),
        )
    })?);
    let size_bytes = bytes.len() as i64;
    let checksum_sha256 = format!("{:x}", Sha256::digest(&bytes));
    let storage_key = crate::services::artifact_service::ArtifactService::storage_key_from_checksum(
        &checksum_sha256,
    );
    storage.put(&storage_key, bytes).await.map_err(|e| {
        connect_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            crate::api::handlers::storage_err_message(&e),
        )
    })?;

    // NO-SCAN-ON-UPLOAD: the `_labels` index is a registry-generated JSON
    // document, not uploaded content; the module upload itself triggers the
    // scan (#4166).
    // NO-QUOTA-ADMISSION: the generated `_labels` index is a few bytes the
    // registry writes for an already-admitted module commit (#4422).
    let artifact_id: uuid::Uuid = sqlx::query_scalar(
        r#"INSERT INTO artifacts (
            repository_id, path, name, version, size_bytes,
            checksum_sha256, content_type, storage_key, uploaded_by
        )
        VALUES ($1, $2, $3, '_labels', $4, $5, 'application/json', $6, $7)
        ON CONFLICT (repository_id, path) DO UPDATE SET
            name = EXCLUDED.name,
            version = EXCLUDED.version,
            size_bytes = EXCLUDED.size_bytes,
            checksum_sha256 = EXCLUDED.checksum_sha256,
            content_type = EXCLUDED.content_type,
            storage_key = EXCLUDED.storage_key,
            uploaded_by = EXCLUDED.uploaded_by,
            is_deleted = false,
            updated_at = NOW()
        RETURNING id"#,
    )
    .bind(repo.id)
    .bind(&label_path)
    .bind(module_name)
    .bind(size_bytes)
    .bind(&checksum_sha256)
    .bind(&storage_key)
    .bind(user_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| {
        connect_error(
            crate::api::handlers::db_status(&e),
            "internal",
            &format!("Database error creating label index: {}", e),
        )
    })?;

    sqlx::query(
        r#"INSERT INTO artifact_metadata (artifact_id, format, metadata)
        VALUES ($1, 'protobuf', $2)
        ON CONFLICT (artifact_id) DO UPDATE SET metadata = $2"#,
    )
    .bind(artifact_id)
    .bind(&metadata)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        connect_error(
            crate::api::handlers::db_status(&e),
            "internal",
            &format!("Database error saving labels: {}", e),
        )
    })?;

    tx.commit().await.map_err(|e| {
        connect_error(
            crate::api::handlers::db_status(&e),
            "internal",
            crate::api::handlers::db_err_message(&e),
        )
    })?;

    // #4916: the previous label document is content-addressed and immutable,
    // so the upsert replaced the row's pointer but left its object behind.
    // Delete it once no live row on the same backend still names it (two
    // modules can legitimately dedupe to one document). Best-effort: a failed
    // delete leaks an object, never a row.
    if let Some(previous_storage_key) = previous_storage_key {
        if previous_storage_key != storage_key
            && previous_storage_key != "none"
            && previous_storage_key != label_path
        {
            let still_referenced = sqlx::query_scalar::<_, bool>(
                r#"SELECT EXISTS (
                    SELECT 1
                    FROM artifacts a
                    JOIN repositories r ON r.id = a.repository_id
                    WHERE a.storage_key = $1
                      AND a.is_deleted = false
                      AND r.storage_backend = $2
                      AND (r.storage_backend <> 'filesystem' OR r.storage_path = $3)
                    UNION ALL
                    SELECT 1
                    FROM artifact_versions av
                    JOIN repositories r ON r.id = av.repository_id
                    WHERE av.storage_key = $1
                      AND r.storage_backend = $2
                      AND (r.storage_backend <> 'filesystem' OR r.storage_path = $3)
                )"#,
            )
            .bind(&previous_storage_key)
            .bind(&repo.storage_backend)
            .bind(&repo.storage_path)
            .fetch_one(&state.db)
            .await
            .unwrap_or(true);
            if !still_referenced {
                if let Err(e) = storage.delete(&previous_storage_key).await {
                    tracing::warn!(
                        storage_key = %previous_storage_key,
                        error = %e,
                        "failed to delete a superseded protobuf label document"
                    );
                }
            }
        }
    }

    // #4725/#4889: fan the label index out like any other upload (the helper
    // skips a write that is itself a replication). The sync worker sends the
    // JSON bytes and the `protobuf` metadata document; the receiver's generic
    // upload restores both.
    super::queue_push_sync_tasks_for_upload(
        &state.db,
        headers,
        repo.id,
        artifact_id,
        &label_path,
        size_bytes,
    )
    .await;

    Ok(())
}

/// Update labels for a module, mapping each label name to a commit digest.
async fn update_labels(
    state: &SharedState,
    repo: &RepoInfo,
    module_name: &str,
    label_refs: &[LabelRef],
    commit_digest: &str,
    user_id: uuid::Uuid,
    headers: &HeaderMap,
) -> Result<(), Response> {
    if label_refs.is_empty() {
        return Ok(());
    }

    let mut labels = load_label_index(&state.db, repo.id, module_name).await?;

    for label_ref in label_refs {
        labels.insert(
            label_ref.name.clone(),
            serde_json::Value::String(commit_digest.to_string()),
        );
    }

    save_label_index(state, repo, module_name, &labels, user_id, headers).await
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
        name: module_of(&name).to_string(),
        full_name: name,
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
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Response> {
    let codec = Codec::from_headers(&headers)?;
    let body: GetModulesRequest = codec.decode(&body, GetModulesRequest::from_pb)?;
    let repo = resolve_protobuf_repo(&state.db, &repo_key).await?;

    let mut modules = Vec::new();

    for module_ref in &body.module_refs {
        let module_name = resolve_module_ref(&state, &repo, module_ref).await?;

        // The label index is a real artifact row since #4889, sharing the
        // module's `name` and written after the commit in the same push. So
        // every latest-by-name query here answers with the index rather than
        // a commit unless it excludes that `version`, and the index's
        // storage object is a JSON document: `buf dep update` resolving a
        // dependency came back 500 "invalid gzip header" from reading it as
        // a commit bundle. `IS DISTINCT FROM` because `version` is nullable
        // and `<>` would drop a NULL-version row along with the index.
        let row = sqlx::query(
            r#"SELECT DISTINCT ON (name)
                id, name, created_at, updated_at, uploaded_by
            FROM artifacts
            WHERE repository_id = $1
              AND name = $2
              AND version IS DISTINCT FROM '_labels'
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
                crate::api::handlers::db_status(&e),
                "internal",
                crate::api::handlers::db_err_message(&e),
            )
        })?;

        match row {
            Some(row) => modules.push(build_module_info_from_row(&row)),
            // The CLI pairs refs with modules positionally and reports a short
            // list as a bug in itself ("expected 1 Module, found 0"), and
            // `buf push --create` decides to create the module from exactly
            // this not_found. An empty list in place of the error strands
            // both: nothing is created and the push cannot proceed.
            None => {
                return Err(connect_error(
                    StatusCode::NOT_FOUND,
                    "not_found",
                    &format!("module {module_name} not found"),
                ));
            }
        }
    }

    let resp = GetModulesResponse { modules };
    if codec.is_proto() {
        return Ok(wire::respond_proto(&pb1::GetModulesResponse {
            modules: resp.modules.iter().map(pb_module).collect(),
        }));
    }
    Ok(wire::respond_json(&resp))
}

// ---------------------------------------------------------------------------
// POST CreateModules
// ---------------------------------------------------------------------------

async fn create_modules(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(repo_key): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Response> {
    // GHSA-vvc3-h39c-mrq5: enforce token scope before processing.
    let _user_id = require_auth_basic_scope(auth, "protobuf", "write:artifacts")?.user_id;
    let repo = resolve_protobuf_repo(&state.db, &repo_key).await?;

    proxy_helpers::reject_write_if_not_hosted(&repo.repo_type)?;
    repo.reject_if_promotion_only(false)?;

    // CreateModules is implicitly handled during upload: a module exists from
    // its first push, so the request is acknowledged as it stands.
    let codec = Codec::from_headers(&headers)?;
    if codec.is_proto() {
        let req: pb1::CreateModulesRequest = wire::decode_proto(&body)?;
        let now = chrono::Utc::now().to_rfc3339();
        let modules = req
            .values
            .iter()
            .map(|value| {
                let owner = match value.owner_ref.as_ref().and_then(|o| o.value.clone()) {
                    Some(wire::proto::owner_v1::owner_ref::Value::Name(name)) => name,
                    Some(wire::proto::owner_v1::owner_ref::Value::Id(id)) => id,
                    None => String::new(),
                };
                pb_module(&ModuleInfo {
                    id: String::new(),
                    owner_id: String::new(),
                    name: value.name.clone(),
                    full_name: format!("{}/{}", owner, value.name),
                    create_time: now.clone(),
                    update_time: now.clone(),
                    state: "ACTIVE".to_string(),
                    default_label_name: if value.default_label_name.is_empty() {
                        "main".to_string()
                    } else {
                        value.default_label_name.clone()
                    },
                })
            })
            .collect();
        return Ok(wire::respond_proto(&pb1::CreateModulesResponse { modules }));
    }
    let body: serde_json::Value = wire::decode_json(&body)?;
    Ok(wire::respond_json(&body))
}

// ---------------------------------------------------------------------------
// POST GetCommits
// ---------------------------------------------------------------------------

async fn get_commits(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Response> {
    let codec = Codec::from_headers(&headers)?;
    let body: GetCommitsRequest = codec.decode(&body, GetCommitsRequest::from_pb)?;
    let repo = resolve_protobuf_repo(&state.db, &repo_key).await?;

    let mut commits = Vec::new();

    for resource_ref in &body.resource_refs {
        let (module_name, digest_filter) =
            resolve_resource_ref(&state, &repo, resource_ref).await?;

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
                  AND version IS DISTINCT FROM '_labels'
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
                crate::api::handlers::db_status(&e),
                "internal",
                crate::api::handlers::db_err_message(&e),
            )
        })?;

        match row {
            Some(row) => commits.push(build_commit_info_from_row(&row)),
            // Same positional contract as GetModules: `buf dep update`
            // resolving a dependency rejects a short list outright
            // ("expected 1 Commits, got 0") instead of reading it as absence.
            None => {
                return Err(connect_error(
                    StatusCode::NOT_FOUND,
                    "not_found",
                    &format!("no commit for module {module_name}"),
                ));
            }
        }
    }

    let resp = GetCommitsResponse { commits };
    if codec.is_proto() {
        return Ok(wire::respond_proto(&pb1::GetCommitsResponse {
            commits: pb_commits(&state, &repo, &resp.commits).await?,
        }));
    }
    Ok(wire::respond_json(&resp))
}

// ---------------------------------------------------------------------------
// POST ListCommits
// ---------------------------------------------------------------------------

async fn list_commits(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Response> {
    let codec = Codec::from_headers(&headers)?;
    let body: ListCommitsRequest = codec.decode(&body, ListCommitsRequest::from_pb)?;
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

    let page_size = clamp_page_size(body.page_size, 250);
    let offset: i64 = parse_page_token(body.page_token.as_deref());

    let rows = sqlx::query(
        r#"SELECT id, name, version, created_at, updated_at, uploaded_by, checksum_sha256
        FROM artifacts
        WHERE repository_id = $1
          AND name = $2
          AND version IS DISTINCT FROM '_labels'
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
            crate::api::handlers::db_status(&e),
            "internal",
            crate::api::handlers::db_err_message(&e),
        )
    })?;

    let commits: Vec<CommitInfo> = rows.iter().map(build_commit_info_from_row).collect();

    let next_page_token = compute_next_page_token(commits.len(), page_size, offset);

    let resp = ListCommitsResponse {
        commits,
        next_page_token,
    };
    if codec.is_proto() {
        return Ok(wire::respond_proto(&pb1::ListCommitsResponse {
            next_page_token: resp.next_page_token.clone(),
            commits: pb_commits(&state, &repo, &resp.commits).await?,
        }));
    }
    Ok(wire::respond_json(&resp))
}

// ---------------------------------------------------------------------------
// POST Upload (buf push)
// ---------------------------------------------------------------------------

async fn upload_v1(
    state: State<SharedState>,
    auth: Extension<Option<AuthExtension>>,
    repo_key: Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Response> {
    upload(state, auth, repo_key, headers, body, BsrApi::V1).await
}

async fn upload_v1beta1(
    state: State<SharedState>,
    auth: Extension<Option<AuthExtension>>,
    repo_key: Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Response> {
    upload(state, auth, repo_key, headers, body, BsrApi::V1Beta1).await
}

async fn upload(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(repo_key): Path<String>,
    headers: HeaderMap,
    body: Bytes,
    api: BsrApi,
) -> Result<Response, Response> {
    // GHSA-vvc3-h39c-mrq5: enforce token scope before processing. Before
    // decoding, too: the body limit on these routes is 256 MiB, and an
    // unauthenticated request has no claim on that much work.
    let user_id = require_auth_basic_scope(auth, "protobuf", "write:artifacts")?.user_id;
    let repo = resolve_protobuf_repo(&state.db, &repo_key).await?;

    proxy_helpers::reject_write_if_not_hosted(&repo.repo_type)?;
    repo.reject_if_promotion_only(false)?;

    let codec = Codec::from_headers(&headers)?;
    let body: UploadRequest = match api {
        BsrApi::V1 => codec.decode(&body, UploadRequest::from_pb_v1)?,
        BsrApi::V1Beta1 => codec.decode(&body, UploadRequest::from_pb)?,
    };

    // Both proto packages carry the dependency commit ids once for the whole
    // push, not per module, and the request says nothing about which module
    // imports which -- the reference BSR derives that from the uploaded files
    // themselves. With one module the attribution is unambiguous; with
    // several it would put every dependency into every module's b5
    // composition, and each digest the CLI then verifies would be wrong for a
    // reason nothing states. Refusing names the limit instead.
    if codec.is_proto()
        && body.contents.len() > 1
        && body.contents.iter().any(|c| !c.dep_refs.is_empty())
    {
        return Err(connect_error(
            StatusCode::BAD_REQUEST,
            "failed_precondition",
            "this upload pushes several modules and declares dependencies, which this \
             registry cannot attribute to individual modules: the request carries the \
             dependency commit ids once for the whole push. Push each module that has \
             dependencies on its own.",
        ));
    }

    let mut result_commits = Vec::new();

    for content in &body.contents {
        let module_name = module_name_from_ref(&content.module_ref)?;

        // Decode and hash all files to compute the commit digest. The decoded
        // files outlive the digest: they are also what the b5 digest hashes.
        let mut decoded_files = Vec::with_capacity(content.files.len());
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
            decoded_files.push((file.path.clone(), decoded));
        }
        let commit_digest = compute_commit_digest(&decoded_files);

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
                crate::api::handlers::db_status(&e),
                "internal",
                crate::api::handlers::db_err_message(&e),
            )
        })?;

        if let Some(existing_row) = existing {
            let commit = build_commit_info_from_row(&existing_row);
            result_commits.push(commit);

            // Still update labels if provided
            update_labels(
                &state,
                &repo,
                &module_name,
                &content.label_refs,
                &commit_digest,
                user_id,
                &headers,
            )
            .await?;

            continue;
        }

        // Build tar.gz bundle from files
        let bundle = build_bundle(&content.files)?;
        let bundle_bytes = Bytes::from(bundle);
        let size_bytes = bundle_bytes.len() as i64;
        // #4921: `checksum_sha256` is the sha256 of the stored bundle, the
        // value a replication peer verifies the pushed bytes against. The
        // commit digest is the row's `version` (and `commitDigest` in the
        // protobuf metadata), which is what every lookup keys on.
        let bundle_sha256 = format!("{:x}", Sha256::digest(&bundle_bytes));

        // Refuse an over-quota commit before its bundle is stored (#4422).
        let artifact_path = build_module_artifact_path(&module_name, &commit_digest);
        connect_quota_decision(
            super::publish_quota::preflight_quota_denial(
                &state.db,
                repo.id,
                super::publish_quota::PublishAt::Path(&artifact_path),
                size_bytes,
            )
            .await,
        )?;

        // Store via StorageBackend
        let storage_key = build_module_storage_key(&module_name, &commit_digest);
        proxy_helpers::guard_cross_repo_write(&state, repo.id, &repo.storage_backend, &storage_key)
            .await?;
        let storage = state
            .storage_for_repo(&repo.storage_location())
            .map_err(|e| e.into_response())?;
        storage.put(&storage_key, bundle_bytes).await.map_err(|e| {
            connect_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal",
                crate::api::handlers::storage_err_message(&e),
            )
        })?;

        super::cleanup_soft_deleted_artifact(&state.db, repo.id, &artifact_path).await;

        // Insert artifact record, admitted against the storage quotas in the
        // same transaction (#4422).
        let mut tx = state.db.begin().await.map_err(connect_db_error)?;
        connect_quota_decision(
            super::publish_quota::locked_quota_denial(
                &mut tx,
                &state.db,
                repo.id,
                &artifact_path,
                size_bytes,
            )
            .await,
        )?;
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
        .bind(&bundle_sha256)
        .bind("application/gzip")
        .bind(&storage_key)
        .bind(user_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| {
            connect_error(
                crate::api::handlers::db_status(&e),
                "internal",
                crate::api::handlers::db_err_message(&e),
            )
        })?;
        tx.commit().await.map_err(connect_db_error)?;

        let artifact_id: uuid::Uuid = row.get("id");

        crate::services::quarantine_service::apply_upload_hold_hosted(
            &state.db,
            repo.id,
            artifact_id,
        )
        .await;
        crate::services::scanner_service::trigger_scan_on_upload(
            &state.db,
            state.scanner_service.clone(),
            repo.id,
            artifact_id,
        )
        .await;

        // Build metadata including dependency refs
        let dep_names = extract_dep_names(&content.dep_refs);

        // The digest the CLI verifies this commit against covers every
        // dependency's own b5, which this repository holds only for the
        // modules it hosts itself (#5066). Recording which dependencies went
        // unresolved beats recording a digest computed from an incomplete set.
        let mut dep_digests = Vec::with_capacity(dep_names.len());
        let mut unresolved_deps = Vec::new();
        for dep in &dep_names {
            match dep_b5(&state, &repo, dep).await? {
                Some(digest) => dep_digests.push(digest),
                None => unresolved_deps.push(dep.clone()),
            }
        }
        let b5 = if unresolved_deps.is_empty() {
            B5Outcome::Resolved(wire::b5_digest(&decoded_files, &dep_digests))
        } else {
            B5Outcome::UnresolvedDeps(unresolved_deps)
        };

        let protobuf_metadata = build_protobuf_metadata(
            &module_name,
            &commit_digest,
            content.files.len(),
            &dep_names,
            &ids::commit(&module_name, &commit_digest),
            &b5,
        );

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
            &state,
            &repo,
            &module_name,
            &effective_labels,
            &commit_digest,
            user_id,
            &headers,
        )
        .await?;

        // Update repository timestamp
        let _ = sqlx::query("UPDATE repositories SET updated_at = NOW() WHERE id = $1")
            .bind(repo.id)
            .execute(&state.db)
            .await;

        let commit = build_commit_info_from_row(&row);
        result_commits.push(commit);

        // Surface the module commit on the Packages page (#3659), keyed on
        // the module name and its commit digest — the module's own
        // coordinates, which is also what `download` resolves against.
        crate::services::package_service::register_published_package(
            &state.db,
            &state.event_bus,
            repo.id,
            "protobuf",
            &module_name,
            &commit_digest,
            size_bytes,
            &bundle_sha256,
            None,
        )
        .await;

        // #4725: fan out to subscribed push peers.
        super::queue_push_sync_tasks_for_upload(
            &state.db,
            &headers,
            repo.id,
            artifact_id,
            &artifact_path,
            size_bytes,
        )
        .await;

        info!(
            "Protobuf upload: module {} commit {} to repo {}",
            module_name, commit_digest, repo_key
        );
    }

    let resp = UploadResponse {
        commits: result_commits,
    };
    if codec.is_proto() {
        if api == BsrApi::V1 {
            return Ok(wire::respond_proto(&pb1::UploadResponse {
                commits: pb_commits(&state, &repo, &resp.commits).await?,
            }));
        }
        let mut commits = Vec::with_capacity(resp.commits.len());
        for commit in &resp.commits {
            let b5 = commit_b5(&state, &repo, &commit.module_id, &commit.digest.value).await?;
            commits.push(pb_commit_v1beta1(commit, &b5));
        }
        return Ok(wire::respond_proto(&pb1b::UploadResponse { commits }));
    }
    Ok(wire::respond_json(&resp))
}

// ---------------------------------------------------------------------------
// POST Download (buf pull)
// ---------------------------------------------------------------------------

async fn download_v1(
    state: State<SharedState>,
    auth: Extension<Option<AuthExtension>>,
    repo_key: Path<String>,
    ctx: crate::api::middleware::download_telemetry::DownloadContext,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Response> {
    download(state, auth, repo_key, ctx, headers, body, BsrApi::V1).await
}

async fn download_v1beta1(
    state: State<SharedState>,
    auth: Extension<Option<AuthExtension>>,
    repo_key: Path<String>,
    ctx: crate::api::middleware::download_telemetry::DownloadContext,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Response> {
    download(state, auth, repo_key, ctx, headers, body, BsrApi::V1Beta1).await
}

#[allow(clippy::too_many_arguments)]
async fn download(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(repo_key): Path<String>,
    ctx: crate::api::middleware::download_telemetry::DownloadContext,
    headers: HeaderMap,
    body: Bytes,
    api: BsrApi,
) -> Result<Response, Response> {
    let codec = Codec::from_headers(&headers)?;
    let body: DownloadRequest = match api {
        BsrApi::V1 => codec.decode(&body, DownloadRequest::from_pb_v1)?,
        BsrApi::V1Beta1 => codec.decode(&body, DownloadRequest::from_pb)?,
    };
    let repo = resolve_protobuf_repo(&state.db, &repo_key).await?;

    let mut contents = Vec::new();

    for value in &body.values {
        let (module_name, commit_digest) =
            resolve_resource_ref(&state, &repo, &value.resource_ref).await?;

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
                  AND version IS DISTINCT FROM '_labels'
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
                crate::api::handlers::db_status(&e),
                "internal",
                crate::api::handlers::db_err_message(&e),
            )
        })?;

        let artifact_row = match artifact_row {
            Some(row) => row,
            None => {
                // Try proxy for remote repos
                if repo.repo_type == RepositoryType::Remote {
                    if let (Some(upstream_url), Some(proxy)) =
                        (&repo.upstream_url, &state.proxy_service)
                    {
                        let digest = commit_digest.as_deref().unwrap_or("latest");
                        let upstream_path = format!("modules/{}/commits/{}", module_name, digest);
                        // The protobuf bundle is inspected in full below
                        // (`extract_files_from_bundle`), so it must be buffered
                        // rather than streamed. Bound the buffered read at
                        // 16 MiB (#1608 Phase 4b / #2181) so a hostile/broken
                        // upstream cannot OOM the pod.
                        let (bundle_data, _content_type) = proxy_helpers::proxy_fetch_capped(
                            proxy,
                            repo.id,
                            &repo_key,
                            upstream_url,
                            &upstream_path,
                            proxy_helpers::LARGE_METADATA_MAX_BYTES,
                        )
                        .await?;

                        // #2561: permit-scoped decode, fast-fail 503 on saturation.
                        #[allow(clippy::result_large_err)]
                        // Response-as-error matches this module's handler convention.
                        let files = crate::util::bounded_archive::with_ingest_extraction(|| {
                            extract_files_from_bundle(&bundle_data)
                        })
                        .map_err(|e| e.into_response())??;
                        let commit = build_commit_info(
                            digest,
                            &chrono::Utc::now().to_rfc3339(),
                            "",
                            &module_name,
                            digest,
                        );
                        contents.push(DownloadContent { commit, files });
                        continue;
                    }
                }

                // Virtual repo: try each member in priority order
                if repo.repo_type == RepositoryType::Virtual {
                    let db = state.db.clone();
                    let digest = commit_digest.as_deref().unwrap_or("latest").to_string();
                    let upstream_path = format!("modules/{}/commits/{}", module_name, digest);
                    let mname = module_name.clone();

                    let result = proxy_helpers::resolve_virtual_download(
                        &state.db,
                        auth.as_ref(),
                        state.proxy_service.as_deref(),
                        repo.id,
                        &upstream_path,
                        // Parity with the Remote arm above, which reads the
                        // bundle through the capped fetch and records no proxy
                        // download: a Remote member's bundle is not counted
                        // here either (#3844).
                        None,
                        |member_id, location| {
                            let db = db.clone();
                            let state = state.clone();
                            let path = format!("modules/{}/commits/{}", mname, digest);
                            async move {
                                proxy_helpers::local_fetch_by_path(
                                    &db, &state, member_id, &location, &path,
                                )
                                .await
                            }
                        },
                    )
                    .await?;

                    let bundle_data = result.collect().await.map_err(|e| e.into_response())?;

                    // #2561: permit-scoped decode, fast-fail 503 on saturation.
                    #[allow(clippy::result_large_err)]
                    // Response-as-error matches this module's handler convention.
                    let files = crate::util::bounded_archive::with_ingest_extraction(|| {
                        extract_files_from_bundle(&bundle_data)
                    })
                    .map_err(|e| e.into_response())??;
                    let commit = build_commit_info(
                        &digest,
                        &chrono::Utc::now().to_rfc3339(),
                        "",
                        &module_name,
                        &digest,
                    );
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

        // Check quarantine status before serving
        let artifact_id_for_check: uuid::Uuid = artifact_row.get("id");
        crate::services::quarantine_service::check_artifact_download(
            &state.db,
            artifact_id_for_check,
        )
        .await
        .map_err(|e| e.into_response())?;

        // Read bundle from local storage
        let storage_key: String = artifact_row.get("storage_key");
        let storage = state
            .storage_for_repo(&repo.storage_location())
            .map_err(|e| e.into_response())?;
        let bundle_data = storage.get(&storage_key).await.map_err(|e| {
            connect_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal",
                crate::api::handlers::storage_err_message(&e),
            )
        })?;

        // #2561: permit-scoped decode, fast-fail 503 on saturation.
        #[allow(clippy::result_large_err)]
        // Response-as-error matches this module's handler convention.
        let files = crate::util::bounded_archive::with_ingest_extraction(|| {
            extract_files_from_bundle(&bundle_data)
        })
        .map_err(|e| e.into_response())??;
        let commit = build_commit_info_from_row(&artifact_row);

        // Record download
        let artifact_id: uuid::Uuid = artifact_row.get("id");
        crate::services::artifact_service::record_download(&state.db, artifact_id, &ctx).await;

        contents.push(DownloadContent { commit, files });
    }

    let resp = DownloadResponse { contents };
    if codec.is_proto() && api == BsrApi::V1 {
        let mut contents = Vec::with_capacity(resp.contents.len());
        for content in &resp.contents {
            let b5 = commit_b5(
                &state,
                &repo,
                &content.commit.module_id,
                &content.commit.digest.value,
            )
            .await?;
            contents.push(pb1::download_response::Content {
                commit: Some(pb_commit(&content.commit, &b5)),
                files: decode_bundle_files(&content.files)?
                    .into_iter()
                    .map(|(path, content)| pb1::File { path, content })
                    .collect(),
            });
        }
        return Ok(wire::respond_proto(&pb1::DownloadResponse { contents }));
    }
    if codec.is_proto() {
        let mut contents = Vec::with_capacity(resp.contents.len());
        for content in &resp.contents {
            let b5 = commit_b5(
                &state,
                &repo,
                &content.commit.module_id,
                &content.commit.digest.value,
            )
            .await?;
            contents.push(pb1b::download_response::Content {
                commit: Some(pb_commit_v1beta1(&content.commit, &b5)),
                files: decode_bundle_files(&content.files)?
                    .into_iter()
                    .map(|(path, content)| pb1b::File { path, content })
                    .collect(),
                v1_buf_yaml_file: None,
                v1_buf_lock_file: None,
            });
        }
        return Ok(wire::respond_proto(&pb1b::DownloadResponse { contents }));
    }
    Ok(wire::respond_json(&resp))
}

// ---------------------------------------------------------------------------
// POST GetLabels
// ---------------------------------------------------------------------------

async fn get_labels(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Response> {
    let codec = Codec::from_headers(&headers)?;
    let body: GetLabelsRequest = codec.decode(&body, GetLabelsRequest::from_pb)?;
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
                labels.push(build_label_info(&module_name, label_name, digest, &now));
            }
        } else {
            // Return all labels for the module
            let now = chrono::Utc::now().to_rfc3339();
            for (name, digest_val) in &label_index {
                let digest = digest_val.as_str().unwrap_or_default();
                labels.push(build_label_info(&module_name, name, digest, &now));
            }
        }
    }

    let resp = GetLabelsResponse { labels };
    if codec.is_proto() {
        return Ok(wire::respond_proto(&pb1::GetLabelsResponse {
            labels: resp.labels.iter().map(pb_label).collect(),
        }));
    }
    Ok(wire::respond_json(&resp))
}

// ---------------------------------------------------------------------------
// POST CreateOrUpdateLabels
// ---------------------------------------------------------------------------

async fn create_or_update_labels(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(repo_key): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Response> {
    // GHSA-vvc3-h39c-mrq5: enforce token scope before processing, and before
    // decoding the body, as in `upload`.
    let user_id = require_auth_basic_scope(auth, "protobuf", "write:artifacts")?.user_id;
    let repo = resolve_protobuf_repo(&state.db, &repo_key).await?;

    proxy_helpers::reject_write_if_not_hosted(&repo.repo_type)?;
    repo.reject_if_promotion_only(false)?;

    let codec = Codec::from_headers(&headers)?;
    let body: CreateOrUpdateLabelsRequest =
        codec.decode(&body, CreateOrUpdateLabelsRequest::from_pb)?;

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
                crate::api::handlers::db_status(&e),
                "internal",
                crate::api::handlers::db_err_message(&e),
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
            &state,
            &repo,
            &module_name,
            &[LabelRef {
                name: value.name.clone(),
            }],
            &value.commit_id,
            user_id,
            &headers,
        )
        .await?;

        labels.push(build_label_info(
            &module_name,
            &value.name,
            &value.commit_id,
            &now,
        ));
    }

    let resp = CreateOrUpdateLabelsResponse { labels };
    if codec.is_proto() {
        return Ok(wire::respond_proto(&pb1::CreateOrUpdateLabelsResponse {
            labels: resp.labels.iter().map(pb_label).collect(),
        }));
    }
    Ok(wire::respond_json(&resp))
}

// ---------------------------------------------------------------------------
// POST GetGraph
// ---------------------------------------------------------------------------

async fn get_graph(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Response> {
    let codec = Codec::from_headers(&headers)?;
    let body: GetGraphRequest = codec.decode(&body, GetGraphRequest::from_pb)?;
    let repo = resolve_protobuf_repo(&state.db, &repo_key).await?;

    // A graph is the closure, not the commits that were asked for. The CLI
    // builds a map from every commit in the reply and then looks up each
    // edge's node in it, so a dependency reached by an edge but absent from
    // `commits` is reported to the user as a bug in buf ("did not have
    // RegistryCommitID ... in registryCommitIDToModuleKey"). Dependencies are
    // therefore followed transitively, which is also what resolving a
    // consumer's dependency needs: `buf dep update` asks for one module and
    // pins everything that module brings in.
    let mut commits: Vec<CommitInfo> = Vec::new();
    let mut edges = Vec::new();
    let mut queue: std::collections::VecDeque<(String, Option<String>)> =
        std::collections::VecDeque::new();
    let mut walked: std::collections::HashSet<(String, String)> = std::collections::HashSet::new();

    for resource_ref in &body.resource_refs {
        queue.push_back(resolve_resource_ref(&state, &repo, resource_ref).await?);
    }

    while let Some((module_name, commit_digest)) = queue.pop_front() {
        let Some(row) =
            load_commit_with_metadata(&state, &repo, &module_name, commit_digest.as_deref())
                .await?
        else {
            continue;
        };
        let commit = build_commit_info_from_row(&row);
        // A diamond reaches the same commit twice; its edges are already in.
        if !walked.insert((commit.module_id.clone(), commit.digest.value.clone())) {
            continue;
        }

        let metadata: Option<serde_json::Value> = row.get("metadata");
        let commit_edges = extract_graph_edges(&metadata, &commit.id);
        for edge in &commit_edges {
            // A dependency that resolves to no commit here stays in the edge
            // list and is refused by name when the reply is built, rather
            // than dropped into a graph that would look complete.
            if let Some((dep_module, dep_digest)) =
                commit_by_derived_id(&state, &repo, &edge.to_commit_id).await?
            {
                queue.push_back((dep_module, Some(dep_digest)));
            }
        }
        edges.extend(commit_edges);
        commits.push(commit);
    }

    let resp = GetGraphResponse { commits, edges };
    if codec.is_proto() {
        return Ok(wire::respond_proto(&pb1::GetGraphResponse {
            graph: Some(pb_graph(&state, &repo, &resp.commits, &resp.edges).await?),
        }));
    }
    Ok(wire::respond_json(&resp))
}

// ---------------------------------------------------------------------------
// POST GetResources
// ---------------------------------------------------------------------------

async fn get_resources(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Response> {
    let codec = Codec::from_headers(&headers)?;
    let body: GetResourcesRequest = codec.decode(&body, GetResourcesRequest::from_pb)?;
    let repo = resolve_protobuf_repo(&state.db, &repo_key).await?;

    let mut resources = Vec::new();

    for resource_ref in &body.resource_refs {
        let (module_name, commit_digest) =
            resolve_resource_ref(&state, &repo, resource_ref).await?;

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
                  AND version IS DISTINCT FROM '_labels'
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
                crate::api::handlers::db_status(&e),
                "internal",
                crate::api::handlers::db_err_message(&e),
            )
        })?;

        if let Some(row) = row {
            let module = build_module_info_from_row(&row);
            let commit = build_commit_info_from_row(&row);
            resources.push(ResourceInfo { module, commit });
        }
    }

    let resp = GetResourcesResponse { resources };
    if codec.is_proto() {
        // A reference resolves to the commit it names: that is what the CLI
        // asks GetResources for, and `Resource` is a oneof, so a reply cannot
        // carry the module and the commit at once the way the JSON shape does.
        let mut resources = Vec::with_capacity(resp.resources.len());
        for resource in &resp.resources {
            let b5 = commit_b5(
                &state,
                &repo,
                &resource.commit.module_id,
                &resource.commit.digest.value,
            )
            .await?;
            resources.push(pb1::Resource {
                value: Some(pb1::resource::Value::Commit(pb_commit(
                    &resource.commit,
                    &b5,
                ))),
            });
        }
        return Ok(wire::respond_proto(&pb1::GetResourcesResponse {
            resources,
        }));
    }
    Ok(wire::respond_json(&resp))
}

// ---------------------------------------------------------------------------
// The buf CLI's codec (#5066)
//
// The CLI speaks Connect with the binary protobuf codec, so every hosted
// endpoint decodes its request from either codec and answers in the one it
// arrived in. The JSON shapes above stay exactly as they were; the generated
// messages below are what the CLI reads, and they carry the identifiers and
// the digest it insists on:
//
//   * ids are tuuids, derived from the names this repository already keys on
//     (`protobuf_wire::ids`), so they are stable without an id column;
//   * `Digest` is b5 over the module's files and its dependencies' b5s, not
//     the SHA-256 the bundle is stored under.
// ---------------------------------------------------------------------------

/// The `owner` half of an `owner/module` module name.
fn owner_of(module_name: &str) -> &str {
    module_name.split('/').next().unwrap_or(module_name)
}

/// The module segment of an `owner/module` name.
fn module_of(module_name: &str) -> &str {
    module_name.split_once('/').map_or(module_name, |(_, m)| m)
}

fn pb_timestamp(rfc3339: &str) -> Option<prost_types::Timestamp> {
    chrono::DateTime::parse_from_rfc3339(rfc3339)
        .ok()
        .map(|t| prost_types::Timestamp {
            seconds: t.timestamp(),
            nanos: t.timestamp_subsec_nanos() as i32,
        })
}

impl ModuleRef {
    fn from_pb_v1(value: Option<pb1::module_ref::Value>) -> Self {
        match value {
            Some(pb1::module_ref::Value::Id(id)) => ModuleRef {
                id: Some(id),
                owner: None,
                module: None,
            },
            Some(pb1::module_ref::Value::Name(name)) => ModuleRef {
                id: None,
                owner: Some(name.owner),
                module: Some(name.module),
            },
            None => ModuleRef {
                id: None,
                owner: None,
                module: None,
            },
        }
    }

    fn from_pb_v1beta1(value: Option<pb1b::module_ref::Value>) -> Self {
        match value {
            Some(pb1b::module_ref::Value::Id(id)) => ModuleRef {
                id: Some(id),
                owner: None,
                module: None,
            },
            Some(pb1b::module_ref::Value::Name(name)) => ModuleRef {
                id: None,
                owner: Some(name.owner),
                module: Some(name.module),
            },
            None => ModuleRef {
                id: None,
                owner: None,
                module: None,
            },
        }
    }
}

impl ResourceRef {
    fn from_pb(value: Option<pb1::resource_ref::Value>) -> Self {
        match value {
            Some(pb1::resource_ref::Value::Id(id)) => ResourceRef {
                id: Some(id),
                owner: None,
                module: None,
                label: None,
            },
            Some(pb1::resource_ref::Value::Name(name)) => {
                // `child` distinguishes a label from a `ref`, which may be a
                // label name or a commit id. Either way the repository looks
                // it up as a label first and falls back to a digest, so both
                // land in the same field.
                // The CLI sets the oneof to an empty `ref` when it wants
                // the module's default label rather than a named one, and an
                // empty string names nothing, so it is the same as unset. Not
                // normalising it here made a `buf push` of a module with a
                // dependency fail: resolving the dependency asked for the ref
                // '' and was told, correctly for a named ref, not_found.
                let label = match name.child {
                    Some(pb1::resource_ref::name::Child::LabelName(l)) => non_empty(l),
                    Some(pb1::resource_ref::name::Child::Ref(r)) => non_empty(r),
                    None => None,
                };
                ResourceRef {
                    id: None,
                    owner: Some(name.owner),
                    module: Some(name.module),
                    label,
                }
            }
            None => ResourceRef {
                id: None,
                owner: None,
                module: None,
                label: None,
            },
        }
    }

    fn from_pb_v1beta1(value: Option<pb1b::resource_ref::Value>) -> Self {
        match value {
            Some(pb1b::resource_ref::Value::Id(id)) => ResourceRef {
                id: Some(id),
                owner: None,
                module: None,
                label: None,
            },
            Some(pb1b::resource_ref::Value::Name(name)) => {
                let label = match name.child {
                    Some(pb1b::resource_ref::name::Child::LabelName(l)) => non_empty(l),
                    Some(pb1b::resource_ref::name::Child::Ref(r)) => non_empty(r),
                    None => None,
                };
                ResourceRef {
                    id: None,
                    owner: Some(name.owner),
                    module: Some(name.module),
                    label,
                }
            }
            None => ResourceRef {
                id: None,
                owner: None,
                module: None,
                label: None,
            },
        }
    }
}

/// One commit row with its metadata: the commit a digest names, or the
/// module's latest when it names none.
async fn load_commit_with_metadata(
    state: &SharedState,
    repo: &RepoInfo,
    module_name: &str,
    commit_digest: Option<&str>,
) -> Result<Option<sqlx::postgres::PgRow>, Response> {
    let query = if let Some(digest) = commit_digest {
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
        .bind(module_name)
        .bind(digest)
    } else {
        sqlx::query(
            r#"SELECT a.id, a.name, a.version, a.created_at, a.updated_at,
                a.uploaded_by, a.checksum_sha256, am.metadata
            FROM artifacts a
            LEFT JOIN artifact_metadata am ON am.artifact_id = a.id
            WHERE a.repository_id = $1
              AND a.name = $2
              AND a.version IS DISTINCT FROM '_labels'
              AND a.is_deleted = false
            ORDER BY a.created_at DESC
            LIMIT 1"#,
        )
        .bind(repo.id)
        .bind(module_name)
    };

    query
        .fetch_optional(&state.db)
        .await
        .map_err(connect_db_error)
}

impl GetOwnersRequest {
    fn from_pb(req: wire::proto::owner_v1::GetOwnersRequest) -> Self {
        GetOwnersRequest {
            owner_refs: req
                .owner_refs
                .into_iter()
                .map(|r| match r.value {
                    Some(wire::proto::owner_v1::owner_ref::Value::Id(id)) => OwnerRef {
                        id: non_empty(id),
                        name: None,
                    },
                    Some(wire::proto::owner_v1::owner_ref::Value::Name(name)) => OwnerRef {
                        id: None,
                        name: non_empty(name),
                    },
                    None => OwnerRef {
                        id: None,
                        name: None,
                    },
                })
                .collect(),
        }
    }
}

/// An empty proto string field names nothing, so it is the same as unset.
fn non_empty(value: String) -> Option<String> {
    (!value.is_empty()).then_some(value)
}

impl GetModulesRequest {
    fn from_pb(req: pb1::GetModulesRequest) -> Self {
        GetModulesRequest {
            module_refs: req
                .module_refs
                .into_iter()
                .map(|r| ModuleRef::from_pb_v1(r.value))
                .collect(),
        }
    }
}

impl GetCommitsRequest {
    fn from_pb(req: pb1::GetCommitsRequest) -> Self {
        GetCommitsRequest {
            resource_refs: req
                .resource_refs
                .into_iter()
                .map(|r| ResourceRef::from_pb(r.value))
                .collect(),
        }
    }
}

impl ListCommitsRequest {
    fn from_pb(req: pb1::ListCommitsRequest) -> Self {
        let resource = req.resource_ref.map(|r| ResourceRef::from_pb(r.value));
        ListCommitsRequest {
            owner: resource.as_ref().and_then(|r| r.owner.clone()),
            module: resource.and_then(|r| r.module),
            page_size: if req.page_size == 0 {
                None
            } else {
                Some(req.page_size as i64)
            },
            page_token: if req.page_token.is_empty() {
                None
            } else {
                Some(req.page_token)
            },
        }
    }
}

impl GetGraphRequest {
    fn from_pb(req: pb1::GetGraphRequest) -> Self {
        GetGraphRequest {
            resource_refs: req
                .resource_refs
                .into_iter()
                .map(|r| ResourceRef::from_pb(r.value))
                .collect(),
        }
    }
}

impl GetResourcesRequest {
    fn from_pb(req: pb1::GetResourcesRequest) -> Self {
        GetResourcesRequest {
            resource_refs: req
                .resource_refs
                .into_iter()
                .map(|r| ResourceRef::from_pb(r.value))
                .collect(),
        }
    }
}

impl GetLabelsRequest {
    fn from_pb(req: pb1::GetLabelsRequest) -> Self {
        GetLabelsRequest {
            label_refs: req
                .label_refs
                .into_iter()
                .map(|r| match r.value {
                    Some(pb1::label_ref::Value::Name(name)) => LabelResourceRef {
                        owner: Some(name.owner),
                        module: Some(name.module),
                        label: Some(name.label),
                    },
                    // A label id is this repository's derived tuuid, which
                    // names no module on its own; the handler answers an empty
                    // list for it rather than guessing.
                    Some(pb1::label_ref::Value::Id(_)) | None => LabelResourceRef {
                        owner: None,
                        module: None,
                        label: None,
                    },
                })
                .collect(),
        }
    }
}

impl CreateOrUpdateLabelsRequest {
    fn from_pb(req: pb1::CreateOrUpdateLabelsRequest) -> Self {
        CreateOrUpdateLabelsRequest {
            values: req
                .values
                .into_iter()
                .map(|v| {
                    let (owner, module, name) = match v.label_ref.and_then(|r| r.value) {
                        Some(pb1::label_ref::Value::Name(n)) => {
                            (Some(n.owner), Some(n.module), n.label)
                        }
                        _ => (None, None, String::new()),
                    };
                    CreateLabelValue {
                        owner,
                        module,
                        name,
                        commit_id: v.commit_id,
                    }
                })
                .collect(),
        }
    }
}

impl DownloadRequest {
    /// v1's `DownloadRequest` has no `digest_type`: the package itself is the
    /// answer, since the CLI only asks v1 for b5.
    fn from_pb_v1(req: pb1::DownloadRequest) -> Self {
        DownloadRequest {
            values: req
                .values
                .into_iter()
                .map(|v| DownloadValue {
                    resource_ref: v
                        .resource_ref
                        .map(|r| ResourceRef::from_pb(r.value))
                        .unwrap_or(ResourceRef {
                            id: None,
                            owner: None,
                            module: None,
                            label: None,
                        }),
                    file_types: Vec::new(),
                })
                .collect(),
        }
    }

    fn from_pb(req: pb1b::DownloadRequest) -> Self {
        DownloadRequest {
            values: req
                .values
                .into_iter()
                .map(|v| DownloadValue {
                    resource_ref: v
                        .resource_ref
                        .map(|r| ResourceRef::from_pb_v1beta1(r.value))
                        .unwrap_or(ResourceRef {
                            id: None,
                            owner: None,
                            module: None,
                            label: None,
                        }),
                    file_types: Vec::new(),
                })
                .collect(),
        }
    }
}

impl UploadRequest {
    /// v1's dependencies are bare commit ids, where v1beta1 pairs each with
    /// the registry that holds it. Without federation there is only the one
    /// registry, so the id is the whole reference.
    fn from_pb_v1(req: pb1::UploadRequest) -> Self {
        let dep_refs: Vec<ModuleRef> = req
            .dep_commit_ids
            .into_iter()
            .map(|commit_id| ModuleRef {
                id: Some(commit_id),
                owner: None,
                module: None,
            })
            .collect();

        UploadRequest {
            contents: req
                .contents
                .into_iter()
                .map(|c| UploadContent {
                    module_ref: c
                        .module_ref
                        .map(|r| ModuleRef::from_pb_v1(r.value))
                        .unwrap_or(ModuleRef {
                            id: None,
                            owner: None,
                            module: None,
                        }),
                    files: c
                        .files
                        .into_iter()
                        .map(|f| UploadFile {
                            path: f.path,
                            content: base64::engine::general_purpose::STANDARD.encode(&f.content),
                        })
                        .collect(),
                    dep_refs: dep_refs.clone(),
                    label_refs: c
                        .scoped_label_refs
                        .into_iter()
                        .filter_map(|l| match l.value {
                            Some(pb1::scoped_label_ref::Value::Name(name)) => {
                                Some(LabelRef { name })
                            }
                            _ => None,
                        })
                        .collect(),
                })
                .collect(),
        }
    }

    /// The CLI's `UploadRequest` carries `dep_refs` once for the whole push
    /// and `scoped_label_refs` per content, where the JSON shape has both per
    /// content. The dep refs are therefore attached to every content, which is
    /// what they apply to.
    fn from_pb(req: pb1b::UploadRequest) -> Self {
        let dep_refs: Vec<ModuleRef> = req
            .dep_refs
            .into_iter()
            .map(|d| ModuleRef {
                id: Some(d.commit_id),
                owner: None,
                module: None,
            })
            .collect();

        UploadRequest {
            contents: req
                .contents
                .into_iter()
                .map(|c| UploadContent {
                    module_ref: c
                        .module_ref
                        .map(|r| ModuleRef::from_pb_v1beta1(r.value))
                        .unwrap_or(ModuleRef {
                            id: None,
                            owner: None,
                            module: None,
                        }),
                    // The handler works in base64 because that is what the
                    // JSON shape carries; the CLI sends raw bytes.
                    files: c
                        .files
                        .into_iter()
                        .map(|f| UploadFile {
                            path: f.path,
                            content: base64::engine::general_purpose::STANDARD.encode(&f.content),
                        })
                        .collect(),
                    dep_refs: dep_refs.clone(),
                    label_refs: c
                        .scoped_label_refs
                        .into_iter()
                        .filter_map(|l| match l.value {
                            Some(pb1b::scoped_label_ref::Value::Name(name)) => {
                                Some(LabelRef { name })
                            }
                            _ => None,
                        })
                        .collect(),
                })
                .collect(),
        }
    }
}

// -- Responses the CLI reads

fn pb_module(info: &ModuleInfo) -> pb1::Module {
    pb1::Module {
        id: ids::module(&info.full_name),
        create_time: pb_timestamp(&info.create_time),
        update_time: pb_timestamp(&info.update_time),
        name: info.name.clone(),
        owner_id: ids::owner(owner_of(&info.full_name)),
        visibility: pb1::ModuleVisibility::Private as i32,
        state: pb1::ModuleState::Active as i32,
        description: String::new(),
        url: String::new(),
        default_label_name: info.default_label_name.clone(),
    }
}

/// `CommitInfo::module_id` holds the module name and `digest.value` the
/// SHA-256 the bundle is stored under; `b5` is the digest the CLI verifies.
fn pb_commit(info: &CommitInfo, b5: &str) -> pb1::Commit {
    let module_name = info.module_id.clone();
    pb1::Commit {
        id: ids::commit(&module_name, &info.digest.value),
        create_time: pb_timestamp(&info.create_time),
        owner_id: ids::owner(owner_of(&module_name)),
        module_id: ids::module(&module_name),
        digest: Some(pb1::Digest {
            r#type: pb1::DigestType::B5 as i32,
            value: wire::b5_bytes(b5),
        }),
        created_by_user_id: String::new(),
        source_control_url: String::new(),
    }
}

/// The beta package the CLI pushes and pulls over numbers b5 as 2, where v1
/// numbers it 1 (#5066): the same commit has to be encoded per package.
fn pb_commit_v1beta1(info: &CommitInfo, b5: &str) -> pb1b::Commit {
    let module_name = info.module_id.clone();
    pb1b::Commit {
        id: ids::commit(&module_name, &info.digest.value),
        create_time: pb_timestamp(&info.create_time),
        owner_id: ids::owner(owner_of(&module_name)),
        module_id: ids::module(&module_name),
        digest: Some(pb1b::Digest {
            r#type: pb1b::DigestType::B5 as i32,
            value: wire::b5_bytes(b5),
        }),
        created_by_user_id: String::new(),
        source_control_url: String::new(),
    }
}

/// `LabelInfo::id` is `module_name:label:commit_digest` and `commit_id` the
/// commit digest, so the module the label belongs to is recoverable from the
/// label itself -- a module name holds a `/`, never a `:`.
fn pb_label(info: &LabelInfo) -> pb1::Label {
    let module_name = info.id.split(':').next().unwrap_or_default().to_string();
    pb1::Label {
        id: ids::label(&module_name, &info.name),
        create_time: pb_timestamp(&info.create_time),
        update_time: pb_timestamp(&info.update_time),
        archive_time: None,
        name: info.name.clone(),
        owner_id: ids::owner(owner_of(&module_name)),
        module_id: ids::module(&module_name),
        commit_id: ids::commit(&module_name, &info.commit_id),
        updated_by_user_id: String::new(),
        commit_check_state: Some(pb1::CommitCheckState {
            // Hosted repositories run no commit checks, which the CLI reads
            // as "nothing to wait for".
            status: pb1::CommitCheckStatus::Disabled as i32,
            update_time: pb_timestamp(&info.update_time),
        }),
    }
}

// -- The b5 digest of a stored commit

/// A dependency whose own b5 this repository does not hold, so the commit's
/// b5 cannot be computed: the CLI compares the digest it computed locally
/// against the one it is answered, and a digest built from an incomplete
/// dependency set would differ without saying why.
fn connect_unresolved_deps(module_name: &str, deps: &[String]) -> Response {
    connect_error(
        StatusCode::BAD_REQUEST,
        "failed_precondition",
        &format!(
            "cannot resolve the dependencies [{1}] of module '{0}'. A hosted repository \
             resolves a dependency by the commit id it recorded at push time, so this is a \
             dependency held by another registry, or one recorded as a bare module name, \
             which names no commit to compose a digest from. Push the dependency here \
             first, or serve the module through a virtual repository with the upstream \
             registry as a member.",
            module_name,
            deps.join(", ")
        ),
    )
}

/// The b5 digest of one stored commit, which is what the CLI verifies and is
/// not the SHA-256 the bundle is stored under.
///
/// `b5Digest` in the artifact's metadata is authoritative: it was computed at
/// push time, when the dependency digests were known. A commit pushed before
/// #5066, or over the JSON codec, has no such entry, so the digest is computed
/// from the stored bundle -- which is exact as long as the module declares no
/// dependencies, and refused rather than guessed when it does.
async fn commit_b5(
    state: &SharedState,
    repo: &RepoInfo,
    module_name: &str,
    commit_digest: &str,
) -> Result<String, Response> {
    let row = sqlx::query(
        r#"SELECT a.storage_key, m.metadata
        FROM artifacts a
        LEFT JOIN artifact_metadata m ON m.artifact_id = a.id
        WHERE a.repository_id = $1
          AND a.name = $2
          AND a.version = $3
          AND a.is_deleted = false
        LIMIT 1"#,
    )
    .bind(repo.id)
    .bind(module_name)
    .bind(commit_digest)
    .fetch_optional(&state.db)
    .await
    .map_err(connect_db_error)?
    .ok_or_else(|| {
        connect_error(
            StatusCode::NOT_FOUND,
            "not_found",
            &format!("commit {commit_digest} of module {module_name} not found"),
        )
    })?;

    let metadata: Option<serde_json::Value> = row.get("metadata");

    if let Some(b5) = metadata
        .as_ref()
        .and_then(|m| m.get("b5Digest"))
        .and_then(|v| v.as_str())
    {
        return Ok(b5.to_string());
    }

    let dep_names: Vec<String> = metadata
        .as_ref()
        .and_then(|m| m.get("dependencies"))
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();

    let mut dep_digests = Vec::with_capacity(dep_names.len());
    let mut unresolved = Vec::new();
    for dep in &dep_names {
        match dep_b5(state, repo, dep).await? {
            Some(digest) => dep_digests.push(digest),
            None => unresolved.push(dep.clone()),
        }
    }
    if !unresolved.is_empty() {
        return Err(connect_unresolved_deps(module_name, &unresolved));
    }

    let storage_key: String = row.get("storage_key");
    let storage = state
        .storage_for_repo(&repo.storage_location())
        .map_err(|e| e.into_response())?;
    let bundle = storage.get(&storage_key).await.map_err(|e| {
        connect_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            crate::api::handlers::storage_err_message(&e),
        )
    })?;

    let files = extract_files_from_bundle(&bundle)?;
    let decoded = decode_bundle_files(&files)?;
    Ok(wire::b5_digest(&decoded, &dep_digests))
}

/// The recorded b5 digest of a dependency hosted in this repository, by
/// `owner/module` name or by a commit id this repository derived. `None` when
/// the repository holds no b5 for it.
async fn dep_b5(
    state: &SharedState,
    repo: &RepoInfo,
    dep: &str,
) -> Result<Option<String>, Response> {
    // Only a commit id resolves: it is this repository's derived tuuid,
    // recorded next to the digest at push time, and it names the one commit
    // the depending module was built against. A dependency recorded as a bare
    // module name (what the JSON codec's `depRefs` carry) does not say which
    // commit that was, and taking the latest would compose a digest from
    // whatever has been pushed since -- a digest the client never pinned and
    // nothing would explain. Such a dependency counts as unresolved.
    let row = sqlx::query(
        r#"SELECT m.metadata
        FROM artifacts a
        JOIN artifact_metadata m ON m.artifact_id = a.id
        WHERE a.repository_id = $1
          AND a.is_deleted = false
          AND m.metadata->>'commitId' = $2
        LIMIT 1"#,
    )
    .bind(repo.id)
    .bind(dep)
    .fetch_optional(&state.db)
    .await
    .map_err(connect_db_error)?;

    Ok(row
        .and_then(|r| r.get::<Option<serde_json::Value>, _>("metadata"))
        .and_then(|m| {
            m.get("b5Digest")
                .and_then(|v| v.as_str())
                .map(str::to_string)
        }))
}

/// Base64 bundle entries as the raw path/content pairs the digest hashes.
fn decode_bundle_files(files: &[DownloadFile]) -> Result<Vec<(String, Vec<u8>)>, Response> {
    files
        .iter()
        .map(|f| {
            base64::engine::general_purpose::STANDARD
                .decode(&f.content)
                .map(|content| (f.path.clone(), content))
                .map_err(|e| {
                    connect_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "internal",
                        &format!("stored file '{}' is not valid base64: {}", f.path, e),
                    )
                })
        })
        .collect()
}

// -- Reply builders that need the stored b5 digest

async fn pb_commits(
    state: &SharedState,
    repo: &RepoInfo,
    commits: &[CommitInfo],
) -> Result<Vec<pb1::Commit>, Response> {
    let mut out = Vec::with_capacity(commits.len());
    for commit in commits {
        let b5 = commit_b5(state, repo, &commit.module_id, &commit.digest.value).await?;
        out.push(pb_commit(commit, &b5));
    }
    Ok(out)
}

/// The dependency edges as the CLI reads them: commit id to commit id, where
/// the JSON shape names the dependency module instead. A dependency this
/// repository does not host has no commit id here to point at, which is the
/// same gap the digest hits, so it is refused the same way.
async fn pb_graph(
    state: &SharedState,
    repo: &RepoInfo,
    commits: &[CommitInfo],
    edges: &[GraphEdge],
) -> Result<pb1::Graph, Response> {
    let pb_commits_list = pb_commits(state, repo, commits).await?;

    // `GraphEdge::from_commit_id` is the artifact row's own uuid, so the edge
    // is tied back to the commit it was extracted from by position in the
    // same list.
    let mut pb_edges = Vec::with_capacity(edges.len());
    for edge in edges {
        let from = commits
            .iter()
            .find(|c| c.id == edge.from_commit_id)
            .ok_or_else(|| {
                connect_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal",
                    "dependency edge does not belong to any commit in the reply",
                )
            })?;
        // The edge names the dependency the way the push recorded it. From
        // the CLI that is a commit id, which is the commit this module was
        // built against and the id the graph's node carries as it stands. A
        // bare module name (the JSON codec's `depRefs`) names no commit, and
        // the node has to be one, so it is refused for the same reason its b5
        // is -- see `dep_b5`.
        let to_commit_id = match commit_by_derived_id(state, repo, &edge.to_commit_id).await? {
            Some(_) => edge.to_commit_id.clone(),
            None => {
                return Err(connect_unresolved_deps(
                    &from.module_id,
                    std::slice::from_ref(&edge.to_commit_id),
                ));
            }
        };
        pb_edges.push(pb1::graph::Edge {
            from_node: Some(pb1::graph::Node {
                commit_id: ids::commit(&from.module_id, &from.digest.value),
            }),
            to_node: Some(pb1::graph::Node {
                commit_id: to_commit_id,
            }),
        });
    }

    Ok(pb1::Graph {
        commits: pb_commits_list,
        edges: pb_edges,
        registry_commit_ids: Vec::new(),
    })
}

// ---------------------------------------------------------------------------
// Pure builders (single source of truth; unit tests pin these against
// hardcoded literals so a format change here fails the tests — #2657)
// ---------------------------------------------------------------------------

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

/// Whether a push could be given the b5 digest the CLI verifies a commit
/// against (#5066).
enum B5Outcome {
    /// Computed over the module's files and every dependency's own b5.
    Resolved(String),
    /// Dependencies whose b5 this repository does not hold, so there is no
    /// digest to record. A later request in the CLI's codec is refused by
    /// naming them, rather than answered a digest built from what was left.
    UnresolvedDeps(Vec<String>),
}

/// Build protobuf metadata JSON for an upload.
///
/// `commit_id` is the tuuid the BSR messages name this commit by, recorded
/// here so a dependency reference that carries only a commit id resolves back
/// to the module and its digest. `moduleId` is recorded for the same reason:
/// both ids are one-way functions of the names, and without a record of them
/// a reference by id can only be resolved by deriving the id of every module
/// in the repository and comparing.
fn build_protobuf_metadata(
    module_name: &str,
    commit_digest: &str,
    file_count: usize,
    dep_names: &[String],
    commit_id: &str,
    b5: &B5Outcome,
) -> serde_json::Value {
    let mut metadata = serde_json::json!({
        "module": module_name,
        "commitDigest": commit_digest,
        "fileCount": file_count,
        "dependencies": dep_names,
        "commitId": commit_id,
        "moduleId": ids::module(module_name),
        "ownerId": ids::owner(owner_of(module_name)),
    });
    let object = metadata.as_object_mut().expect("object literal");
    match b5 {
        B5Outcome::Resolved(digest) => {
            object.insert("b5Digest".to_string(), serde_json::json!(digest));
        }
        B5Outcome::UnresolvedDeps(deps) => {
            object.insert("b5UnresolvedDeps".to_string(), serde_json::json!(deps));
        }
    }
    metadata
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
fn extract_graph_edges(metadata: &Option<serde_json::Value>, commit_id: &str) -> Vec<GraphEdge> {
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

#[cfg(ak_test_shard = "handlers-2")]
#[cfg(test)]
mod tests {
    use super::*;

    // -- The buf CLI's codec (#5066)

    fn commit_fixture() -> CommitInfo {
        build_commit_info(
            "ignored-row-uuid",
            "2024-01-02T03:04:05Z",
            "ignored-owner-uuid",
            "acme/payments",
            "abc123",
        )
    }

    /// The reply the CLI reads carries tuuids derived from the module name and
    /// the commit digest, not the row uuid and module name the JSON shape
    /// puts in those fields.
    #[test]
    fn pb_commit_carries_derived_ids_5066() {
        let commit = pb_commit(&commit_fixture(), "b5:00ff");

        assert_eq!(commit.id, ids::commit("acme/payments", "abc123"));
        assert_eq!(commit.module_id, ids::module("acme/payments"));
        assert_eq!(commit.owner_id, ids::owner("acme"));
        assert_eq!(commit.create_time.unwrap().seconds, 1_704_164_645);
    }

    /// `Digest.value` is `bytes`, so the digest travels as the 64 raw bytes of
    /// the b5 hash; the JSON shape's hex text decoded as base64 is junk.
    #[test]
    fn pb_commit_digest_is_raw_b5_bytes_5066() {
        let b5 = wire::b5_digest(&[("a.proto".to_string(), b"x".to_vec())], &[]);
        let digest = pb_commit(&commit_fixture(), &b5).digest.unwrap();

        assert_eq!(digest.value.len(), 64);
        assert_eq!(digest.value, wire::b5_bytes(&b5));
    }

    /// The beta package the CLI pushes and pulls over numbers b5 as 2 where
    /// v1 numbers it 1. Encoding a commit with v1's number tells the CLI the
    /// digest is b4 and it refuses the commit, so both are pinned here.
    #[test]
    fn b5_enum_number_differs_between_packages_5066() {
        assert_eq!(pb1::DigestType::B5 as i32, 1);
        assert_eq!(pb1b::DigestType::B5 as i32, 2);

        let commit = commit_fixture();
        assert_eq!(pb_commit(&commit, "b5:00ff").digest.unwrap().r#type, 1);
        assert_eq!(
            pb_commit_v1beta1(&commit, "b5:00ff").digest.unwrap().r#type,
            2
        );
    }

    #[test]
    fn pb_label_recovers_its_module_5066() {
        let info = build_label_info("acme/payments", "main", "abc123", "2024-01-02T03:04:05Z");
        let label = pb_label(&info);

        assert_eq!(label.id, ids::label("acme/payments", "main"));
        assert_eq!(label.module_id, ids::module("acme/payments"));
        assert_eq!(label.owner_id, ids::owner("acme"));
        assert_eq!(label.commit_id, ids::commit("acme/payments", "abc123"));
        assert_eq!(
            label.commit_check_state.unwrap().status,
            pb1::CommitCheckStatus::Disabled as i32
        );
    }

    /// The CLI sends `dep_refs` once for the whole push and raw file bytes;
    /// the handler works per content and in base64.
    #[test]
    fn upload_request_from_pb_spreads_deps_and_encodes_files_5066() {
        let req = pb1b::UploadRequest {
            contents: vec![
                pb1b::upload_request::Content {
                    module_ref: Some(pb1b::ModuleRef {
                        value: Some(pb1b::module_ref::Value::Name(pb1b::module_ref::Name {
                            owner: "acme".to_string(),
                            module: "payments".to_string(),
                        })),
                    }),
                    files: vec![pb1b::File {
                        path: "a.proto".to_string(),
                        content: b"hello".to_vec(),
                    }],
                    scoped_label_refs: vec![pb1b::ScopedLabelRef {
                        value: Some(pb1b::scoped_label_ref::Value::Name("main".to_string())),
                    }],
                    source_control_url: String::new(),
                },
                pb1b::upload_request::Content {
                    module_ref: None,
                    files: Vec::new(),
                    scoped_label_refs: Vec::new(),
                    source_control_url: String::new(),
                },
            ],
            dep_refs: vec![pb1b::upload_request::DepRef {
                commit_id: "deadbeef".to_string(),
                registry: "buf.build".to_string(),
            }],
        };

        let body = UploadRequest::from_pb(req);

        assert_eq!(body.contents.len(), 2);
        let first = &body.contents[0];
        assert_eq!(first.module_ref.owner.as_deref(), Some("acme"));
        assert_eq!(first.module_ref.module.as_deref(), Some("payments"));
        assert_eq!(
            first.files[0].content,
            base64::engine::general_purpose::STANDARD.encode(b"hello")
        );
        assert_eq!(first.label_refs[0].name, "main");
        // The push's dep refs apply to every content in it.
        for content in &body.contents {
            assert_eq!(content.dep_refs.len(), 1);
            assert_eq!(content.dep_refs[0].id.as_deref(), Some("deadbeef"));
        }
    }

    /// A `ResourceRef` names its child either as a label or as a `ref` that
    /// may be a label or a commit id; both resolve the same way here.
    #[test]
    fn resource_ref_from_pb_takes_either_child_5066() {
        let named = |child| {
            ResourceRef::from_pb(Some(pb1::resource_ref::Value::Name(
                pb1::resource_ref::Name {
                    owner: "acme".to_string(),
                    module: "payments".to_string(),
                    child,
                },
            )))
        };

        let by_label = named(Some(pb1::resource_ref::name::Child::LabelName(
            "main".to_string(),
        )));
        assert_eq!(by_label.owner.as_deref(), Some("acme"));
        assert_eq!(by_label.label.as_deref(), Some("main"));

        let by_ref = named(Some(pb1::resource_ref::name::Child::Ref("abc".to_string())));
        assert_eq!(by_ref.label.as_deref(), Some("abc"));

        let by_id = ResourceRef::from_pb(Some(pb1::resource_ref::Value::Id("x".to_string())));
        assert_eq!(by_id.id.as_deref(), Some("x"));
        assert!(by_id.label.is_none());
    }

    #[test]
    fn metadata_records_the_commit_id_and_its_b5_5066() {
        let meta = build_protobuf_metadata(
            "acme/payments",
            "abc123",
            1,
            &[],
            "c0ffee",
            &B5Outcome::Resolved("b5:00ff".to_string()),
        );

        assert_eq!(meta["commitId"], "c0ffee");
        assert_eq!(meta["b5Digest"], "b5:00ff");
        assert!(meta.get("b5UnresolvedDeps").is_none());
    }

    /// No digest is recorded when a dependency's own b5 is missing: the names
    /// are kept so a later request in the CLI's codec can say which.
    #[test]
    fn metadata_names_unresolved_deps_instead_of_a_digest_5066() {
        let meta = build_protobuf_metadata(
            "acme/payments",
            "abc123",
            1,
            &["buf.build/bufbuild/protovalidate".to_string()],
            "c0ffee",
            &B5Outcome::UnresolvedDeps(vec!["buf.build/bufbuild/protovalidate".to_string()]),
        );

        assert!(meta.get("b5Digest").is_none());
        assert_eq!(
            meta["b5UnresolvedDeps"][0],
            "buf.build/bufbuild/protovalidate"
        );
    }

    /// #4422: a quota decision maps to the Connect error an upload answers.
    #[test]
    fn connect_quota_decision_maps_scopes_4422() {
        use crate::services::repository_service::QuotaScope;
        assert!(connect_quota_decision(Ok(None)).is_ok());
        for scope in [QuotaScope::Repository, QuotaScope::Project] {
            let resp = connect_quota_decision(Ok(Some(scope))).unwrap_err();
            assert_eq!(resp.status(), StatusCode::INSUFFICIENT_STORAGE);
        }
        let resp =
            connect_quota_decision(Err(crate::error::AppError::Database("x".into()))).unwrap_err();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    // -----------------------------------------------------------------------
    // connect_error
    // -----------------------------------------------------------------------

    /// #3667, end to end. `GetModules` is **anonymous** — it takes no auth
    /// extension at all — and binds the caller's module reference straight
    /// into its lookup. A NUL byte in that reference is rejected by Postgres
    /// at the wire protocol, and the handler used to interpolate the driver
    /// message into its Connect envelope. The #3622 boundary guard covers URL
    /// paths only, so a JSON body still reaches the driver, which is exactly
    /// why the body itself has to be sanitised.
    ///
    /// Runtime-skips when `DATABASE_URL` is unset, like every other in-`src`
    /// DB test.
    #[tokio::test]
    #[allow(clippy::disallowed_methods)]
    // streaming-invariant: test exempt — a small JSON error body is not an
    // artifact path (#1608).
    async fn test_get_modules_database_error_body_carries_no_driver_text_3667() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(fx) = tdh::Fixture::setup("local", "protobuf").await else {
            return;
        };
        // The handler takes the body raw now that it serves both Connect
        // codecs (#5066); no Content-Type selects the JSON one.
        let request = serde_json::json!({
            "moduleRefs": [{ "id": "mod\u{0}ule" }],
        });
        let response = get_modules(
            State(fx.state.clone()),
            Path(fx.repo_key.clone()),
            HeaderMap::new(),
            Bytes::from(serde_json::to_vec(&request).expect("encode request")),
        )
        .await
        .expect_err("a NUL in the module reference must fail the lookup");

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read body");
        let text = String::from_utf8_lossy(&body);
        assert!(
            !text.contains("invalid byte sequence"),
            "leaked the driver message: {text}"
        );
        assert!(!text.contains("UTF8"), "leaked the encoding name: {text}");
        let json: serde_json::Value = serde_json::from_slice(&body).expect("JSON body");
        assert_eq!(json["code"], "internal");
        assert_eq!(json["message"], "Database operation failed");
        fx.teardown().await;
    }

    /// #3667: the 11 DB sites in this file build a Connect error envelope
    /// themselves; the message must be the stable text, never the driver's.
    #[tokio::test]
    #[allow(clippy::disallowed_methods)]
    // streaming-invariant: test exempt — a small JSON error body is not an
    // artifact path (#1608).
    async fn test_connect_error_db_message_carries_no_driver_text_3667() {
        let raw =
            r#"error returned from database: invalid byte sequence for encoding "UTF8": 0x00"#;
        let response = connect_error(
            crate::api::handlers::db_status(raw),
            "internal",
            crate::api::handlers::db_err_message(raw),
        );

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read body");
        let text = String::from_utf8_lossy(&body);
        assert!(
            !text.contains("invalid byte sequence") && !text.contains("UTF8"),
            "the Connect envelope leaked the driver message: {text}"
        );
        let json: serde_json::Value = serde_json::from_slice(&body).expect("JSON body");
        assert_eq!(json["code"], "internal");
        assert_eq!(json["message"], "Database operation failed");
    }

    /// #4765: a database outage in a Connect handler is Connect's retryable
    /// `unavailable` at 503 with `Retry-After: 1`, not `internal` at 500.
    #[tokio::test]
    #[allow(clippy::disallowed_methods)]
    // streaming-invariant: test exempt — a small JSON error body is not an
    // artifact path (#1608).
    async fn test_connect_db_error_db_unavailable_is_503_unavailable_4765() {
        let pool = crate::api::handlers::test_db_helpers::lazy_pool();
        pool.close().await;
        let e = sqlx::query("SELECT 1")
            .fetch_one(&pool)
            .await
            .expect_err("a closed pool cannot run a query");

        let response = connect_db_error(e);

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            response
                .headers()
                .get(axum::http::header::RETRY_AFTER)
                .unwrap(),
            "1"
        );
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read body");
        let json: serde_json::Value = serde_json::from_slice(&body).expect("JSON body");
        assert_eq!(json["code"], "unavailable");
    }

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

    /// #2556: a bundle entry that inflates past the per-entry cap (the worst
    /// in-memory site: every entry is read + base64-encoded) is rejected with a
    /// bounded error instead of buffering unbounded. The compressed bundle stays
    /// tiny (highly repetitive), proving the cap bounds the decompressed size.
    #[test]
    fn test_extract_bundle_oversized_entry_rejected_2556() {
        let oversized = vec![
            b'A';
            (crate::util::bounded_archive::MAX_INGEST_METADATA_ENTRY_BYTES + 1024)
                as usize
        ];
        let files = vec![UploadFile {
            path: "bomb.proto".to_string(),
            content: base64::engine::general_purpose::STANDARD.encode(&oversized),
        }];
        let bundle = build_bundle(&files).unwrap();
        assert!(bundle.len() < 256 * 1024, "compressed bundle stays tiny");
        assert!(
            extract_files_from_bundle(&bundle).is_err(),
            "oversized bundle entry must be rejected"
        );
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
                name: "module".to_string(),
                full_name: "test/module".to_string(),
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
        let meta = build_protobuf_metadata(
            "buf/validate",
            "abc",
            3,
            &deps,
            "c0ffee",
            &B5Outcome::Resolved("b5:beef".to_string()),
        );
        assert_eq!(meta["module"], "buf/validate");
        assert_eq!(meta["commitDigest"], "abc");
        assert_eq!(meta["fileCount"], 3);
        assert_eq!(meta["dependencies"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn test_build_protobuf_metadata_no_deps() {
        let meta = build_protobuf_metadata(
            "m",
            "d",
            0,
            &[],
            "c0ffee",
            &B5Outcome::Resolved("b5:beef".to_string()),
        );
        assert!(meta["dependencies"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_build_protobuf_metadata_many_deps() {
        let deps = vec!["a/b".to_string(), "c/d".to_string(), "e/f".to_string()];
        let meta = build_protobuf_metadata(
            "mod",
            "hash",
            10,
            &deps,
            "c0ffee",
            &B5Outcome::Resolved("b5:beef".to_string()),
        );
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
    // ModuleInfo serialization / build_commit_info / build_label_info
    // -----------------------------------------------------------------------

    #[test]
    fn test_module_info_serialization() {
        // Pins the wire shape (camelCase renames) of the production struct.
        let info = ModuleInfo {
            id: "id".to_string(),
            owner_id: "o".to_string(),
            name: "n".to_string(),
            full_name: "o/n".to_string(),
            create_time: "t1".to_string(),
            update_time: "t2".to_string(),
            state: "ACTIVE".to_string(),
            default_label_name: "main".to_string(),
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"ownerId\""));
        assert!(json.contains("\"defaultLabelName\":\"main\""));
        // `name` is the schema's: the module alone. The full `owner/module`
        // is what the derived ids key on and is not part of the reply -- the
        // CLI rejects a name with a slash in it.
        assert!(json.contains("\"name\":\"n\""));
        assert!(!json.contains("full_name") && !json.contains("fullName"));
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

    // -- The regressions the CLI found (#5117). These need a database, so
    // they runtime-skip when `DATABASE_URL` is unset, like the DB tests
    // above.

    /// Uploads one module over the JSON codec and returns its commit digest.
    #[cfg(test)]
    async fn push_json_module(
        fx: &crate::api::handlers::test_db_helpers::Fixture,
        owner: &str,
        module: &str,
        contents: &[u8],
    ) -> String {
        use crate::api::handlers::test_db_helpers as tdh;
        use base64::Engine;

        let file = (format!("{owner}/{module}/v1/api.proto"), contents.to_vec());
        let digest = compute_commit_digest(std::slice::from_ref(&file));
        let body = serde_json::json!({
            "contents": [{
                "moduleRef": { "owner": owner, "module": module },
                "files": [{
                    "path": file.0,
                    "content": base64::engine::general_purpose::STANDARD.encode(&file.1),
                }],
            }],
        });
        let (status, resp) = tdh::send(
            fx.router_with_auth(super::router()),
            tdh::post(
                format!(
                    "/{}/buf.registry.module.v1beta1.UploadService/Upload",
                    fx.repo_key
                ),
                "application/json",
                bytes::Bytes::from(serde_json::to_vec(&body).unwrap()),
            ),
        )
        .await;
        assert!(
            status.is_success(),
            "upload failed: {status} {}",
            String::from_utf8_lossy(&resp)
        );
        digest
    }

    /// The label index is an artifact row sharing the module's `name`, written
    /// after the commit in the same push (#4889), so a query for the module's
    /// latest commit ordered by time answers with the index unless it is
    /// excluded. Its stored object is a JSON document, so `buf dep update`
    /// resolving a dependency was answered `500 invalid gzip header` from
    /// reading it as a commit bundle.
    #[tokio::test]
    async fn latest_commit_queries_skip_the_label_index_row_5117() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(fx) = tdh::Fixture::setup("local", "protobuf").await else {
            return;
        };
        let digest = push_json_module(&fx, "acme", "latest", b"syntax = \"proto3\";\n").await;

        // The index row exists and is newer, which is what made this fail.
        let (label_created_later,): (bool,) = sqlx::query_as(
            "SELECT max(created_at) FILTER (WHERE version = '_labels') \
                  >= max(created_at) FILTER (WHERE version <> '_labels') \
             FROM artifacts WHERE repository_id = $1 AND name = 'acme/latest'",
        )
        .bind(fx.repo_id)
        .fetch_one(&fx.pool)
        .await
        .expect("compare row ages");
        assert!(
            label_created_later,
            "the premise of this test is that the index row is the newer one"
        );

        // No ref: the module's latest commit.
        let body = serde_json::json!({
            "resourceRefs": [{ "owner": "acme", "module": "latest" }],
        });
        let (status, resp) = tdh::send(
            fx.router_with_auth(super::router()),
            tdh::post(
                format!(
                    "/{}/buf.registry.module.v1.CommitService/GetCommits",
                    fx.repo_key
                ),
                "application/json",
                bytes::Bytes::from(serde_json::to_vec(&body).unwrap()),
            ),
        )
        .await;
        assert!(status.is_success(), "GetCommits failed: {status}");
        let json: serde_json::Value = serde_json::from_slice(&resp).expect("JSON reply");
        assert_eq!(
            json["commits"][0]["digest"]["value"], digest,
            "answered with the label index instead of the commit: {json}"
        );
        fx.teardown().await;
    }

    /// The CLI pairs each reference in a request with one entry in the reply
    /// and treats a short list as a bug in itself, and `buf push --create`
    /// decides to create a module from exactly this `not_found`.
    #[tokio::test]
    async fn a_reference_that_resolves_to_nothing_is_not_found_5117() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(fx) = tdh::Fixture::setup("local", "protobuf").await else {
            return;
        };
        push_json_module(&fx, "acme", "present", b"syntax = \"proto3\";\n").await;

        let cases = [
            (
                "buf.registry.module.v1.ModuleService/GetModules",
                serde_json::json!({ "moduleRefs": [{ "owner": "acme", "module": "absent" }] }),
                "a module that was never pushed",
            ),
            (
                "buf.registry.module.v1.CommitService/GetCommits",
                serde_json::json!({ "resourceRefs": [{ "owner": "acme", "module": "absent" }] }),
                "a commit of a module that was never pushed",
            ),
            (
                "buf.registry.module.v1.CommitService/GetCommits",
                serde_json::json!({
                    "resourceRefs": [{
                        "owner": "acme", "module": "present", "label": "typo-not-a-label",
                    }],
                }),
                "a ref that is neither a label nor a commit id",
            ),
        ];

        for (method, body, what) in cases {
            let (status, resp) = tdh::send(
                fx.router_with_auth(super::router()),
                tdh::post(
                    format!("/{}/{method}", fx.repo_key),
                    "application/json",
                    bytes::Bytes::from(serde_json::to_vec(&body).unwrap()),
                ),
            )
            .await;
            assert_eq!(
                status,
                StatusCode::NOT_FOUND,
                "{what}: {status} {}",
                String::from_utf8_lossy(&resp)
            );
            let json: serde_json::Value = serde_json::from_slice(&resp).expect("JSON error body");
            assert_eq!(json["code"], "not_found", "{what}");
        }
        fx.teardown().await;
    }

    /// The round trip the CLI makes: push over the v1 `UploadService` in the
    /// binary codec, then ask for the commit back by the id the reply gave,
    /// which is a derived tuuid no column holds.
    #[tokio::test]
    async fn a_binary_upload_is_fetched_back_by_its_derived_commit_id_5117() {
        use crate::api::handlers::test_db_helpers as tdh;
        use prost::Message;

        let Some(fx) = tdh::Fixture::setup("local", "protobuf").await else {
            return;
        };

        let request = pb1::UploadRequest {
            contents: vec![pb1::upload_request::Content {
                module_ref: Some(pb1::ModuleRef {
                    value: Some(pb1::module_ref::Value::Name(pb1::module_ref::Name {
                        owner: "acme".to_string(),
                        module: "wire".to_string(),
                    })),
                }),
                files: vec![pb1::File {
                    path: "acme/wire/v1/wire.proto".to_string(),
                    content: b"syntax = \"proto3\";\n".to_vec(),
                }],
                scoped_label_refs: Vec::new(),
                source_control_url: String::new(),
            }],
            dep_commit_ids: Vec::new(),
        };
        let (status, resp) = tdh::send(
            fx.router_with_auth(super::router()),
            tdh::post(
                format!(
                    "/{}/buf.registry.module.v1.UploadService/Upload",
                    fx.repo_key
                ),
                "application/proto",
                bytes::Bytes::from(request.encode_to_vec()),
            ),
        )
        .await;
        assert!(
            status.is_success(),
            "binary upload failed: {status} {}",
            String::from_utf8_lossy(&resp)
        );
        let uploaded =
            pb1::UploadResponse::decode(resp.as_ref()).expect("a protobuf reply, not JSON");
        let commit = uploaded.commits.first().expect("one commit per content");
        assert_eq!(commit.id.len(), 32, "the id is a tuuid: {}", commit.id);
        let digest = commit.digest.as_ref().expect("a digest");
        assert_eq!(digest.r#type, pb1::DigestType::B5 as i32);
        assert_eq!(digest.value.len(), 64, "b5 is 64 raw bytes");

        // By id alone: nothing stores it, so it resolves through the id
        // recorded with the commit at push time.
        let request = pb1::GetCommitsRequest {
            resource_refs: vec![pb1::ResourceRef {
                value: Some(pb1::resource_ref::Value::Id(commit.id.clone())),
            }],
        };
        let (status, resp) = tdh::send(
            fx.router_with_auth(super::router()),
            tdh::post(
                format!(
                    "/{}/buf.registry.module.v1.CommitService/GetCommits",
                    fx.repo_key
                ),
                "application/proto",
                bytes::Bytes::from(request.encode_to_vec()),
            ),
        )
        .await;
        assert!(
            status.is_success(),
            "GetCommits by derived id failed: {status} {}",
            String::from_utf8_lossy(&resp)
        );
        let fetched = pb1::GetCommitsResponse::decode(resp.as_ref()).expect("a protobuf reply");
        let same = fetched.commits.first().expect("one commit per reference");
        assert_eq!(same.id, commit.id);
        assert_eq!(same.digest, commit.digest, "the same b5 digest comes back");
        fx.teardown().await;
    }

    /// Pushes a module in the binary codec and returns its reply.
    #[cfg(test)]
    async fn push_proto_module(
        fx: &crate::api::handlers::test_db_helpers::Fixture,
        owner: &str,
        module: &str,
        contents: &[u8],
        dep_commit_ids: Vec<String>,
    ) -> pb1::Commit {
        use crate::api::handlers::test_db_helpers as tdh;
        use prost::Message;

        let request = pb1::UploadRequest {
            contents: vec![pb1::upload_request::Content {
                module_ref: Some(pb1::ModuleRef {
                    value: Some(pb1::module_ref::Value::Name(pb1::module_ref::Name {
                        owner: owner.to_string(),
                        module: module.to_string(),
                    })),
                }),
                files: vec![pb1::File {
                    path: format!("{owner}/{module}/v1/api.proto"),
                    content: contents.to_vec(),
                }],
                scoped_label_refs: Vec::new(),
                source_control_url: String::new(),
            }],
            dep_commit_ids,
        };
        let (status, resp) = tdh::send(
            fx.router_with_auth(super::router()),
            tdh::post(
                format!(
                    "/{}/buf.registry.module.v1.UploadService/Upload",
                    fx.repo_key
                ),
                "application/proto",
                bytes::Bytes::from(request.encode_to_vec()),
            ),
        )
        .await;
        assert!(
            status.is_success(),
            "binary upload of {owner}/{module} failed: {status} {}",
            String::from_utf8_lossy(&resp)
        );
        pb1::UploadResponse::decode(resp.as_ref())
            .expect("a protobuf reply")
            .commits
            .into_iter()
            .next()
            .expect("one commit per content")
    }

    /// The chain the CLI walks when a consumer pins one module and gets its
    /// dependencies with it: the graph has to be the closure, not the commits
    /// that were asked for, and a dependency recorded as a commit id has to
    /// resolve. The same shape as `test-protobuf-buf-cli.sh`, in a test CI
    /// runs.
    #[tokio::test]
    async fn the_dependency_chain_resolves_over_the_binary_codec_5117() {
        use crate::api::handlers::test_db_helpers as tdh;
        use prost::Message;

        let Some(fx) = tdh::Fixture::setup("local", "protobuf").await else {
            return;
        };

        let base =
            push_proto_module(&fx, "acme", "base", b"syntax = \"proto3\";\n", Vec::new()).await;
        let middle = push_proto_module(
            &fx,
            "acme",
            "middle",
            b"syntax = \"proto3\";\n// middle\n",
            vec![base.id.clone()],
        )
        .await;

        // Asking for the middle module alone must answer with both commits
        // and the edge between them: the CLI builds a map from `commits` and
        // then looks up each edge's node in it.
        let request = pb1::GetGraphRequest {
            resource_refs: vec![pb1::ResourceRef {
                value: Some(pb1::resource_ref::Value::Id(middle.id.clone())),
            }],
        };
        let (status, resp) = tdh::send(
            fx.router_with_auth(super::router()),
            tdh::post(
                format!(
                    "/{}/buf.registry.module.v1.GraphService/GetGraph",
                    fx.repo_key
                ),
                "application/proto",
                bytes::Bytes::from(request.encode_to_vec()),
            ),
        )
        .await;
        assert!(
            status.is_success(),
            "GetGraph failed: {status} {}",
            String::from_utf8_lossy(&resp)
        );
        let graph = pb1::GetGraphResponse::decode(resp.as_ref())
            .expect("a protobuf reply")
            .graph
            .expect("a graph");

        let commit_ids: Vec<&str> = graph.commits.iter().map(|c| c.id.as_str()).collect();
        assert!(
            commit_ids.contains(&middle.id.as_str()) && commit_ids.contains(&base.id.as_str()),
            "the graph must carry the closure, got {commit_ids:?}"
        );
        let edge = graph.edges.first().expect("one dependency edge");
        assert_eq!(
            edge.from_node.as_ref().map(|n| n.commit_id.as_str()),
            Some(middle.id.as_str())
        );
        assert_eq!(
            edge.to_node.as_ref().map(|n| n.commit_id.as_str()),
            Some(base.id.as_str()),
            "the edge must name the commit the dependency was recorded as"
        );

        // And the files come back over the v1 download the CLI uses for b5.
        let request = pb1::DownloadRequest {
            values: vec![pb1::download_request::Value {
                resource_ref: Some(pb1::ResourceRef {
                    value: Some(pb1::resource_ref::Value::Id(middle.id.clone())),
                }),
                file_types: Vec::new(),
                paths: Vec::new(),
                paths_allow_not_exist: false,
            }],
        };
        let (status, resp) = tdh::send(
            fx.router_with_auth(super::router()),
            tdh::post(
                format!(
                    "/{}/buf.registry.module.v1.DownloadService/Download",
                    fx.repo_key
                ),
                "application/proto",
                bytes::Bytes::from(request.encode_to_vec()),
            ),
        )
        .await;
        assert!(
            status.is_success(),
            "Download failed: {status} {}",
            String::from_utf8_lossy(&resp)
        );
        let downloaded = pb1::DownloadResponse::decode(resp.as_ref()).expect("a protobuf reply");
        let content = downloaded.contents.first().expect("one content per value");
        assert_eq!(
            content.commit.as_ref().map(|c| c.id.as_str()),
            Some(middle.id.as_str())
        );
        let file = content.files.first().expect("the pushed file");
        assert_eq!(file.path, "acme/middle/v1/api.proto");
        assert_eq!(file.content, b"syntax = \"proto3\";\n// middle\n");

        fx.teardown().await;
    }

    /// Both proto packages carry the dependency commit ids once for the whole
    /// push, so a push of several modules that declares dependencies cannot
    /// say which module imports which. Recording a digest composed from every
    /// dependency would be wrong for a reason nothing states.
    #[tokio::test]
    async fn a_multi_module_push_with_dependencies_is_refused_5117() {
        use crate::api::handlers::test_db_helpers as tdh;
        use prost::Message;

        let Some(fx) = tdh::Fixture::setup("local", "protobuf").await else {
            return;
        };
        let base =
            push_proto_module(&fx, "acme", "shared", b"syntax = \"proto3\";\n", Vec::new()).await;

        let content = |module: &str| pb1::upload_request::Content {
            module_ref: Some(pb1::ModuleRef {
                value: Some(pb1::module_ref::Value::Name(pb1::module_ref::Name {
                    owner: "acme".to_string(),
                    module: module.to_string(),
                })),
            }),
            files: vec![pb1::File {
                path: format!("acme/{module}/v1/api.proto"),
                content: b"syntax = \"proto3\";\n".to_vec(),
            }],
            scoped_label_refs: Vec::new(),
            source_control_url: String::new(),
        };
        let request = pb1::UploadRequest {
            contents: vec![content("one"), content("two")],
            dep_commit_ids: vec![base.id.clone()],
        };
        let (status, resp) = tdh::send(
            fx.router_with_auth(super::router()),
            tdh::post(
                format!(
                    "/{}/buf.registry.module.v1.UploadService/Upload",
                    fx.repo_key
                ),
                "application/proto",
                bytes::Bytes::from(request.encode_to_vec()),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let json: serde_json::Value = serde_json::from_slice(&resp).expect("a Connect error body");
        assert_eq!(json["code"], "failed_precondition");

        // Nothing was stored: the refusal comes before the first content.
        let stored: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM artifacts WHERE repository_id = $1 AND name IN \
             ('acme/one', 'acme/two')",
        )
        .bind(fx.repo_id)
        .fetch_one(&fx.pool)
        .await
        .expect("count the modules");
        assert_eq!(stored, 0, "a refused push must store nothing");

        fx.teardown().await;
    }

    /// #4725: a `buf push` to a hosted repository must queue a push sync task
    /// for a subscribed push peer. Since #4889 the registry-generated `_labels`
    /// index is a stored JSON document and is queued alongside the commit, and
    /// a push that arrives as peer replication must not be fanned back out.
    #[tokio::test]
    async fn protobuf_upload_queues_push_sync_task_4725() {
        use crate::api::handlers::test_db_helpers as tdh;
        use base64::Engine;

        let Some(fx) = tdh::Fixture::setup("local", "protobuf").await else {
            return;
        };
        let peer_id = tdh::subscribe_push_peer(&fx.pool, fx.repo_id, "protobuf").await;

        let file = (
            "acme/repl/v1/repl.proto".to_string(),
            b"syntax = \"proto3\";\n".as_slice().to_vec(),
        );
        let digest = compute_commit_digest(std::slice::from_ref(&file));
        let body = serde_json::json!({
            "contents": [{
                "moduleRef": { "owner": "acme", "module": "repl" },
                "files": [{
                    "path": file.0,
                    "content": base64::engine::general_purpose::STANDARD.encode(&file.1),
                }],
            }],
        });
        let (status, resp) = tdh::send(
            fx.router_with_auth(super::router()),
            tdh::post(
                format!(
                    "/{}/buf.registry.module.v1beta1.UploadService/Upload",
                    fx.repo_key
                ),
                "application/json",
                bytes::Bytes::from(serde_json::to_vec(&body).unwrap()),
            ),
        )
        .await;
        assert!(
            status.is_success(),
            "upload failed: {status} {}",
            String::from_utf8_lossy(&resp)
        );

        // A replicated push (as the sync worker sends it) stores the commit but
        // must not queue another task.
        let body2 = serde_json::json!({
            "contents": [{
                "moduleRef": { "owner": "acme", "module": "repl" },
                "files": [{
                    "path": "acme/repl/v1/repl.proto",
                    "content": base64::engine::general_purpose::STANDARD
                        .encode(b"syntax = \"proto3\";\n// v2\n"),
                }],
            }],
        });
        let mut req = tdh::post(
            format!(
                "/{}/buf.registry.module.v1beta1.UploadService/Upload",
                fx.repo_key
            ),
            "application/json",
            bytes::Bytes::from(serde_json::to_vec(&body2).unwrap()),
        );
        req.headers_mut().insert(
            "x-artifact-keeper-replication",
            axum::http::HeaderValue::from_static("true"),
        );
        let (status, resp) = tdh::send(fx.router_with_auth(super::router()), req).await;
        assert!(
            status.is_success(),
            "replicated push must succeed: {status} {}",
            String::from_utf8_lossy(&resp)
        );

        let queued = tdh::queued_push_paths(&fx.pool, peer_id, fx.repo_id).await;

        // #4889: the `_labels` row must carry real bytes so the sync worker can
        // transfer it, and the label move must be queued to the push peer. The
        // replicated push above must not queue another task.
        let (label_size, label_checksum, label_key): (i64, String, String) = sqlx::query_as(
            "SELECT size_bytes, checksum_sha256, storage_key FROM artifacts \
             WHERE repository_id = $1 AND path = 'modules/acme/repl/_labels'",
        )
        .bind(fx.repo_id)
        .fetch_one(&fx.pool)
        .await
        .expect("load _labels row");
        assert!(label_size > 0, "the _labels document must have bytes");
        assert_ne!(label_checksum, "none");
        let stored = tokio::fs::read(fx.storage_dir.join(&label_key))
            .await
            .expect("read the stored _labels document");
        let stored: serde_json::Value = serde_json::from_slice(&stored).unwrap();
        assert!(stored["labels"]["main"].is_string());

        tdh::delete_push_peer(&fx.pool, peer_id).await;
        fx.teardown().await;
        assert_eq!(
            queued,
            vec![
                "modules/acme/repl/_labels".to_string(),
                format!("modules/acme/repl/commits/{digest}"),
            ],
            "the client push queues the commit and the label index; \
             the replicated push must not queue another task"
        );
    }

    /// #4916: every label move stores a new content-addressed JSON document.
    /// The superseded object must be reclaimed once no live row names it, and
    /// the document must carry a monotonic revision for peer conflict
    /// resolution.
    #[tokio::test]
    async fn save_label_index_reclaims_superseded_document_4916() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(fx) = tdh::Fixture::setup("local", "protobuf").await else {
            return;
        };
        let repo = fx.repo_info("local", None);
        let module = "acme/labels";
        let mut labels = serde_json::Map::new();
        labels.insert("main".to_string(), serde_json::json!("commit-a"));
        save_label_index(
            &fx.state,
            &repo,
            module,
            &labels,
            fx.user_id,
            &HeaderMap::new(),
        )
        .await
        .expect("first label move");

        let label_path = build_label_path(module);
        let (first_key, first_metadata): (String, serde_json::Value) = sqlx::query_as(
            "SELECT a.storage_key, am.metadata FROM artifacts a \
             JOIN artifact_metadata am ON am.artifact_id = a.id \
             WHERE a.repository_id = $1 AND a.path = $2",
        )
        .bind(fx.repo_id)
        .bind(&label_path)
        .fetch_one(&fx.pool)
        .await
        .expect("first label row");
        let first_object = fx.storage_dir.join(&first_key);
        assert!(
            tokio::fs::metadata(&first_object).await.is_ok(),
            "the first label document must be stored"
        );
        assert_eq!(first_metadata["revision"], 1);

        labels.insert("main".to_string(), serde_json::json!("commit-b"));
        save_label_index(
            &fx.state,
            &repo,
            module,
            &labels,
            fx.user_id,
            &HeaderMap::new(),
        )
        .await
        .expect("second label move");

        let (second_key, second_metadata, second_size): (String, serde_json::Value, i64) =
            sqlx::query_as(
                "SELECT a.storage_key, am.metadata, a.size_bytes FROM artifacts a \
                 JOIN artifact_metadata am ON am.artifact_id = a.id \
                 WHERE a.repository_id = $1 AND a.path = $2",
            )
            .bind(fx.repo_id)
            .bind(&label_path)
            .fetch_one(&fx.pool)
            .await
            .expect("second label row");
        let stored = tokio::fs::read(fx.storage_dir.join(&second_key))
            .await
            .expect("read the current label document");
        fx.teardown().await;

        assert_ne!(first_key, second_key, "a label move writes a new document");
        assert_eq!(second_metadata["revision"], 2);
        assert_eq!(second_metadata["labels"]["main"], "commit-b");
        assert_eq!(second_size, stored.len() as i64);
        assert!(
            tokio::fs::metadata(&first_object).await.is_err(),
            "the superseded label document must not be left behind"
        );
        let stored: serde_json::Value = serde_json::from_slice(&stored).unwrap();
        assert_eq!(stored["labels"]["main"], "commit-b");
        assert_eq!(stored["revision"], 2);
    }

    /// #4916: a label document replicated to a peer arrives byte for byte.
    /// The source's stored JSON is what the sync worker sends; the peer must
    /// store exactly those bytes (same sha256 and size) with the same label
    /// map and revision, and a later move must replace it the same way.
    #[tokio::test]
    async fn replicated_label_document_round_trips_byte_exact_4916() {
        use crate::api::handlers::test_db_helpers as tdh;
        use sha2::{Digest, Sha256};

        let Some(source) = tdh::Fixture::setup("local", "protobuf").await else {
            return;
        };
        let Some(peer) = tdh::Fixture::setup("local", "protobuf").await else {
            source.teardown().await;
            return;
        };
        let repo = source.repo_info("local", None);
        let module = "acme/roundtrip";
        let label_path = build_label_path(module);
        let row_sql = "SELECT a.storage_key, a.size_bytes, a.checksum_sha256, am.metadata \
                       FROM artifacts a JOIN artifact_metadata am ON am.artifact_id = a.id \
                       WHERE a.repository_id = $1 AND a.path = $2 AND a.is_deleted = false";
        let mut labels = serde_json::Map::new();
        let mut rounds = Vec::new();
        for (revision, commit) in [(1, "commit-a"), (2, "commit-b")] {
            labels.insert("main".to_string(), serde_json::json!(commit));
            labels.insert(format!("v{revision}"), serde_json::json!(commit));
            save_label_index(
                &source.state,
                &repo,
                module,
                &labels,
                source.user_id,
                &HeaderMap::new(),
            )
            .await
            .expect("label move");
            let (key, size, sha, metadata): (String, i64, String, serde_json::Value) =
                sqlx::query_as(row_sql)
                    .bind(source.repo_id)
                    .bind(&label_path)
                    .fetch_one(&source.pool)
                    .await
                    .expect("source label row");
            let sent = tokio::fs::read(source.storage_dir.join(&key))
                .await
                .expect("source label document");

            // What the sync worker sends: the stored bytes, their sha256, and
            // the `protobuf` metadata document.
            let (status, body) = peer
                .chunked_upload_as(
                    tdh::admin_auth(peer.user_id, &peer.username),
                    &label_path,
                    &sent,
                    serde_json::json!({
                        "artifact_name": module,
                        "artifact_version": "_labels",
                        "artifact_metadata_format": "protobuf",
                        "artifact_metadata": metadata,
                    }),
                    true,
                )
                .await;
            let (peer_key, peer_size, peer_sha, peer_metadata): (
                String,
                i64,
                String,
                serde_json::Value,
            ) = sqlx::query_as(row_sql)
                .bind(peer.repo_id)
                .bind(&label_path)
                .fetch_one(&peer.pool)
                .await
                .expect("peer label row");
            let received = tokio::fs::read(peer.storage_dir.join(&peer_key))
                .await
                .expect("peer label document");
            rounds.push((
                revision,
                status,
                body,
                sent,
                size,
                sha,
                metadata,
                received,
                peer_size,
                peer_sha,
                peer_metadata,
            ));
        }
        sqlx::query("DELETE FROM upload_sessions WHERE repository_id = $1")
            .bind(peer.repo_id)
            .execute(&peer.pool)
            .await
            .ok();
        source.teardown().await;
        peer.teardown().await;

        for (
            revision,
            status,
            body,
            sent,
            size,
            sha,
            metadata,
            received,
            peer_size,
            peer_sha,
            peer_metadata,
        ) in rounds
        {
            assert!(
                status.is_success(),
                "revision {revision}: {status} {}",
                String::from_utf8_lossy(&body)
            );
            assert_eq!(received, sent, "revision {revision}: bytes must match");
            assert_eq!(peer_size, size);
            assert_eq!(peer_size, sent.len() as i64);
            assert_eq!(peer_sha.trim(), sha.trim());
            assert_eq!(peer_sha.trim(), format!("{:x}", Sha256::digest(&sent)));
            assert_eq!(peer_metadata, metadata);
            assert_eq!(peer_metadata["revision"], revision);
            let doc: serde_json::Value = serde_json::from_slice(&received).unwrap();
            assert_eq!(doc["labels"], peer_metadata["labels"]);
        }
    }

    /// #4921: a pushed commit must be accepted by the receiving peer. The
    /// sync worker sends the row's `checksum_sha256` with the stored bundle,
    /// and the peer's upload session verifies the bytes against it; before
    /// the fix the row held the commit digest and every push was refused 409
    /// "checksum mismatch". This replays the worker's session against a
    /// second repository (the peer) with the source row's values.
    #[tokio::test]
    async fn protobuf_commit_push_is_accepted_by_peer_4921() {
        use crate::api::handlers::test_db_helpers as tdh;
        use axum::Extension;
        use base64::Engine;

        let Some(fx) = tdh::Fixture::setup("local", "protobuf").await else {
            return;
        };
        let Some(peer) = tdh::Fixture::setup("local", "protobuf").await else {
            fx.teardown().await;
            return;
        };

        let file = (
            "acme/pushed/v1/pushed.proto".to_string(),
            b"syntax = \"proto3\";\npackage acme.pushed.v1;\n"
                .as_slice()
                .to_vec(),
        );
        let digest = compute_commit_digest(std::slice::from_ref(&file));
        let body = serde_json::json!({
            "contents": [{
                "moduleRef": { "owner": "acme", "module": "pushed" },
                "files": [{
                    "path": file.0,
                    "content": base64::engine::general_purpose::STANDARD.encode(&file.1),
                }],
            }],
        });
        let (status, resp) = tdh::send(
            fx.router_with_auth(super::router()),
            tdh::post(
                format!(
                    "/{}/buf.registry.module.v1beta1.UploadService/Upload",
                    fx.repo_key
                ),
                "application/json",
                bytes::Bytes::from(serde_json::to_vec(&body).unwrap()),
            ),
        )
        .await;
        assert!(
            status.is_success(),
            "upload failed: {status} {}",
            String::from_utf8_lossy(&resp)
        );

        // What the sync worker reads for the push task.
        let (path, name, version, size, checksum, storage_key, content_type, metadata): (
            String,
            String,
            Option<String>,
            i64,
            String,
            String,
            String,
            Option<serde_json::Value>,
        ) = sqlx::query_as(
            "SELECT a.path, a.name, a.version, a.size_bytes, a.checksum_sha256, \
                    a.storage_key, a.content_type, am.metadata \
             FROM artifacts a LEFT JOIN artifact_metadata am ON am.artifact_id = a.id \
             WHERE a.repository_id = $1 AND a.path = $2",
        )
        .bind(fx.repo_id)
        .bind(format!("modules/acme/pushed/commits/{digest}"))
        .fetch_one(&fx.pool)
        .await
        .expect("load commit row");
        let stored = tokio::fs::read(fx.storage_dir.join(&storage_key))
            .await
            .expect("read the stored commit bundle");
        assert_eq!(version.as_deref(), Some(digest.as_str()));
        assert_eq!(size, stored.len() as i64);

        let mut auth = tdh::make_auth(peer.user_id, &peer.username);
        auth.is_admin = true;
        let upload_app = || {
            crate::api::handlers::upload::router()
                .with_state(peer.state.clone())
                .layer(Extension::<crate::api::middleware::auth::AuthExtension>(
                    auth.clone(),
                ))
        };
        let replication = |mut req: axum::http::Request<axum::body::Body>| {
            req.headers_mut().insert(
                "x-artifact-keeper-replication",
                axum::http::HeaderValue::from_static("true"),
            );
            req
        };

        let session_body = serde_json::json!({
            "repository_key": peer.repo_key,
            "artifact_path": path,
            "artifact_name": name,
            "artifact_version": version,
            "artifact_metadata_format": "protobuf",
            "artifact_metadata": metadata,
            "total_size": size,
            "checksum_sha256": checksum.trim(),
            "chunk_size": 8 * 1024 * 1024,
            "content_type": content_type,
        });
        let (status, resp) = tdh::send(
            upload_app(),
            replication(tdh::post(
                "/".to_string(),
                "application/json",
                bytes::Bytes::from(serde_json::to_vec(&session_body).unwrap()),
            )),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "create session: {}",
            String::from_utf8_lossy(&resp)
        );
        let session: serde_json::Value = serde_json::from_slice(&resp).unwrap();
        let session_id = session["session_id"].as_str().unwrap().to_string();

        let req = axum::http::Request::builder()
            .method("PATCH")
            .uri(format!("/{session_id}"))
            .header(
                "content-range",
                format!("bytes 0-{}/{}", stored.len() - 1, stored.len()),
            )
            .header("content-type", "application/octet-stream")
            .body(axum::body::Body::from(stored.clone()))
            .unwrap();
        let (status, resp) = tdh::send(upload_app(), replication(req)).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "chunk PATCH: {}",
            String::from_utf8_lossy(&resp)
        );

        let req = axum::http::Request::builder()
            .method("PUT")
            .uri(format!("/{session_id}/complete"))
            .body(axum::body::Body::empty())
            .unwrap();
        let (complete_status, complete_resp) = tdh::send(upload_app(), replication(req)).await;

        let peer_row: Option<(Option<String>, String)> = sqlx::query_as(
            "SELECT version, checksum_sha256 FROM artifacts \
             WHERE repository_id = $1 AND path = $2 AND is_deleted = false",
        )
        .bind(peer.repo_id)
        .bind(&path)
        .fetch_optional(&peer.pool)
        .await
        .expect("load peer row");

        peer.teardown().await;
        fx.teardown().await;

        assert_eq!(
            complete_status,
            StatusCode::OK,
            "the peer must accept the pushed commit: {}",
            String::from_utf8_lossy(&complete_resp)
        );
        let (peer_version, peer_checksum) = peer_row.expect("the peer holds the commit");
        assert_eq!(peer_version.as_deref(), Some(digest.as_str()));
        assert_eq!(
            peer_checksum.trim(),
            format!("{:x}", Sha256::digest(&stored)),
            "the peer row carries the sha256 of the bundle"
        );
    }
}

// ---------------------------------------------------------------------------
// #3659: the native publish path must register the package catalog row.
// ---------------------------------------------------------------------------

#[cfg(ak_test_shard = "handlers-2")]
#[cfg(test)]
mod catalog_registration_tests {
    use crate::api::handlers::test_db_helpers as tdh;

    /// A `buf push` must register the catalog row under the module name and
    /// its commit digest.
    #[tokio::test]
    async fn module_upload_registers_catalog_row() {
        use base64::Engine;

        let Some(fx) = tdh::Fixture::setup("local", "protobuf").await else {
            return;
        };
        let body = serde_json::json!({
            "contents": [{
                "moduleRef": { "owner": "acme", "module": "widgets" },
                "files": [{
                    "path": "acme/widgets/v1/widget.proto",
                    "content": base64::engine::general_purpose::STANDARD
                        .encode(b"syntax = \"proto3\";\n"),
                }],
            }],
        });

        let (status, resp) = tdh::send(
            fx.router_with_auth(super::router()),
            tdh::post(
                format!(
                    "/{}/buf.registry.module.v1beta1.UploadService/Upload",
                    fx.repo_key
                ),
                "application/json",
                bytes::Bytes::from(serde_json::to_vec(&body).unwrap()),
            ),
        )
        .await;
        assert!(
            status.is_success(),
            "upload failed: {status} {}",
            String::from_utf8_lossy(&resp)
        );

        // The upload writes two `artifacts` rows for the module: the content
        // (version = its digest) and the `_labels` index (version = '_labels',
        // see `update_labels`). Without this filter the unordered
        // `fetch_optional` returned either one and the assertion below was
        // a coin flip.
        let digest: Option<String> = sqlx::query_scalar(
            "SELECT version FROM artifacts \
             WHERE repository_id = $1 AND name = 'acme/widgets' AND version IS DISTINCT FROM '_labels'",
        )
        .bind(fx.repo_id)
        .fetch_optional(&fx.pool)
        .await
        .expect("read artifact version");
        let row = tdh::catalog_row(&fx.pool, fx.repo_id, "acme/widgets").await;
        fx.teardown().await;

        let digest = digest.expect("the upload must write an artifact row");
        let row = row.expect("a protobuf upload must write a packages row (#3659)");
        assert_eq!(row.version, digest);
        assert_eq!(row.versions, vec![digest]);
    }

    /// #4422 review: a `buf push` past the repository quota answers the
    /// Connect `resource_exhausted` error with status 507 and writes no row.
    #[tokio::test]
    async fn module_upload_refused_by_quota_answers_connect_507_4422() {
        use base64::Engine;

        let Some(fx) = tdh::Fixture::setup("local", "protobuf").await else {
            return;
        };
        sqlx::query("UPDATE repositories SET quota_bytes = 1 WHERE id = $1")
            .bind(fx.repo_id)
            .execute(&fx.pool)
            .await
            .unwrap();
        let body = serde_json::json!({
            "contents": [{
                "moduleRef": { "owner": "acme", "module": "quota" },
                "files": [{
                    "path": "acme/quota/v1/q.proto",
                    "content": base64::engine::general_purpose::STANDARD
                        .encode(b"syntax = \"proto3\";\n"),
                }],
            }],
        });
        let (status, resp) = tdh::send(
            fx.router_with_auth(super::router()),
            tdh::post(
                format!(
                    "/{}/buf.registry.module.v1beta1.UploadService/Upload",
                    fx.repo_key
                ),
                "application/json",
                bytes::Bytes::from(serde_json::to_vec(&body).unwrap()),
            ),
        )
        .await;
        let rows: i64 =
            sqlx::query_scalar("SELECT count(*) FROM artifacts WHERE repository_id = $1")
                .bind(fx.repo_id)
                .fetch_one(&fx.pool)
                .await
                .unwrap();
        fx.teardown().await;

        let resp: serde_json::Value = serde_json::from_slice(&resp).expect("connect error json");
        assert_eq!(
            status,
            axum::http::StatusCode::INSUFFICIENT_STORAGE,
            "{resp}"
        );
        assert_eq!(resp["code"], "resource_exhausted", "{resp}");
        assert_eq!(resp["message"], "Repository storage quota exceeded");
        assert_eq!(rows, 0);
    }
}

/// #3919 review (B1): a protobuf commit row written before #4921 records the
/// COMMIT digest (over file paths + contents), not the SHA-256 of the stored
/// gzip bundle. Download verification must not abort those downloads.
#[cfg(ak_test_shard = "handlers-2")]
#[cfg(test)]
pub(crate) mod integrity_tests {
    use crate::api::handlers::test_db_helpers as tdh;

    /// Push one module through the real BSR upload route and return its
    /// commit digest (the artifact row's `version`).
    pub(crate) async fn push_module(fx: &tdh::Fixture) -> String {
        use base64::Engine;
        let body = serde_json::json!({
            "contents": [{
                "moduleRef": { "owner": "acme", "module": "integrity" },
                "files": [{
                    "path": "acme/integrity/v1/thing.proto",
                    "content": base64::engine::general_purpose::STANDARD
                        .encode(b"syntax = \"proto3\";\nmessage Thing {}\n"),
                }],
            }],
        });
        let (status, resp) = tdh::send(
            fx.router_with_auth(super::router()),
            tdh::post(
                format!(
                    "/{}/buf.registry.module.v1beta1.UploadService/Upload",
                    fx.repo_key
                ),
                "application/json",
                bytes::Bytes::from(serde_json::to_vec(&body).unwrap()),
            ),
        )
        .await;
        assert!(
            status.is_success(),
            "upload failed: {status} {}",
            String::from_utf8_lossy(&resp)
        );
        sqlx::query_scalar(
            "SELECT version FROM artifacts \
             WHERE repository_id = $1 AND name = 'acme/integrity' AND version IS DISTINCT FROM '_labels'",
        )
        .bind(fx.repo_id)
        .fetch_one(&fx.pool)
        .await
        .expect("commit row")
    }

    #[tokio::test]
    #[allow(clippy::disallowed_methods)]
    // streaming-invariant: test exempt — collects a small test bundle to
    // assert it was delivered in full (#1608).
    async fn protobuf_commit_bundle_downloads_in_full_with_verification_on() {
        let Some(fx) = tdh::Fixture::setup("local", "protobuf").await else {
            return;
        };
        assert!(fx.state.config.download_verify_checksums);
        let digest = push_module(&fx).await;
        // Since #4921 a new commit row records the bundle's sha256; rows
        // written before that still hold the commit digest. Put the row in
        // that legacy shape: its download must not be aborted either.
        sqlx::query(
            "UPDATE artifacts SET checksum_sha256 = version \
             WHERE repository_id = $1 AND version = $2",
        )
        .bind(fx.repo_id)
        .bind(&digest)
        .execute(&fx.pool)
        .await
        .expect("legacy checksum");
        let (size, recorded): (i64, String) = sqlx::query_as(
            "SELECT size_bytes, checksum_sha256 FROM artifacts \
             WHERE repository_id = $1 AND version = $2",
        )
        .bind(fx.repo_id)
        .bind(&digest)
        .fetch_one(&fx.pool)
        .await
        .expect("row");

        use tower::ServiceExt;
        let resp = fx
            .router_with_auth(crate::api::handlers::repositories::download_router())
            .oneshot(tdh::get(format!(
                "/{}/download/modules/acme/integrity/commits/{digest}",
                fx.repo_key
            )))
            .await
            .expect("respond");
        let status = resp.status();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await;
        fx.teardown().await;

        assert_eq!(status, axum::http::StatusCode::OK);
        let body = body.expect("a protobuf commit bundle must download completely");
        assert_eq!(body.len() as i64, size);
        // Pin the premise: the recorded checksum is NOT the bundle's digest.
        use sha2::Digest;
        assert_ne!(recorded.trim(), hex::encode(sha2::Sha256::digest(&body)));
    }

    /// #3910 review (B1): the scrub must not flag protobuf commit bundles as
    /// corrupt (their row records the commit digest, not the bundle's).
    #[tokio::test]
    async fn scrub_reports_nothing_for_protobuf_commit_bundles() {
        use crate::services::storage_scrub_service::{ScrubOptions, StorageScrubService};
        let Some(fx) = tdh::Fixture::setup("local", "protobuf").await else {
            return;
        };
        push_module(&fx).await;
        let res = StorageScrubService::new(fx.pool.clone(), fx.state.storage_registry.clone())
            .run(&ScrubOptions {
                max_objects: 100,
                max_bytes: 1 << 30,
                repair: true,
                repository_id: Some(fx.repo_id),
            })
            .await
            .expect("scrub run");
        let findings: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM storage_scrub_findings WHERE repository_id = $1",
        )
        .bind(fx.repo_id)
        .fetch_one(&fx.pool)
        .await
        .expect("count findings");
        fx.teardown().await;

        assert_eq!(res.corrupt + res.missing + res.repaired, 0, "{res:?}");
        assert!(res.unverifiable >= 1, "{res:?}");
        assert_eq!(findings, 0);
    }
}
