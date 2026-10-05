//! Bazel module registry (Bzlmod / BCR-compatible) handlers (#2858).
//!
//! Serves the static file layout a Bazel client walks when a repository is
//! named with `--registry=<base>/bazel/{repo_key}`:
//!
//!   GET  /bazel/{repo_key}/bazel_registry.json                         - Registry config
//!   GET  /bazel/{repo_key}/modules/{name}/metadata.json                - Version list
//!   GET  /bazel/{repo_key}/modules/{name}/{version}/MODULE.bazel       - Module file
//!   GET  /bazel/{repo_key}/modules/{name}/{version}/source.json        - Source descriptor
//!   GET  /bazel/{repo_key}/modules/{name}/{version}/{file...}          - Patches, overlays, archives
//!   PUT  /bazel/{repo_key}/modules/{name}/{version}/{file...}          - Publish a file (hosted)
//!
//! Hosted repositories generate `metadata.json` from the versions that have a
//! stored `MODULE.bazel`, so publishing a version is just uploading its files.
//! Remote repositories proxy an upstream registry (normally
//! `https://bcr.bazel.build`): the registry config and `metadata.json` are
//! revalidated on the mutable TTL, every versioned file is cached as immutable
//! (the BCR forbids changing a published version). Virtual repositories merge
//! `metadata.json` across their members and resolve versioned files by member
//! priority; a module that a hosted member publishes shadows the same module
//! name on every Remote member.

use std::cmp::Ordering;
use std::collections::BTreeSet;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Extension;
use axum::Router;
use bytes::Bytes;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tracing::info;
use uuid::Uuid;

use crate::api::handlers::proxy_helpers::{self, RepoInfo};
use crate::api::middleware::auth::{require_auth_basic_scope, AuthExtension};
use crate::api::middleware::download_telemetry::DownloadContext;
use crate::api::SharedState;
use crate::models::repository::{RepositoryFormat, RepositoryType};

const REGISTRY_FILE: &str = "bazel_registry.json";

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn router() -> Router<SharedState> {
    Router::new().route("/:repo_key/*path", get(get_file).put(put_file))
}

// ---------------------------------------------------------------------------
// Request classification (pure)
// ---------------------------------------------------------------------------

/// One request against the registry layout.
#[derive(Debug, Clone, PartialEq, Eq)]
enum BazelRequest {
    /// `bazel_registry.json`
    RegistryConfig,
    /// `modules/{name}/metadata.json`
    ModuleMetadata { name: String },
    /// `modules/{name}/{version}/{file}` where `file` may contain `/`
    /// (`patches/fix.patch`, `overlay/BUILD.bazel`).
    ModuleFile {
        name: String,
        version: String,
        file: String,
    },
}

impl BazelRequest {
    /// The registry-relative path, which is also the stored artifact path and
    /// the upstream/proxy-cache path.
    fn path(&self) -> String {
        match self {
            Self::RegistryConfig => REGISTRY_FILE.to_string(),
            Self::ModuleMetadata { name } => format!("modules/{}/metadata.json", name),
            Self::ModuleFile {
                name,
                version,
                file,
            } => format!("modules/{}/{}/{}", name, version, file),
        }
    }
}

/// A path segment that is safe to splice into a storage key and an upstream
/// URL: non-empty, not a dot segment, and free of separators, control
/// characters and URL metacharacters (`%`, `?`, `#` would smuggle a query,
/// fragment or second encoding layer upstream; no registry file needs them).
fn is_safe_segment(seg: &str) -> bool {
    !seg.is_empty()
        && seg != "."
        && seg != ".."
        && !seg
            .chars()
            .any(|c| matches!(c, '/' | '\\' | '%' | '?' | '#') || c.is_control())
}

/// Bazel module names are `[a-z]([a-z0-9._-]*[a-z0-9])?`. Upper case is
/// tolerated so a remote registry with looser naming still proxies.
fn is_valid_module_name(name: &str) -> bool {
    name.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// Bazel versions are dot-separated identifiers with optional `-prerelease`
/// and `+build` parts (`1.2.3`, `0.0.0-20240101-abc`, `27.0.bcr.1`).
fn is_valid_module_version(version: &str) -> bool {
    is_safe_segment(version)
        && !version.starts_with('.')
        && version
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '+'))
}

/// Classify a registry-relative request path, or `None` when it is not part of
/// the registry layout (answered with 404).
fn classify_request(path: &str) -> Option<BazelRequest> {
    let path = path.trim_start_matches('/');
    if path == REGISTRY_FILE {
        return Some(BazelRequest::RegistryConfig);
    }
    let rest = path.strip_prefix("modules/")?;
    let mut parts = rest.splitn(3, '/');
    let name = parts.next()?;
    let second = parts.next()?;
    if !is_valid_module_name(name) {
        return None;
    }
    match parts.next() {
        None if second == "metadata.json" => Some(BazelRequest::ModuleMetadata {
            name: name.to_string(),
        }),
        Some(file) if is_valid_module_version(second) && file.split('/').all(is_safe_segment) => {
            Some(BazelRequest::ModuleFile {
                name: name.to_string(),
                version: second.to_string(),
                file: file.to_string(),
            })
        }
        _ => None,
    }
}

/// Content type for a served registry file.
fn content_type_for(path: &str) -> &'static str {
    let leaf = path.rsplit('/').next().unwrap_or(path).to_ascii_lowercase();
    if leaf.ends_with(".json") {
        "application/json"
    } else if leaf.ends_with(".tar.gz") || leaf.ends_with(".tgz") {
        "application/gzip"
    } else if leaf.ends_with(".zip") {
        "application/zip"
    } else if leaf == "module.bazel"
        || leaf.starts_with("build")
        || [".patch", ".diff", ".bzl", ".bazel", ".txt", ".yml", ".yaml"]
            .iter()
            .any(|ext| leaf.ends_with(ext))
    {
        "text/plain; charset=utf-8"
    } else {
        "application/octet-stream"
    }
}

// ---------------------------------------------------------------------------
// metadata.json (pure)
// ---------------------------------------------------------------------------

/// Order Bazel versions the way the registry lists them: release identifiers
/// compared component-wise (numeric components numerically and below
/// alphanumeric ones), a pre-release below its release, build metadata
/// ignored. This only sorts the advertised list; Bazel re-sorts it itself.
fn compare_versions(a: &str, b: &str) -> Ordering {
    fn split(v: &str) -> (&str, Option<&str>) {
        let v = v.split('+').next().unwrap_or(v);
        match v.split_once('-') {
            Some((rel, pre)) => (rel, Some(pre)),
            None => (v, None),
        }
    }
    fn cmp_ids(a: &str, b: &str) -> Ordering {
        let mut ia = a.split('.');
        let mut ib = b.split('.');
        loop {
            match (ia.next(), ib.next()) {
                (None, None) => return Ordering::Equal,
                (None, Some(_)) => return Ordering::Less,
                (Some(_), None) => return Ordering::Greater,
                (Some(x), Some(y)) => {
                    let ord = match (x.parse::<u64>(), y.parse::<u64>()) {
                        (Ok(nx), Ok(ny)) => nx.cmp(&ny),
                        (Ok(_), Err(_)) => Ordering::Less,
                        (Err(_), Ok(_)) => Ordering::Greater,
                        (Err(_), Err(_)) => x.cmp(y),
                    };
                    if ord != Ordering::Equal {
                        return ord;
                    }
                }
            }
        }
    }
    let (ra, pa) = split(a);
    let (rb, pb) = split(b);
    cmp_ids(ra, rb).then_with(|| match (pa, pb) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Greater,
        (Some(_), None) => Ordering::Less,
        (Some(x), Some(y)) => cmp_ids(x, y),
    })
}

fn sorted_versions(versions: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut out: Vec<String> = versions
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    out.sort_by(|a, b| compare_versions(a, b));
    out
}

/// The `metadata.json` a hosted repository serves for a module, generated from
/// its published versions.
fn build_metadata(versions: impl IntoIterator<Item = String>) -> serde_json::Value {
    serde_json::json!({
        "versions": sorted_versions(versions),
        "yanked_versions": {},
    })
}

/// Merge member `metadata.json` documents (highest priority first) into one:
/// the versions are unioned, a yanked version keeps the reason of the first
/// member that yanked it, and every other field comes from the first member.
/// Returns `None` when there is nothing to merge.
fn merge_metadata(docs: Vec<serde_json::Value>) -> Option<serde_json::Value> {
    let mut docs = docs.into_iter().filter(|d| d.is_object());
    let mut merged = docs.next()?;
    let mut versions: Vec<String> = Vec::new();
    let mut yanked = serde_json::Map::new();
    let mut absorb = |doc: &serde_json::Value| {
        if let Some(list) = doc.get("versions").and_then(|v| v.as_array()) {
            versions.extend(list.iter().filter_map(|v| v.as_str().map(str::to_string)));
        }
        if let Some(map) = doc.get("yanked_versions").and_then(|v| v.as_object()) {
            for (k, v) in map {
                yanked.entry(k.clone()).or_insert_with(|| v.clone());
            }
        }
    };
    absorb(&merged);
    for doc in docs {
        absorb(&doc);
    }
    let obj = merged.as_object_mut()?;
    obj.insert(
        "versions".into(),
        serde_json::json!(sorted_versions(versions)),
    );
    obj.insert("yanked_versions".into(), serde_json::Value::Object(yanked));
    Some(merged)
}

/// The version a stored path publishes for `name`: `modules/{name}/{v}/MODULE.bazel`.
fn version_from_module_path(path: &str, name: &str) -> Option<String> {
    match classify_request(path)? {
        BazelRequest::ModuleFile {
            name: n,
            version,
            file,
        } if n == name && file == "MODULE.bazel" => Some(version),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Database lookups
// ---------------------------------------------------------------------------

async fn resolve_bazel_repo(db: &PgPool, repo_key: &str) -> Result<RepoInfo, Response> {
    proxy_helpers::resolve_repo_by_key(db, repo_key, &["bazel"], "a Bazel").await
}

/// Versions of `name` published (with a `MODULE.bazel`) in any of `repo_ids`.
async fn hosted_versions(
    db: &PgPool,
    repo_ids: &[Uuid],
    name: &str,
) -> Result<Vec<String>, Response> {
    if repo_ids.is_empty() {
        return Ok(Vec::new());
    }
    let pattern = format!(
        "modules/{}/%/MODULE.bazel",
        super::escape_like_literal(name)
    );
    let paths: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT path FROM artifacts \
         WHERE repository_id = ANY($1) AND is_deleted = false \
           AND path LIKE $2 ESCAPE '\\'",
    )
    .bind(repo_ids)
    .bind(&pattern)
    .fetch_all(db)
    .await
    .map_err(super::db_err)?;
    Ok(paths
        .iter()
        .filter_map(|p| version_from_module_path(p, name))
        .collect())
}

fn non_remote_ids(members: Vec<crate::models::repository::Repository>) -> Vec<Uuid> {
    members
        .into_iter()
        .filter(|m| m.repo_type != RepositoryType::Remote)
        .map(|m| m.id)
        .collect()
}

/// How a virtual repository's hosted members relate to one module name.
struct HostedOwnership {
    /// Some hosted member publishes the name, whether or not the caller may
    /// read it. Decided over ALL members (an enforcement walk, like the
    /// `virtual_non_remote_owns_*` guards): narrowing by caller visibility
    /// would hand an anonymous caller the upstream copy of a name a private
    /// hosted member owns, the dependency-confusion case #1217 closes.
    owned: bool,
    /// The versions the caller may see (hosted members it can read).
    visible_versions: Vec<String>,
}

async fn hosted_ownership(
    state: &SharedState,
    auth: Option<&AuthExtension>,
    virtual_id: Uuid,
    name: &str,
) -> Result<HostedOwnership, Response> {
    let all = non_remote_ids(proxy_helpers::fetch_virtual_members(&state.db, virtual_id).await?);
    if hosted_versions(&state.db, &all, name).await?.is_empty() {
        return Ok(HostedOwnership {
            owned: false,
            visible_versions: Vec::new(),
        });
    }
    let readable = non_remote_ids(
        proxy_helpers::authorized_virtual_members(&state.db, auth, virtual_id).await?,
    );
    Ok(HostedOwnership {
        owned: true,
        visible_versions: hosted_versions(&state.db, &readable, name).await?,
    })
}

/// Look up a hosted file by its EXACT stored path. A suffix match would let a
/// file published under another module (`modules/evil/1.0/x/modules/a/1.0/
/// source.json`) shadow the real `modules/a/1.0/source.json`.
async fn find_hosted_exact(
    db: &PgPool,
    repo_id: Uuid,
    path: &str,
) -> Result<Option<proxy_helpers::LocalArtifactHit>, Response> {
    let row: Option<(Uuid, String)> = sqlx::query_as(
        "SELECT id, storage_key FROM artifacts \
         WHERE repository_id = $1 AND path = $2 AND is_deleted = false \
         LIMIT 1",
    )
    .bind(repo_id)
    .bind(path)
    .fetch_optional(db)
    .await
    .map_err(super::db_err)?;
    Ok(row.map(|(id, storage_key)| proxy_helpers::LocalArtifactHit { id, storage_key }))
}

// ---------------------------------------------------------------------------
// GET
// ---------------------------------------------------------------------------

fn not_found(what: &str) -> Response {
    (StatusCode::NOT_FOUND, format!("{} not found", what)).into_response()
}

async fn get_file(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((repo_key, path)): Path<(String, String)>,
    ctx: DownloadContext,
) -> Result<Response, Response> {
    let repo = resolve_bazel_repo(&state.db, &repo_key).await?;
    let request = classify_request(&path).ok_or_else(|| not_found("Registry file"))?;

    if repo.repo_type == RepositoryType::Remote {
        return proxy_remote(&state, &repo, &request, &ctx).await;
    }
    let is_virtual = repo.repo_type == RepositoryType::Virtual;

    match &request {
        BazelRequest::RegistryConfig => {
            if !is_virtual {
                if let Some(hit) = find_hosted_exact(&state.db, repo.id, REGISTRY_FILE).await? {
                    return serve_hosted(&state, &repo, hit, REGISTRY_FILE, &ctx).await;
                }
            }
            // Bazel treats every field as optional; no mirrors means "fetch
            // archives from the URL in `source.json`".
            Ok(super::json_response(&serde_json::json!({ "mirrors": [] })))
        }
        BazelRequest::ModuleMetadata { name } => {
            let doc = if is_virtual {
                virtual_metadata(&state, auth.as_ref(), &repo, name).await?
            } else {
                let versions = hosted_versions(&state.db, &[repo.id], name).await?;
                (!versions.is_empty()).then(|| build_metadata(versions))
            };
            let doc = doc.ok_or_else(|| not_found("Module"))?;
            Ok(super::json_response(&doc))
        }
        BazelRequest::ModuleFile { name, .. } => {
            let rel = request.path();
            if !is_virtual {
                let hit = find_hosted_exact(&state.db, repo.id, &rel)
                    .await?
                    .ok_or_else(|| not_found("Module file"))?;
                return serve_hosted(&state, &repo, hit, &rel, &ctx).await;
            }
            // A module a hosted member publishes shadows the same name on
            // every Remote member (the #1217 name-shadowing guard).
            let owned_locally = hosted_ownership(&state, auth.as_ref(), repo.id, name)
                .await?
                .owned;
            let opts = proxy_helpers::DownloadResponseOpts {
                upstream_path: &rel,
                virtual_lookup: proxy_helpers::VirtualLookup::ExactPath(&rel),
                default_content_type: content_type_for(&rel),
                content_disposition_filename: None,
                suppress_upstream_proxy: owned_locally,
            };
            proxy_helpers::try_remote_or_virtual_download(&state, auth.as_ref(), &repo, &ctx, opts)
                .await?
                .ok_or_else(|| not_found("Module file"))
        }
    }
}

async fn serve_hosted(
    state: &SharedState,
    repo: &RepoInfo,
    hit: proxy_helpers::LocalArtifactHit,
    rel: &str,
    ctx: &DownloadContext,
) -> Result<Response, Response> {
    proxy_helpers::serve_local_artifact(
        state,
        repo,
        hit.id,
        &hit.storage_key,
        content_type_for(rel),
        None,
        ctx,
    )
    .await
}

/// Proxy one registry file from a Remote repository's upstream. The real
/// format is passed so the cache classifier keeps versioned files forever and
/// revalidates `bazel_registry.json` / `metadata.json` on the mutable TTL.
async fn proxy_remote(
    state: &SharedState,
    repo: &RepoInfo,
    request: &BazelRequest,
    ctx: &DownloadContext,
) -> Result<Response, Response> {
    let (Some(upstream_url), Some(proxy)) =
        (repo.upstream_url.as_deref(), state.proxy_service.as_deref())
    else {
        return Err(not_found("Registry file"));
    };
    let rel = request.path();
    let response = proxy_helpers::proxy_fetch_streaming_with_disposition_and_format(
        proxy,
        repo.id,
        &repo.key,
        upstream_url,
        &rel,
        content_type_for(&rel),
        None,
        RepositoryFormat::Bazel,
    )
    .await?;
    if matches!(request, BazelRequest::ModuleFile { .. }) {
        proxy_helpers::record_proxy_download(state, repo.id, &repo.key, &rel, ctx).await;
    }
    Ok(response)
}

/// `metadata.json` for a virtual repository. When any hosted member publishes
/// the module, Remote members are shadowed (matching the file route) and only
/// the hosted versions the caller may read are advertised (none: 404);
/// otherwise every Remote member's document is merged in priority order.
async fn virtual_metadata(
    state: &SharedState,
    auth: Option<&AuthExtension>,
    repo: &RepoInfo,
    name: &str,
) -> Result<Option<serde_json::Value>, Response> {
    let hosted = hosted_ownership(state, auth, repo.id, name).await?;
    if hosted.owned {
        let versions = hosted.visible_versions;
        return Ok((!versions.is_empty()).then(|| build_metadata(versions)));
    }
    let docs = proxy_helpers::collect_virtual_metadata(
        &state.db,
        auth,
        state.proxy_service.as_deref(),
        repo.id,
        &format!("modules/{}/metadata.json", name),
        // A member whose document does not parse is logged and skipped by
        // `collect_virtual_metadata`; the error value itself is discarded.
        |bytes, _member| async move {
            serde_json::from_slice::<serde_json::Value>(&bytes)
                .map_err(|_| StatusCode::BAD_GATEWAY.into_response())
        },
    )
    .await?;
    Ok(merge_metadata(docs.into_iter().map(|(_, d)| d).collect()))
}

// ---------------------------------------------------------------------------
// PUT /bazel/{repo_key}/modules/{name}/{version}/{file...} — Publish a file
// ---------------------------------------------------------------------------

/// Storage key for a published file, unique per content.
fn storage_key_for(artifact_path: &str, sha256: &str) -> String {
    format!("bazel/{}/{}", sha256, artifact_path)
}

/// Validate an uploaded file's body for the registry file it is published as.
#[allow(clippy::result_large_err)]
fn validate_upload(file: &str, body: &[u8]) -> Result<(), Response> {
    if body.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Empty file").into_response());
    }
    if file == "source.json" && serde_json::from_slice::<serde_json::Value>(body).is_err() {
        return Err((StatusCode::BAD_REQUEST, "source.json is not valid JSON").into_response());
    }
    Ok(())
}

async fn put_file(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((repo_key, path)): Path<(String, String)>,
    body: Bytes,
) -> Result<Response, Response> {
    let user_id = require_auth_basic_scope(auth, "bazel", "write:artifacts")?.user_id;
    let repo = resolve_bazel_repo(&state.db, &repo_key).await?;
    proxy_helpers::reject_write_if_not_hosted(&repo.repo_type)?;
    repo.reject_if_promotion_only(false)?;

    let Some(BazelRequest::ModuleFile {
        name,
        version,
        file,
    }) = classify_request(&path)
    else {
        return Err((
            StatusCode::BAD_REQUEST,
            "Only modules/{name}/{version}/{file} can be published; \
             metadata.json is generated from the published versions",
        )
            .into_response());
    };
    validate_upload(&file, &body)?;

    let artifact_path = format!("modules/{}/{}/{}", name, version, file);
    crate::services::upload_service::validate_artifact_path(&artifact_path)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()).into_response())?;
    let checksum = format!("{:x}", Sha256::digest(&body));
    // A deleted version stays immutable: re-publishing the same path is only
    // allowed with identical bytes (Bazel lockfiles pin these hashes).
    super::cleanup_soft_deleted_artifact_checked(
        &state.db,
        &RepositoryFormat::Bazel,
        repo.id,
        &artifact_path,
        &checksum,
    )
    .await
    .map_err(|e| e.into_response())?;
    let ensure_unique = || {
        proxy_helpers::ensure_unique_artifact_path(
            &state.db,
            repo.id,
            &artifact_path,
            "Module file already exists",
        )
    };
    ensure_unique().await?;

    // Content-addressed key: a concurrent PUT of different bytes to the same
    // path cannot overwrite the blob the winning row points at.
    let storage_key = storage_key_for(&artifact_path, &checksum);
    proxy_helpers::put_artifact_bytes(&state, &repo, &storage_key, body.clone()).await?;

    let inserted = proxy_helpers::insert_artifact(
        &state.db,
        proxy_helpers::NewArtifact {
            repository_id: repo.id,
            path: &artifact_path,
            name: &name,
            version: &version,
            size_bytes: body.len() as i64,
            checksum_sha256: &checksum,
            content_type: content_type_for(&file),
            storage_key: &storage_key,
            uploaded_by: user_id,
        },
    )
    .await;
    let artifact_id = match inserted {
        Ok(id) => id,
        // Lost a race with a concurrent PUT of the same path: the
        // UNIQUE(repository_id, path) violation surfaces as a 409 like the
        // pre-check, not a 500.
        Err(resp) => {
            ensure_unique().await?;
            return Err(resp);
        }
    };

    let metadata = serde_json::json!({ "name": name, "version": version, "filename": file });
    proxy_helpers::record_artifact_metadata(&state.db, artifact_id, repo.id, "bazel", &metadata)
        .await;
    crate::services::scanner_service::trigger_scan_on_upload(
        &state.db,
        state.scanner_service.clone(),
        repo.id,
        artifact_id,
    )
    .await;

    // A version becomes resolvable (listed in metadata.json) when its
    // MODULE.bazel is published, so that file registers the catalog row and
    // fires the one artifact.uploaded webhook event for the version (#3659).
    if file == "MODULE.bazel" {
        crate::services::package_service::register_published_package(
            &state.db,
            &state.event_bus,
            repo.id,
            "bazel",
            &name,
            &version,
            body.len() as i64,
            &checksum,
            None,
        )
        .await;
    }

    info!(
        "Bazel publish: {} {} {} to repo {}",
        name, version, file, repo_key
    );
    Ok((StatusCode::CREATED, "Published").into_response())
}

#[cfg(ak_test_shard = "handlers-1")]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::handlers::test_db_helpers as tdh;

    fn module_file(name: &str, version: &str, file: &str) -> Option<BazelRequest> {
        Some(BazelRequest::ModuleFile {
            name: name.into(),
            version: version.into(),
            file: file.into(),
        })
    }

    #[test]
    fn classify_request_recognises_the_registry_layout() {
        assert_eq!(
            classify_request("bazel_registry.json"),
            Some(BazelRequest::RegistryConfig)
        );
        assert_eq!(
            classify_request("/modules/rules_cc/metadata.json"),
            Some(BazelRequest::ModuleMetadata {
                name: "rules_cc".into()
            })
        );
        assert_eq!(
            classify_request("modules/rules_cc/0.1.1/MODULE.bazel"),
            module_file("rules_cc", "0.1.1", "MODULE.bazel")
        );
        assert_eq!(
            classify_request("modules/protobuf/29.0-rc2.bcr.1/patches/a.patch"),
            module_file("protobuf", "29.0-rc2.bcr.1", "patches/a.patch")
        );
        let req = classify_request("modules/abseil-cpp/20240116.2/source.json").unwrap();
        assert_eq!(req.path(), "modules/abseil-cpp/20240116.2/source.json");
        assert_eq!(
            BazelRequest::ModuleMetadata { name: "x".into() }.path(),
            "modules/x/metadata.json"
        );
        assert_eq!(BazelRequest::RegistryConfig.path(), REGISTRY_FILE);
    }

    #[test]
    fn classify_request_rejects_traversal_and_foreign_paths() {
        for bad in [
            "",
            "modules",
            "modules/rules_cc",
            "modules/rules_cc/",
            "modules/rules_cc/1.0",
            "modules/rules_cc/1.0/",
            "modules/rules_cc/../x/MODULE.bazel",
            "modules/rules_cc/1.0/../../etc/passwd",
            "modules/rules_cc/1.0/a//b",
            "modules/rules_cc/../MODULE.bazel",
            "modules/1abc/1.0/MODULE.bazel",
            "modules/rules cc/1.0/MODULE.bazel",
            "modules/rules_cc/.hidden/MODULE.bazel",
            "modules/rules_cc/1.0 /MODULE.bazel",
            "modules/rules_cc/1.0/MODULE.bazel%3Fx",
            "modules/rules_cc/1.0/MODULE.bazel?x=1",
            "modules/rules_cc/1.0/a#frag",
            "modules/rules_cc/1%2e0/MODULE.bazel",
            "other/bazel_registry.json",
            "v2/_catalog",
        ] {
            assert_eq!(classify_request(bad), None, "{bad:?} must not classify");
        }
    }

    #[test]
    fn content_type_by_leaf() {
        assert_eq!(
            content_type_for("modules/a/1/source.json"),
            "application/json"
        );
        assert_eq!(
            content_type_for("modules/a/1/MODULE.bazel"),
            "text/plain; charset=utf-8"
        );
        assert_eq!(
            content_type_for("modules/a/1/patches/x.patch"),
            "text/plain; charset=utf-8"
        );
        assert_eq!(
            content_type_for("modules/a/1/overlay/BUILD"),
            "text/plain; charset=utf-8"
        );
        assert_eq!(content_type_for("modules/a/1/a.tar.gz"), "application/gzip");
        assert_eq!(content_type_for("modules/a/1/a.zip"), "application/zip");
        assert_eq!(
            content_type_for("modules/a/1/a.bin"),
            "application/octet-stream"
        );
    }

    #[test]
    fn versions_sort_in_registry_order() {
        let got = sorted_versions(
            [
                "1.10.0",
                "1.2.0",
                "1.2.0-rc1",
                "1.2.0",
                "0.0.0-20240101-abc",
                "27.0.bcr.1",
                "27.0",
                "1.2.0+build5",
            ]
            .map(String::from),
        );
        assert_eq!(
            got,
            vec![
                "0.0.0-20240101-abc",
                "1.2.0-rc1",
                "1.2.0",
                "1.2.0+build5",
                "1.10.0",
                "27.0",
                "27.0.bcr.1",
            ]
        );
        assert_eq!(compare_versions("1.0-rc1", "1.0-rc2"), Ordering::Less);
        assert_eq!(compare_versions("1.0", "1.0"), Ordering::Equal);
    }

    #[test]
    fn build_metadata_lists_sorted_versions() {
        let doc = build_metadata(["2.0".to_string(), "1.0".to_string()]);
        assert_eq!(
            doc,
            serde_json::json!({"versions": ["1.0", "2.0"], "yanked_versions": {}})
        );
    }

    #[test]
    fn merge_metadata_unions_versions_and_keeps_first_member_fields() {
        let first = serde_json::json!({
            "homepage": "https://a",
            "versions": ["1.0", "2.0"],
            "yanked_versions": {"1.0": "first reason"},
        });
        let second = serde_json::json!({
            "homepage": "https://b",
            "versions": ["2.0", "3.0"],
            "yanked_versions": {"1.0": "second reason", "3.0": "bad"},
        });
        let merged = merge_metadata(vec![first, serde_json::json!("junk"), second]).unwrap();
        assert_eq!(merged["homepage"], "https://a");
        assert_eq!(merged["versions"], serde_json::json!(["1.0", "2.0", "3.0"]));
        assert_eq!(
            merged["yanked_versions"],
            serde_json::json!({"1.0": "first reason", "3.0": "bad"})
        );
        assert_eq!(merge_metadata(vec![]), None);
        assert_eq!(merge_metadata(vec![serde_json::json!([1])]), None);
    }

    #[test]
    fn version_from_module_path_only_matches_the_module_file() {
        assert_eq!(
            version_from_module_path("modules/a/1.0/MODULE.bazel", "a"),
            Some("1.0".into())
        );
        assert_eq!(
            version_from_module_path("modules/a/1.0/source.json", "a"),
            None
        );
        assert_eq!(
            version_from_module_path("modules/ab/1.0/MODULE.bazel", "a"),
            None
        );
        assert_eq!(
            version_from_module_path("modules/a/1.0/x/MODULE.bazel", "a"),
            None
        );
    }

    #[test]
    fn validate_upload_rules() {
        assert!(validate_upload("MODULE.bazel", b"").is_err());
        assert!(validate_upload("source.json", b"{not json").is_err());
        assert!(validate_upload("source.json", br#"{"url":"u"}"#).is_ok());
        assert!(validate_upload("patches/a.patch", b"--- a").is_ok());
    }

    // -----------------------------------------------------------------------
    // DB-backed router tests
    // -----------------------------------------------------------------------

    /// PUT as the fixture user, an ordinary member of the fixture repository.
    async fn put_as_member(f: &tdh::Fixture, path: &str, body: &'static [u8]) -> StatusCode {
        put_with(f.router_with_auth(super::router()), &f.repo_key, path, body).await
    }

    async fn put_with(app: Router, key: &str, path: &str, body: &'static [u8]) -> StatusCode {
        let uri = format!("/{}/{}", key, path);
        tdh::send(app, tdh::put(uri, Bytes::from_static(body)))
            .await
            .0
    }

    async fn fetch(app: Router, uri: String) -> (StatusCode, Bytes) {
        tdh::send(app, tdh::get(uri)).await
    }

    /// Serve each `(path, body)` from the mock upstream registry.
    async fn mount_upstream(server: &wiremock::MockServer, files: &[(&str, &str)]) {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};
        for (p, body) in files {
            Mock::given(method("GET"))
                .and(path(*p))
                .respond_with(ResponseTemplate::new(200).set_body_string(*body))
                .mount(server)
                .await;
        }
    }

    fn json(body: &[u8]) -> serde_json::Value {
        serde_json::from_slice(body).expect("json body")
    }

    #[tokio::test]
    async fn hosted_publish_then_resolve() {
        let Some(f) = tdh::Fixture::setup("local", "bazel").await else {
            return;
        };
        for (path, body) in [
            (
                "modules/mylib/1.10.0/MODULE.bazel",
                &b"module(name='mylib')"[..],
            ),
            (
                "modules/mylib/1.2.0/MODULE.bazel",
                &b"module(name='mylib')"[..],
            ),
            ("modules/mylib/1.2.0/source.json", &br#"{"url":"u"}"#[..]),
            ("modules/mylib/1.2.0/patches/fix.patch", &b"--- a"[..]),
        ] {
            assert_eq!(
                put_as_member(&f, path, body).await,
                StatusCode::CREATED,
                "{path}"
            );
        }
        // Published versions are immutable.
        assert_eq!(
            put_as_member(&f, "modules/mylib/1.2.0/MODULE.bazel", b"other").await,
            StatusCode::CONFLICT
        );
        // metadata.json is generated, never uploaded.
        assert_eq!(
            put_as_member(&f, "modules/mylib/metadata.json", b"{}").await,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            put_as_member(&f, "modules/mylib/1.3.0/source.json", b"nope").await,
            StatusCode::BAD_REQUEST
        );

        let app = f.router_anon(super::router());
        let key = &f.repo_key;
        let (status, body) =
            fetch(app.clone(), format!("/{key}/modules/mylib/metadata.json")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            json(&body)["versions"],
            serde_json::json!(["1.2.0", "1.10.0"])
        );

        let (status, body) = fetch(
            app.clone(),
            format!("/{key}/modules/mylib/1.2.0/MODULE.bazel"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(&body[..], b"module(name='mylib')");
        let (status, body) = fetch(
            app.clone(),
            format!("/{key}/modules/mylib/1.2.0/patches/fix.patch"),
        )
        .await;
        assert_eq!((status, &body[..]), (StatusCode::OK, &b"--- a"[..]));

        let (status, body) = fetch(app.clone(), format!("/{key}/bazel_registry.json")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json(&body), serde_json::json!({"mirrors": []}));

        // A file published under another module whose tail spells this
        // module's path must not shadow it (exact-path lookup), and a module
        // file named bazel_registry.json must not become the registry config.
        for (path, body) in [
            (
                "modules/evil/1.0/x/modules/mylib/1.2.0/MODULE.bazel",
                &b"evil"[..],
            ),
            (
                "modules/evil/1.0/x/modules/mylib/1.2.0/source.json",
                &br#"{"url":"evil"}"#[..],
            ),
            (
                "modules/x/1.0/bazel_registry.json",
                &br#"{"mirrors":["https://evil/"]}"#[..],
            ),
        ] {
            assert_eq!(put_as_member(&f, path, body).await, StatusCode::CREATED);
        }
        for (path, want) in [
            (
                "modules/mylib/1.2.0/MODULE.bazel",
                &b"module(name='mylib')"[..],
            ),
            ("modules/mylib/1.2.0/source.json", &br#"{"url":"u"}"#[..]),
        ] {
            let (status, body) = fetch(app.clone(), format!("/{key}/{path}")).await;
            assert_eq!((status, &body[..]), (StatusCode::OK, want), "{path}");
        }
        let (_, body) = fetch(app.clone(), format!("/{key}/bazel_registry.json")).await;
        assert_eq!(json(&body), serde_json::json!({"mirrors": []}));

        // A deleted version stays immutable: only identical bytes republish.
        sqlx::query(
            "UPDATE artifacts SET is_deleted = true WHERE repository_id = $1 AND path = $2",
        )
        .bind(f.repo_id)
        .bind("modules/mylib/1.2.0/source.json")
        .execute(&f.pool)
        .await
        .expect("soft-delete");
        assert_eq!(
            put_as_member(&f, "modules/mylib/1.2.0/source.json", br#"{"url":"swap"}"#).await,
            StatusCode::CONFLICT
        );
        assert_eq!(
            put_as_member(&f, "modules/mylib/1.2.0/source.json", br#"{"url":"u"}"#).await,
            StatusCode::CREATED
        );

        for missing in [
            "modules/other/metadata.json",
            "modules/mylib/9.9.9/MODULE.bazel",
            "modules/mylib/1.2.0/../../x",
            "not/a/registry/path",
        ] {
            let (status, _) = fetch(app.clone(), format!("/{key}/{missing}")).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{missing}");
        }
        f.teardown().await;
    }

    #[tokio::test]
    async fn hosted_serves_stored_registry_config() {
        let Some(f) = tdh::Fixture::setup("local", "bazel").await else {
            return;
        };
        let repo = f.repo_info("local", None);
        let config: &[u8] = br#"{"mirrors":["https://mirror.example/"]}"#;
        tdh::seed_artifact(
            &f.state,
            &f.pool,
            &repo,
            "bazel/bazel_registry.json",
            REGISTRY_FILE,
            REGISTRY_FILE,
            "",
            "application/json",
            Bytes::from_static(config),
            f.user_id,
        )
        .await;
        let (status, body) = fetch(
            f.router_anon(super::router()),
            format!("/{}/{}", f.repo_key, REGISTRY_FILE),
        )
        .await;
        assert_eq!((status, &body[..]), (StatusCode::OK, config));
        f.teardown().await;
    }

    #[tokio::test]
    async fn remote_without_upstream_or_proxy_is_404() {
        // The fixture state carries no proxy service.
        let Some(f) = tdh::Fixture::setup("remote", "bazel").await else {
            return;
        };
        let (status, _) = fetch(
            f.router_anon(super::router()),
            format!("/{}/modules/a/1.0/MODULE.bazel", f.repo_key),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        f.teardown().await;
    }

    #[tokio::test]
    async fn hosted_publish_requires_auth_and_hosted_repo() {
        let Some(f) = tdh::Fixture::setup("local", "bazel").await else {
            return;
        };
        let app = f.router_anon(super::router());
        let req = tdh::put(
            format!("/{}/modules/a/1.0/MODULE.bazel", f.repo_key),
            Bytes::from_static(b"m"),
        );
        assert_eq!(tdh::send(app, req).await.0, StatusCode::UNAUTHORIZED);

        // A token without write:artifacts cannot publish.
        let mut read_only = tdh::make_auth(f.user_id, &f.username);
        read_only.is_api_token = true;
        read_only.scopes = Some(vec!["read:artifacts".to_string()]);
        let app = tdh::router_with_auth(super::router(), f.state.clone(), read_only);
        assert_eq!(
            put_with(app, &f.repo_key, "modules/a/1.0/MODULE.bazel", b"m").await,
            StatusCode::FORBIDDEN
        );

        f.set_promotion_only(true).await;
        assert_eq!(
            put_as_member(&f, "modules/a/1.0/MODULE.bazel", b"m").await,
            StatusCode::CONFLICT
        );
        f.teardown().await;

        let Some(f) = tdh::Fixture::setup("virtual", "bazel").await else {
            return;
        };
        assert_eq!(
            put_as_member(&f, "modules/a/1.0/MODULE.bazel", b"m").await,
            StatusCode::BAD_REQUEST
        );
        f.teardown().await;

        let Some(f) = tdh::Fixture::setup("remote", "bazel").await else {
            return;
        };
        assert_eq!(
            put_as_member(&f, "modules/a/1.0/MODULE.bazel", b"m").await,
            StatusCode::METHOD_NOT_ALLOWED
        );
        f.teardown().await;
    }

    #[tokio::test]
    async fn remote_proxies_upstream_registry() {
        use wiremock::MockServer;

        let Some(f) = tdh::Fixture::setup("remote", "bazel").await else {
            return;
        };
        let server = MockServer::start().await;
        mount_upstream(
            &server,
            &[
                ("/bazel_registry.json", r#"{"mirrors":["https://m/"]}"#),
                (
                    "/modules/rules_cc/metadata.json",
                    r#"{"versions":["0.1.1"]}"#,
                ),
                (
                    "/modules/rules_cc/0.1.1/MODULE.bazel",
                    "module(name='rules_cc')",
                ),
            ],
        )
        .await;
        let (state, cache) = tdh::rewire_remote_proxy(&f, &server.uri()).await;
        let app = tdh::router_anon(super::router(), state);
        let key = &f.repo_key;

        let (status, body) = fetch(app.clone(), format!("/{key}/bazel_registry.json")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json(&body)["mirrors"][0], "https://m/");
        let (status, body) = fetch(
            app.clone(),
            format!("/{key}/modules/rules_cc/metadata.json"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json(&body)["versions"], serde_json::json!(["0.1.1"]));
        let (status, body) = fetch(
            app.clone(),
            format!("/{key}/modules/rules_cc/0.1.1/MODULE.bazel"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(&body[..], b"module(name='rules_cc')");
        // The real format reaches the cache classifier: a versioned file is
        // kept forever, the version list revalidates on the mutable TTL.
        let immutable = crate::services::cache_classifier::Mutability::Immutable.write_ttl_secs();
        let module_ttl =
            tdh::written_proxy_ttl_secs(cache.path(), key, "modules/rules_cc/0.1.1/MODULE.bazel")
                .await;
        let metadata_ttl =
            tdh::written_proxy_ttl_secs(cache.path(), key, "modules/rules_cc/metadata.json").await;
        assert_eq!(module_ttl, immutable);
        assert!(metadata_ttl < immutable, "metadata.json must stay mutable");
        let (status, _) = fetch(app.clone(), format!("/{key}/modules/absent/metadata.json")).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        f.teardown().await;
    }

    #[tokio::test]
    async fn virtual_merges_members_and_hosted_shadows_remote() {
        use wiremock::MockServer;

        // The fixture repo is the (private) hosted member; the fixture user is
        // an ordinary member of it, an anonymous caller cannot read it.
        let Some(f) = tdh::Fixture::setup("local", "bazel").await else {
            return;
        };
        assert_eq!(
            put_as_member(&f, "modules/internal/1.0.0/MODULE.bazel", b"internal").await,
            StatusCode::CREATED
        );

        let server = MockServer::start().await;
        mount_upstream(
            &server,
            &[
                (
                    "/modules/rules_cc/metadata.json",
                    r#"{"versions":["0.2.0","0.1.1"]}"#,
                ),
                (
                    "/modules/internal/metadata.json",
                    r#"{"versions":["6.6.6"]}"#,
                ),
                ("/modules/rules_cc/0.1.1/MODULE.bazel", "upstream rules_cc"),
                ("/modules/internal/1.0.0/MODULE.bazel", "upstream impostor"),
            ],
        )
        .await;
        let (virtual_id, virtual_key, vdir) = tdh::create_repo(&f.pool, "virtual", "bazel").await;
        tdh::publish_repo(&f.pool, virtual_id).await;
        // The remote member outranks the hosted one, so only the shadowing
        // guard keeps the impostor out.
        let (remote_id, _, rdir) =
            tdh::attach_remote_member(&f.pool, virtual_id, "bazel", &server.uri(), 0).await;
        tdh::link_virtual_member(&f.pool, virtual_id, f.repo_id, 1).await;
        // A lower-priority member whose metadata.json is not JSON is skipped
        // by the merge rather than failing it.
        let junk = MockServer::start().await;
        mount_upstream(&junk, &[("/modules/rules_cc/metadata.json", "not json")]).await;
        let (junk_id, _jkey, jdir) =
            tdh::attach_remote_member(&f.pool, virtual_id, "bazel", &junk.uri(), 2).await;

        let cache = tempfile::tempdir().expect("tempdir");
        let proxy =
            tdh::build_proxy_service_with_fs(f.pool.clone(), cache.path().to_str().unwrap());
        let state =
            tdh::build_state_with_proxy(f.pool.clone(), cache.path().to_str().unwrap(), proxy);
        let anon = tdh::router_anon(super::router(), state.clone());
        let app = tdh::router_with_auth(
            super::router(),
            state,
            tdh::make_auth(f.user_id, &f.username),
        );
        let vk = &virtual_key;

        let (status, body) =
            fetch(app.clone(), format!("/{vk}/modules/rules_cc/metadata.json")).await;
        assert_eq!(status, StatusCode::OK, "{:?}", body);
        assert_eq!(
            json(&body)["versions"],
            serde_json::json!(["0.1.1", "0.2.0"])
        );
        let (status, body) = fetch(
            app.clone(),
            format!("/{vk}/modules/rules_cc/0.1.1/MODULE.bazel"),
        )
        .await;
        assert_eq!(
            (status, &body[..]),
            (StatusCode::OK, &b"upstream rules_cc"[..])
        );
        // A versioned file fetched through a Remote member is cached with the
        // member's real format, i.e. as immutable.
        let rkey = sqlx::query_scalar::<_, String>("SELECT key FROM repositories WHERE id = $1")
            .bind(remote_id)
            .fetch_one(&f.pool)
            .await
            .expect("remote key");
        assert_eq!(
            tdh::written_proxy_ttl_secs(cache.path(), &rkey, "modules/rules_cc/0.1.1/MODULE.bazel")
                .await,
            crate::services::cache_classifier::Mutability::Immutable.write_ttl_secs()
        );

        let (status, body) =
            fetch(app.clone(), format!("/{vk}/modules/internal/metadata.json")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json(&body)["versions"], serde_json::json!(["1.0.0"]));
        let (status, body) = fetch(
            app.clone(),
            format!("/{vk}/modules/internal/1.0.0/MODULE.bazel"),
        )
        .await;
        assert_eq!((status, &body[..]), (StatusCode::OK, &b"internal"[..]));

        let (status, body) = fetch(app.clone(), format!("/{vk}/bazel_registry.json")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json(&body), serde_json::json!({"mirrors": []}));
        let (status, _) = fetch(app.clone(), format!("/{vk}/modules/absent/metadata.json")).await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // An anonymous caller cannot read the private hosted member, but the
        // member still owns `internal`: the upstream impostor must not be
        // served in its place (dependency confusion, #1217).
        for path in [
            "modules/internal/metadata.json",
            "modules/internal/1.0.0/MODULE.bazel",
        ] {
            let (status, body) = fetch(anon.clone(), format!("/{vk}/{path}")).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{path}: {body:?}");
        }
        let (status, body) = fetch(
            anon.clone(),
            format!("/{vk}/modules/rules_cc/metadata.json"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            json(&body)["versions"],
            serde_json::json!(["0.1.1", "0.2.0"])
        );

        tdh::cleanup_member_repo(&f.pool, junk_id, &jdir).await;
        tdh::cleanup_member_repo(&f.pool, remote_id, &rdir).await;
        tdh::cleanup_member_repo(&f.pool, virtual_id, &vdir).await;
        f.teardown().await;
    }
}
