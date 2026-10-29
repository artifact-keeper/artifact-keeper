//! Terraform Registry Protocol API handlers.
//!
//! Implements the Terraform Registry Protocol for modules and providers,
//! compatible with both Terraform CLI and OpenTofu.
//!
//! Routes are mounted at `/terraform/{repo_key}/...`:
//!
//! Service Discovery:
//!   GET  /terraform/{repo_key}/.well-known/terraform.json
//!
//! Module Registry:
//!   GET  /terraform/{repo_key}/v1/modules/{namespace}/{name}/{provider}/versions
//!   GET  /terraform/{repo_key}/v1/modules/{namespace}/{name}/{provider}/{version}/download
//!   GET  /terraform/{repo_key}/v1/modules/{namespace}/{name}/{provider}
//!   GET  /terraform/{repo_key}/v1/modules/search?q=query
//!   PUT  /terraform/{repo_key}/v1/modules/{namespace}/{name}/{provider}/{version}
//!
//! Provider Registry:
//!   GET  /terraform/{repo_key}/v1/providers/{namespace}/{type}/versions
//!   GET  /terraform/{repo_key}/v1/providers/{namespace}/{type}/{version}/download/{os}/{arch}
//!   GET  /terraform/{repo_key}/v1/providers/{namespace}/{type}/{version}/binary/{os}/{arch}
//!   GET  /terraform/{repo_key}/v1/providers/{namespace}/{type}/{version}/SHA256SUMS
//!   GET  /terraform/{repo_key}/v1/providers/{namespace}/{type}/{version}/SHA256SUMS.sig
//!   PUT  /terraform/{repo_key}/v1/providers/{namespace}/{type}/{version}/{os}/{arch}
//!
//! Host-level discovery (mounted by `crate::api::routes`, not by [`router`]):
//!   GET  /.well-known/terraform.json   (see [`host_service_discovery`])
//!
//! Note the two distinct provider endpoints, which the Provider Registry
//! Protocol keeps separate: `.../download/{os}/{arch}` returns the JSON
//! *package document*, whose `download_url` field then points at
//! `.../binary/{os}/{arch}`, which streams the `.zip` itself.
//!
//! # Hosted repos as an origin provider registry
//!
//! A hosted repo can be used directly as `host/namespace/type` (no
//! `network_mirror`). For that, the package document also carries
//! `shasums_url`, `shasums_signature_url` and `signing_keys`: `SHA256SUMS` is
//! computed from the stored packages and signed per request with the
//! repository's active OpenPGP signing key (the same key and service that sign
//! Debian/RPM metadata). A repo with no usable key never gets a signing-less
//! `SHA256SUMS`: those routes fail closed, and the package document falls back
//! to its legacy shape. See `docs/terraform-registry.md`.

use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::header::CONTENT_TYPE;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, put};
use axum::Extension;
use axum::Router;
use bytes::Bytes;
// The `sha2` digest types are now only referenced by the unit tests: the
// upload handlers stream the body and take their digests from the shared
// staging primitive (#2517), so gate this import to test builds to keep the
// production build free of unused-import warnings.
use futures::StreamExt;
#[cfg(test)]
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tracing::info;

use crate::api::handlers::proxy_helpers::{self, RepoInfo};
use crate::api::middleware::auth::{require_auth_basic_scope, AuthExtension};
use crate::api::validation::validate_outbound_url;
use crate::api::SharedState;
use crate::models::repository::{RepositoryFormat, RepositoryType};
use crate::services::signing_service::SigningService;

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

/// The path prefix [`router`] is mounted at (see `crate::api::routes`).
///
/// The absolute URLs this module advertises to clients (`download_url`,
/// `X-Terraform-Get`) must carry this prefix to resolve, so the mount point and
/// the advertised locations are both derived from this one constant.
pub const MOUNT_PREFIX: &str = "/terraform";

pub fn router() -> Router<SharedState> {
    Router::new()
        // Service discovery
        .route(
            "/:repo_key/.well-known/terraform.json",
            get(service_discovery),
        )
        // Module registry - search
        .route("/:repo_key/v1/modules/search", get(search_modules))
        // Module registry - list versions
        .route(
            "/:repo_key/v1/modules/:namespace/:name/:provider/versions",
            get(list_module_versions),
        )
        // Module registry - download (must be before latest to avoid clash)
        .route(
            "/:repo_key/v1/modules/:namespace/:name/:provider/:version/download",
            get(download_module),
        )
        // Module registry - the archive `download_module`'s `X-Terraform-Get`
        // header advertises. Must stay registered for that advertised location
        // to resolve (#2580 class).
        .route(
            "/:repo_key/v1/modules/:namespace/:name/:provider/:version/archive",
            get(download_module_archive),
        )
        // Module registry - latest version
        .route(
            "/:repo_key/v1/modules/:namespace/:name/:provider",
            get(latest_module_version),
        )
        // Module upload
        .route(
            "/:repo_key/v1/modules/:namespace/:name/:provider/:version",
            put(upload_module),
        )
        // Provider registry - list versions
        .route(
            "/:repo_key/v1/providers/:namespace/:type_name/versions",
            get(list_provider_versions),
        )
        // Provider registry - download (the JSON package document)
        .route(
            "/:repo_key/v1/providers/:namespace/:type_name/:version/download/:os/:arch",
            get(download_provider),
        )
        // Provider registry - the archive `download_provider`'s `download_url`
        // advertises. Must stay registered for that advertised location to
        // resolve (#2580 class).
        .route(
            "/:repo_key/v1/providers/:namespace/:type_name/:version/binary/:os/:arch",
            get(download_provider_binary),
        )
        // Provider registry - checksum list and its detached signature, the
        // locations `download_provider`'s `shasums_url` /
        // `shasums_signature_url` advertise (hosted repos only).
        .route(
            "/:repo_key/v1/providers/:namespace/:type_name/:version/SHA256SUMS",
            get(provider_shasums),
        )
        .route(
            "/:repo_key/v1/providers/:namespace/:type_name/:version/SHA256SUMS.sig",
            get(provider_shasums_signature),
        )
        // Provider upload
        .route(
            "/:repo_key/v1/providers/:namespace/:type_name/:version/:os/:arch",
            put(upload_provider),
        )
        // Provider Network Mirror Protocol (#1566).
        //
        // Configured by the client via `.terraformrc`/`.tofurc`:
        //   provider_installation {
        //     network_mirror { url = "https://host/terraform/<repo_key>/" }
        //   }
        // Terraform/OpenTofu then appends `<hostname>/<namespace>/<type>/...`
        // to that base, which lands on the routes below. Served for hosted
        // repos (from their own uploaded packages) and for remote repos (by
        // translating to the configured upstream registry).
        //
        // List available versions of a provider.
        .route(
            "/:repo_key/:hostname/:namespace/:type_name/index.json",
            get(mirror_index),
        )
        // List the installation packages for one version (e.g. `2.0.0.json`).
        .route(
            "/:repo_key/:hostname/:namespace/:type_name/:version_file",
            get(mirror_version),
        )
        // Stream the actual provider archive for a platform (referenced by the
        // `url` field that `mirror_version` emits).
        .route(
            "/:repo_key/:hostname/:namespace/:type_name/:version/download/:os/:arch",
            get(mirror_download),
        )
}

// ---------------------------------------------------------------------------
// Repository resolution
// ---------------------------------------------------------------------------

async fn resolve_terraform_repo(db: &PgPool, repo_key: &str) -> Result<RepoInfo, Response> {
    proxy_helpers::resolve_repo_by_key(db, repo_key, &["terraform"], "a Terraform").await
}

// ---------------------------------------------------------------------------
// Artifact coordinates
//
// The `artifacts.path` a module/provider is filed under at upload time is the
// same key every read path looks it up by, so both sides derive it from these
// helpers rather than re-formatting the string at each site.
// ---------------------------------------------------------------------------

/// `artifacts.path` for a module version.
fn build_module_artifact_path(
    namespace: &str,
    name: &str,
    provider: &str,
    version: &str,
) -> String {
    format!("{}/{}/{}/{}", namespace, name, provider, version)
}

/// `artifacts.path` for one provider package (a single os/arch build).
fn build_provider_artifact_path(
    namespace: &str,
    type_name: &str,
    version: &str,
    os: &str,
    arch: &str,
) -> String {
    format!(
        "{}/{}/{}/{}",
        namespace,
        type_name,
        version,
        build_platform(os, arch)
    )
}

/// The `<os>_<arch>` platform token Terraform names a package by.
fn build_platform(os: &str, arch: &str) -> String {
    format!("{}_{}", os, arch)
}

/// Build the service discovery JSON for a Terraform registry.
fn build_service_discovery_json(repo_key: &str) -> serde_json::Value {
    serde_json::json!({
        "modules.v1": format!("{}/{}/v1/modules/", MOUNT_PREFIX, repo_key),
        "providers.v1": format!("{}/{}/v1/providers/", MOUNT_PREFIX, repo_key),
    })
}

// ---------------------------------------------------------------------------
// GET /{repo_key}/.well-known/terraform.json — Service Discovery
// ---------------------------------------------------------------------------

async fn service_discovery(Path(repo_key): Path<String>) -> Result<Response, Response> {
    Ok(service_discovery_response(&repo_key))
}

fn service_discovery_response(repo_key: &str) -> Response {
    let json = build_service_discovery_json(repo_key);

    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&json).unwrap()))
        .unwrap()
}

// ---------------------------------------------------------------------------
// GET /.well-known/terraform.json — host-level Service Discovery
//
// Terraform/OpenTofu discover a registry per *host*: for the source address
// `artifacts.example.com/ns/type` the client fetches
// `https://artifacts.example.com/.well-known/terraform.json`, with no
// repository key anywhere in the request. The per-repo document above can only
// be reached by a client that already knows the repo key, so it cannot serve an
// origin-registry source address on its own.
//
// The host document therefore points at ONE operator-chosen repository
// (`TERRAFORM_DEFAULT_REPO`). Unset, the route answers 404, exactly as before
// this route existed. The route is mounted by `crate::api::routes`.
// ---------------------------------------------------------------------------

/// The response for an unconfigured or unusable default repo. One generic body
/// for every reason, so the anonymous route cannot be used to probe which
/// repository keys exist or what format they are.
fn host_discovery_not_configured() -> Response {
    (
        StatusCode::NOT_FOUND,
        "No default Terraform registry is configured on this host",
    )
        .into_response()
}

pub async fn host_service_discovery(
    State(state): State<SharedState>,
) -> Result<Response, Response> {
    let Some(repo_key) = state.config.terraform_default_repo.as_deref() else {
        return Err(host_discovery_not_configured());
    };

    // Advertise the repo only while it still resolves to a Terraform repo, so a
    // stale setting never points clients at a registry that does not exist.
    match resolve_terraform_repo(&state.db, repo_key).await {
        Ok(_) => Ok(service_discovery_response(repo_key)),
        Err(resp)
            if matches!(
                resp.status(),
                StatusCode::NOT_FOUND | StatusCode::BAD_REQUEST
            ) =>
        {
            Err(host_discovery_not_configured())
        }
        Err(resp) => Err(resp),
    }
}

// ---------------------------------------------------------------------------
// GET /v1/modules/{namespace}/{name}/{provider}/versions
// ---------------------------------------------------------------------------

async fn list_module_versions(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((repo_key, namespace, name, provider)): Path<(String, String, String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_terraform_repo(&state.db, &repo_key).await?;
    let module_name = build_module_name(&namespace, &name, &provider);
    let upstream_path = format!("v1/modules/{namespace}/{name}/{provider}/versions");

    // #4598: `terraform init` / `tofu init` list a module's versions before
    // they ask for `/download`, so a remote (its upstream's versions) and a
    // virtual (the union over the members the caller may read) must answer
    // here too, not only a hosted repository.
    let mut upstream_err: Option<Response> = None;
    let versions: Vec<String> = if repo.repo_type == RepositoryType::Virtual {
        let members =
            proxy_helpers::authorized_virtual_members(&state.db, auth.as_ref(), repo.id).await?;
        let mut all = std::collections::BTreeSet::new();
        for member in &members {
            if member.repo_type.is_hosted() {
                all.extend(hosted_module_versions(&state.db, member.id, &module_name).await?);
            } else if member.repo_type == RepositoryType::Remote {
                let info = proxy_helpers::repo_info_from_member(member);
                match remote_module_versions(&state, &info, &upstream_path).await {
                    Ok(v) => all.extend(v),
                    Err(resp) if resp.status() == StatusCode::NOT_FOUND => {}
                    Err(resp) => {
                        upstream_err.get_or_insert(resp);
                    }
                }
            }
        }
        all.into_iter().collect()
    } else if repo.repo_type == RepositoryType::Remote {
        match remote_module_versions(&state, &repo, &upstream_path).await {
            Ok(v) => v,
            Err(resp) if resp.status() == StatusCode::NOT_FOUND => Vec::new(),
            Err(resp) => return Err(resp),
        }
    } else {
        hosted_module_versions(&state.db, repo.id, &module_name).await?
    };

    if versions.is_empty() {
        if let Some(resp) = upstream_err {
            return Err(resp);
        }
        return Err((
            StatusCode::NOT_FOUND,
            format!("Module {} not found", module_name),
        )
            .into_response());
    }

    let json = build_version_list_json(&versions);

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&json).unwrap()))
        .unwrap())
}

/// The versions a hosted repository holds of a module.
async fn hosted_module_versions(
    db: &PgPool,
    repository_id: uuid::Uuid,
    module_name: &str,
) -> Result<Vec<String>, Response> {
    let versions: Vec<Option<String>> = sqlx::query_scalar!(
        r#"
        SELECT DISTINCT version
        FROM artifacts
        WHERE repository_id = $1
          AND name = $2
          AND is_deleted = false
          AND version IS NOT NULL
        ORDER BY version
        "#,
        repository_id,
        module_name
    )
    .fetch_all(db)
    .await
    .map_err(crate::api::handlers::db_err)?;
    Ok(versions.into_iter().flatten().collect())
}

/// The versions a remote repository's upstream registry lists for a module
/// (`{"modules":[{"versions":[{"version":"..."}]}]}`), through the proxy.
/// A remote without an upstream or proxy lists none.
async fn remote_module_versions(
    state: &SharedState,
    repo: &RepoInfo,
    upstream_path: &str,
) -> Result<Vec<String>, Response> {
    let (Some(upstream_url), Some(proxy)) =
        (repo.upstream_url.as_deref(), state.proxy_service.as_deref())
    else {
        return Ok(Vec::new());
    };
    let (content, _ct) = proxy_helpers::proxy_fetch_capped(
        proxy,
        repo.id,
        &repo.key,
        upstream_url,
        upstream_path,
        proxy_helpers::DEFAULT_METADATA_MAX_BYTES,
    )
    .await?;
    let value: serde_json::Value = serde_json::from_slice(&content).map_err(|e| {
        (
            StatusCode::BAD_GATEWAY,
            format!("Invalid upstream registry response: {}", e),
        )
            .into_response()
    })?;
    Ok(module_versions_from_registry(&value))
}

/// The version strings of a module registry `versions` document.
fn module_versions_from_registry(value: &serde_json::Value) -> Vec<String> {
    value
        .get("modules")
        .and_then(|m| m.as_array())
        .into_iter()
        .flatten()
        .filter_map(|m| m.get("versions").and_then(|v| v.as_array()))
        .flatten()
        .filter_map(|v| v.get("version").and_then(|v| v.as_str()))
        .map(str::to_string)
        .collect()
}

// ---------------------------------------------------------------------------
// GET /v1/modules/{namespace}/{name}/{provider}/{version}/download
// ---------------------------------------------------------------------------

async fn download_module(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((repo_key, namespace, name, provider, version)): Path<(
        String,
        String,
        String,
        String,
        String,
    )>,
    ctx: crate::api::middleware::download_telemetry::DownloadContext,
) -> Result<Response, Response> {
    let repo = resolve_terraform_repo(&state.db, &repo_key).await?;
    let module_name = build_module_name(&namespace, &name, &provider);
    let coords = ModuleCoords {
        namespace: &namespace,
        name: &name,
        provider: &provider,
        version: &version,
    };

    let artifact = sqlx::query!(
        r#"
        SELECT id, storage_key
        FROM artifacts
        WHERE repository_id = $1
          AND name = $2
          AND version = $3
          AND is_deleted = false
        LIMIT 1
        "#,
        repo.id,
        module_name,
        version,
    )
    .fetch_optional(&state.db)
    .await
    .map_err(crate::api::handlers::db_err)?
    .ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            format!(
                "Module {}/{}/{} version {} not found",
                namespace, name, provider, version
            ),
        )
            .into_response()
    });

    let artifact = match artifact {
        Ok(a) => a,
        Err(not_found) => {
            if repo.repo_type == RepositoryType::Remote {
                if let (Some(ref upstream_url), Some(ref proxy)) =
                    (&repo.upstream_url, &state.proxy_service)
                {
                    // #4590: answer with the protocol's own `204` +
                    // `X-Terraform-Get`, pointing at this server's `/archive`
                    // (which streams the upstream archive through the proxy
                    // cache) with the archive-type hint the client needs.
                    // This used to stream the upstream `/download` response
                    // body back as a `200`, which no client can use: a
                    // registry answers with an empty `204` whose location is
                    // in a header that was dropped.
                    let remote = RemoteModuleUpstream {
                        repo: &repo,
                        upstream_url,
                        proxy,
                    };
                    return remote_module_download(&remote, &coords).await;
                }
            }
            // Virtual repo (#4598): answer the way the resolving member does,
            // a `204` whose `X-Terraform-Get` points at this virtual's own
            // `/archive`. This used to stream the member's archive back as a
            // `200`, which no client can use.
            if repo.repo_type == RepositoryType::Virtual {
                return virtual_module_download(&state, auth.as_ref(), &repo, &coords, &ctx).await;
            }
            return Err(not_found);
        }
    };

    // Record download
    crate::services::artifact_service::record_download(&state.db, artifact.id, &ctx).await;

    // Return 204 with X-Terraform-Get header pointing to the archive download
    // URL served by `download_module_archive`, carrying the archive-type hint
    // go-getter needs to unpack it (#4590).
    let archive = hosted_module_archive_type(&state, &repo, artifact.id, &coords).await;
    let download_url = coords.archive_url(&repo_key, archive, None);

    Ok(Response::builder()
        .status(StatusCode::NO_CONTENT)
        .header("X-Terraform-Get", download_url)
        .body(Body::empty())
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /v1/modules/{namespace}/{name}/{provider}/{version}/archive
// ---------------------------------------------------------------------------

/// The location [`download_module`] advertises in `X-Terraform-Get`. Built here
/// (rather than inline) so the advertised URL and the registered route are
/// derived from one shared definition.
///
/// #4590: the URL always carries go-getter's `archive=<type>` hint. Terraform
/// and OpenTofu hand this location to go-getter, which only unpacks a plain
/// HTTP URL as an archive when the URL names the archive type (that query
/// parameter, or a file extension); without it go-getter fetches the URL as an
/// HTML page looking for a `terraform-get` meta tag and fails on the archive
/// bytes. `subdir` is go-getter's `//<subdir>` component, placed before the
/// query exactly as go-getter splits it back off.
fn build_module_archive_url(
    repo_key: &str,
    namespace: &str,
    name: &str,
    provider: &str,
    version: &str,
    archive: ModuleArchiveType,
    subdir: Option<&str>,
) -> String {
    let subdir = subdir
        .filter(|s| !s.is_empty())
        .map(|s| format!("//{s}"))
        .unwrap_or_default();
    format!(
        "{}/{}/v1/modules/{}/{}/{}/{}/archive{}?archive={}",
        MOUNT_PREFIX,
        repo_key,
        namespace,
        name,
        provider,
        version,
        subdir,
        archive.getter_hint()
    )
}

/// Stream a module's archive — the bytes `X-Terraform-Get` points a client at.
///
/// Hosted: the stored upload. Remote: the archive the upstream registry names,
/// fetched through the proxy cache (#4590). The `?archive=` hint on the
/// advertised URL is for the client's getter and is ignored here; the served
/// file's name and `Content-Type` follow the bytes themselves.
async fn download_module_archive(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((repo_key, namespace, name, provider, version)): Path<(
        String,
        String,
        String,
        String,
        String,
    )>,
    ctx: crate::api::middleware::download_telemetry::DownloadContext,
) -> Result<Response, Response> {
    let repo = resolve_terraform_repo(&state.db, &repo_key).await?;
    let coords = ModuleCoords {
        namespace: &namespace,
        name: &name,
        provider: &provider,
        version: &version,
    };

    if repo.repo_type == RepositoryType::Remote {
        if let (Some(ref upstream_url), Some(ref proxy)) =
            (&repo.upstream_url, &state.proxy_service)
        {
            let remote = RemoteModuleUpstream {
                repo: &repo,
                upstream_url,
                proxy,
            };
            return remote_module_archive(&state, &remote, &coords, &ctx).await;
        }
    }
    if repo.repo_type == RepositoryType::Virtual {
        return virtual_module_archive(&state, auth.as_ref(), &repo, &coords, &ctx).await;
    }

    let result = proxy_helpers::local_fetch_by_path(
        &state.db,
        &state,
        repo.id,
        &repo.storage_location(),
        &coords.artifact_path(),
    )
    .await?;

    // #3143: enforce quarantine + scan policy before streaming. `local_fetch_by_path`
    // applies the quarantine predicate only, so this route served artifacts that
    // `block_unscanned` / `block_on_fail` / `max_severity` should have blocked.
    proxy_helpers::gate_and_record_streamed_local(&state.db, result.artifact_id, &ctx).await?;

    serve_module_archive(result, &coords).await
}

// ---------------------------------------------------------------------------
// Module archive types (#4590)
// ---------------------------------------------------------------------------

/// A module version's registry coordinate, grouped so the archive helpers
/// below take one argument instead of four.
struct ModuleCoords<'a> {
    namespace: &'a str,
    name: &'a str,
    provider: &'a str,
    version: &'a str,
}

impl ModuleCoords<'_> {
    fn artifact_path(&self) -> String {
        build_module_artifact_path(self.namespace, self.name, self.provider, self.version)
    }

    /// The upstream registry's download endpoint for this version.
    fn upstream_download_path(&self) -> String {
        format!(
            "v1/modules/{}/{}/{}/{}/download",
            self.namespace, self.name, self.provider, self.version
        )
    }

    /// Proxy-cache path a remote module's archive is stored under: derived
    /// from the coordinate, never from the upstream archive URL, which may be
    /// absolute or signed (the #1998 lesson).
    fn archive_cache_path(&self) -> String {
        format!(
            "v1/modules/{}/{}/{}/{}/archive",
            self.namespace, self.name, self.provider, self.version
        )
    }

    fn archive_url(
        &self,
        repo_key: &str,
        archive: ModuleArchiveType,
        subdir: Option<&str>,
    ) -> String {
        build_module_archive_url(
            repo_key,
            self.namespace,
            self.name,
            self.provider,
            self.version,
            archive,
            subdir,
        )
    }

    /// Attachment filename for the served archive.
    fn filename(&self, archive: Option<ModuleArchiveType>) -> String {
        let stem = format!(
            "{}-{}-{}-{}",
            self.namespace, self.name, self.provider, self.version
        );
        match archive {
            Some(a) => format!("{stem}.{}", a.extension()),
            None => stem,
        }
    }
}

/// The archive formats a module archive is recognised as.
///
/// Detected from the bytes, never from the upload's name or `Content-Type`, so
/// the hint `X-Terraform-Get` advertises always matches what is served.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ModuleArchiveType {
    /// `PK\x03\x04` — a ZIP local file header.
    Zip,
    /// `\x1f\x8b` — gzip; a module tarball.
    TarGz,
    /// `ustar` at offset 257 — an uncompressed POSIX tar. Recognised so it can
    /// be named precisely, but neither Terraform nor OpenTofu can install one:
    /// their module getter registers no plain-`tar` decompressor, so
    /// `?archive=tar` falls back to the same HTML-page parse as no hint at all.
    /// New uploads are therefore refused (see [`classify_module_upload`]).
    Tar,
}

/// The type assumed for a stored module whose bytes cannot be read or are not
/// recognised: every module was labelled a gzip tarball before #4590, so this
/// keeps such an artifact exactly as it was advertised.
const LEGACY_MODULE_ARCHIVE_TYPE: ModuleArchiveType = ModuleArchiveType::TarGz;

/// `artifact_metadata.metadata` key the detected type is recorded under.
const MODULE_ARCHIVE_METADATA_KEY: &str = "archive_type";

/// Leading bytes needed to tell the types apart: a tar header's `ustar` magic
/// spans offsets 257..262.
const MODULE_ARCHIVE_SNIFF_LEN: usize = 262;

impl ModuleArchiveType {
    /// Identify an archive from its leading bytes (at least
    /// [`MODULE_ARCHIVE_SNIFF_LEN`] of them for a plain tar to be recognised).
    fn sniff(head: &[u8]) -> Option<Self> {
        if head.starts_with(b"PK\x03\x04") {
            Some(Self::Zip)
        } else if head.starts_with(&[0x1f, 0x8b]) {
            Some(Self::TarGz)
        } else if head.get(257..MODULE_ARCHIVE_SNIFF_LEN) == Some(&b"ustar"[..]) {
            Some(Self::Tar)
        } else {
            None
        }
    }

    /// go-getter's name for the type: the `archive=` query value.
    fn getter_hint(self) -> &'static str {
        match self {
            Self::Zip => "zip",
            Self::TarGz => "tar.gz",
            Self::Tar => "tar",
        }
    }

    /// File extension of the served archive.
    fn extension(self) -> &'static str {
        self.getter_hint()
    }

    fn content_type(self) -> &'static str {
        match self {
            Self::Zip => "application/zip",
            Self::TarGz => "application/gzip",
            Self::Tar => "application/x-tar",
        }
    }

    /// Parse a go-getter `archive=` value (also the recorded metadata value).
    fn from_getter_hint(hint: &str) -> Option<Self> {
        match hint.to_ascii_lowercase().as_str() {
            "zip" => Some(Self::Zip),
            "tar.gz" | "tgz" => Some(Self::TarGz),
            "tar" => Some(Self::Tar),
            _ => None,
        }
    }

    /// The type recorded in a module's `artifact_metadata` at upload.
    fn from_metadata(metadata: &serde_json::Value) -> Option<Self> {
        metadata
            .get(MODULE_ARCHIVE_METADATA_KEY)
            .and_then(|v| v.as_str())
            .and_then(Self::from_getter_hint)
    }
}

/// What a URL path's extension tells go-getter about the archive behind it.
#[derive(Debug, PartialEq, Eq)]
enum GetterExtension {
    /// An archive type this server serves and hints.
    Known(ModuleArchiveType),
    /// An archive go-getter unpacks that is not one of ours (`.tar.xz`,
    /// `.tar.bz2`, ...): left for the client's getter to handle itself.
    Foreign,
    /// No archive extension.
    None,
}

/// go-getter's own extension match, in its order (longest suffixes first).
fn getter_extension(path: &str) -> GetterExtension {
    let path = path.to_ascii_lowercase();
    for (ext, archive) in [
        (".tar.gz", Some(ModuleArchiveType::TarGz)),
        (".tgz", Some(ModuleArchiveType::TarGz)),
        (".zip", Some(ModuleArchiveType::Zip)),
        (".tar.bz2", None),
        (".tar.tbz2", None),
        (".tbz2", None),
        (".tar.xz", None),
        (".txz", None),
        (".tar.zst", None),
        (".tzst", None),
        (".bz2", None),
        (".gz", None),
        (".xz", None),
        (".zst", None),
    ] {
        if path.ends_with(ext) {
            return match archive {
                Some(a) => GetterExtension::Known(a),
                None => GetterExtension::Foreign,
            };
        }
    }
    GetterExtension::None
}

/// Decide whether an uploaded module archive is accepted, from its leading
/// bytes. ZIP and gzip-compressed tar are what `terraform init` / `tofu init`
/// can install; anything else is refused with the reason.
fn classify_module_upload(head: &[u8]) -> Result<ModuleArchiveType, &'static str> {
    match ModuleArchiveType::sniff(head) {
        Some(ModuleArchiveType::Tar) => Err(
            "Module archive is an uncompressed tar, which terraform/tofu cannot install \
             (their module getter has no plain-tar support); upload it gzip-compressed \
             (.tar.gz) or as a .zip",
        ),
        Some(archive) => Ok(archive),
        None => Err(
            "Module archive is not a ZIP or gzip-compressed tar (.tar.gz); \
             terraform/tofu modules must be uploaded in one of those formats",
        ),
    }
}

/// Read the leading bytes of a staged upload and classify it, mapping a
/// refusal to `400 Bad Request`.
#[allow(clippy::result_large_err)]
async fn sniff_staged_module_archive(
    path: &std::path::Path,
) -> Result<ModuleArchiveType, Response> {
    use tokio::io::AsyncReadExt;

    // #3718: the IO error text names the scratch path; keep it in the log.
    let read_failed = |e: std::io::Error| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            crate::api::handlers::internal_err_message("Failed to read staged module archive", &e),
        )
            .into_response()
    };
    let mut head = Vec::with_capacity(MODULE_ARCHIVE_SNIFF_LEN);
    tokio::fs::File::open(path)
        .await
        .map_err(read_failed)?
        .take(MODULE_ARCHIVE_SNIFF_LEN as u64)
        .read_to_end(&mut head)
        .await
        .map_err(read_failed)?;
    classify_module_upload(&head).map_err(|msg| (StatusCode::BAD_REQUEST, msg).into_response())
}

type ByteStream = futures::stream::BoxStream<'static, crate::error::Result<Bytes>>;

/// Read just enough of `body` to identify the archive, returning the type and
/// a stream that replays those bytes followed by the rest — so the caller can
/// still serve the whole body. A stream error is replayed in place, not
/// swallowed.
async fn peek_module_archive(mut body: ByteStream) -> (Option<ModuleArchiveType>, ByteStream) {
    let mut head = Vec::with_capacity(MODULE_ARCHIVE_SNIFF_LEN);
    let mut replay = Vec::new();
    let mut finished = false;
    while head.len() < MODULE_ARCHIVE_SNIFF_LEN {
        match body.next().await {
            Some(Ok(chunk)) => {
                head.extend_from_slice(&chunk);
                replay.push(Ok(chunk));
            }
            Some(Err(e)) => {
                replay.push(Err(e));
                finished = true;
                break;
            }
            None => {
                finished = true;
                break;
            }
        }
    }
    let rest = if finished {
        futures::stream::empty().boxed()
    } else {
        body
    };
    (
        ModuleArchiveType::sniff(&head),
        futures::stream::iter(replay).chain(rest).boxed(),
    )
}

/// Serve a module archive with the filename and `Content-Type` its bytes call
/// for (a stored module used to be named `.tar.gz` whatever it held).
async fn serve_module_archive(
    mut result: crate::services::proxy_service::StreamingFetchResult,
    coords: &ModuleCoords<'_>,
) -> Result<Response, Response> {
    let body = std::mem::replace(&mut result.body, futures::stream::empty().boxed());
    let (archive, body) = peek_module_archive(body).await;
    result.body = body;
    if let Some(a) = archive {
        result.content_type = Some(a.content_type().to_string());
    }
    proxy_helpers::stream_fetch_result(
        result,
        "application/octet-stream",
        Some(&coords.filename(archive)),
    )
}

/// The archive type of a hosted module version: the type recorded at upload,
/// or — for a module uploaded before #4590 recorded one — the type of its
/// stored bytes. Falls back to [`LEGACY_MODULE_ARCHIVE_TYPE`] when the bytes
/// cannot be read (e.g. a quarantined artifact, which `/archive` refuses
/// anyway) or are not recognised.
async fn hosted_module_archive_type(
    state: &SharedState,
    repo: &RepoInfo,
    artifact_id: uuid::Uuid,
    coords: &ModuleCoords<'_>,
) -> ModuleArchiveType {
    let recorded: Option<serde_json::Value> =
        sqlx::query_scalar("SELECT metadata FROM artifact_metadata WHERE artifact_id = $1")
            .bind(artifact_id)
            .fetch_optional(&state.db)
            .await
            .ok()
            .flatten();
    if let Some(archive) = recorded.as_ref().and_then(ModuleArchiveType::from_metadata) {
        return archive;
    }

    match proxy_helpers::local_fetch_by_path(
        &state.db,
        state,
        repo.id,
        &repo.storage_location(),
        &coords.artifact_path(),
    )
    .await
    {
        Ok(result) => peek_module_archive(result.body)
            .await
            .0
            .unwrap_or(LEGACY_MODULE_ARCHIVE_TYPE),
        Err(_) => LEGACY_MODULE_ARCHIVE_TYPE,
    }
}

// ---------------------------------------------------------------------------
// Remote modules (#4590)
// ---------------------------------------------------------------------------

/// A remote Terraform repository together with its upstream and proxy.
struct RemoteModuleUpstream<'a> {
    repo: &'a RepoInfo,
    upstream_url: &'a str,
    proxy: &'a crate::services::proxy_service::ProxyService,
}

/// Where an upstream registry says a module version's source lives.
#[derive(Debug, PartialEq, Eq)]
enum UpstreamModuleSource {
    /// A plain HTTP(S) URL this server fetches through its proxy cache and
    /// serves back under `/archive`.
    Http {
        /// The URL to fetch: absolute, with go-getter's `archive=` parameter
        /// removed (the client's getter strips it before fetching too).
        fetch_url: String,
        /// go-getter `//<subdir>` component, if any.
        subdir: Option<String>,
        /// The type the location names, if it names one.
        archive: Option<ModuleArchiveType>,
        /// The location as an absolute address, for handing to the client
        /// unchanged when the archive turns out not to be one we serve.
        absolute: String,
    },
    /// A source this server does not proxy — a forced getter (`git::`,
    /// `s3::`, ...), a non-HTTP scheme, or an archive format go-getter knows
    /// and we do not — handed to the client as an absolute address.
    Passthrough(String),
}

/// go-getter's `SourceDirSubdir`: split a `//<subdir>` component off a source
/// address (ignoring the scheme's own `//`), keeping any query on the source.
fn split_getter_subdir(src: &str) -> (String, Option<String>) {
    let stop = src.find('?').unwrap_or(src.len());
    let offset = src[..stop].find("://").map_or(0, |i| i + 3);
    let Some(idx) = src[offset..stop].find("//") else {
        return (src.to_string(), None);
    };
    let idx = idx + offset;
    let mut source = src[..idx].to_string();
    let mut subdir = src[idx + 2..].to_string();
    if let Some(q) = subdir.find('?') {
        source.push_str(&subdir[q..]);
        subdir.truncate(q);
    }
    (source, Some(subdir).filter(|s| !s.is_empty()))
}

/// Classify the location an upstream registry returned for a module version.
///
/// Mirrors the Terraform client: a location starting with `/`, `./` or `../`
/// is a URL relative to `base_url` (the URL that answered); anything else is a
/// go-getter source address taken as written (`git::...`, `github.com/...`,
/// an absolute URL).
fn classify_upstream_module_location(location: &str, base_url: &str) -> UpstreamModuleSource {
    let location = location.trim();
    let relative = ["/", "./", "../"].iter().any(|p| location.starts_with(p));
    let resolve = |source: &str| -> Option<reqwest::Url> {
        if relative {
            reqwest::Url::parse(base_url).ok()?.join(source).ok()
        } else {
            reqwest::Url::parse(source).ok()
        }
    };
    let absolute = resolve(location)
        .map(|u| u.to_string())
        .unwrap_or_else(|| location.to_string());

    // A forced getter (`git::https://...`) names its own protocol.
    if let Some(forced) = location.find("::") {
        if location.find("://").is_none_or(|scheme| forced < scheme) {
            return UpstreamModuleSource::Passthrough(location.to_string());
        }
    }

    let (source, subdir) = split_getter_subdir(location);
    let Some(mut url) = resolve(&source) else {
        return UpstreamModuleSource::Passthrough(absolute);
    };
    if !matches!(url.scheme(), "http" | "https") {
        return UpstreamModuleSource::Passthrough(absolute);
    }

    let mut hint = None;
    let kept: Vec<(String, String)> = url
        .query_pairs()
        .filter(|(k, v)| {
            if k == "archive" {
                hint = Some(v.to_string());
                false
            } else {
                true
            }
        })
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();

    let archive = match hint {
        Some(hint) => {
            // Only rewrite the query when there is a hint to drop, so a signed
            // URL's query string otherwise reaches upstream byte for byte.
            url.set_query(None);
            if !kept.is_empty() {
                url.query_pairs_mut().extend_pairs(kept);
            }
            match ModuleArchiveType::from_getter_hint(&hint) {
                Some(ModuleArchiveType::Tar) | None => {
                    return UpstreamModuleSource::Passthrough(absolute)
                }
                Some(archive) => Some(archive),
            }
        }
        None => match getter_extension(url.path()) {
            GetterExtension::Known(archive) => Some(archive),
            GetterExtension::Foreign => return UpstreamModuleSource::Passthrough(absolute),
            GetterExtension::None => None,
        },
    };

    UpstreamModuleSource::Http {
        fetch_url: url.to_string(),
        subdir,
        archive,
        absolute,
    }
}

/// Pull the module location out of an upstream registry's download answer:
/// the `X-Terraform-Get` header, else a `{"location": ...}` JSON body — the
/// Terraform client's own precedence.
fn upstream_module_location_value(header: Option<&str>, body: &[u8]) -> Option<String> {
    header
        .map(str::trim)
        .filter(|h| !h.is_empty())
        .map(str::to_string)
        .or_else(|| {
            serde_json::from_slice::<serde_json::Value>(body)
                .ok()?
                .get("location")?
                .as_str()
                .map(str::to_string)
        })
        .filter(|l| !l.is_empty())
}

/// Ask the upstream registry where a module version lives and classify it.
async fn resolve_upstream_module_source(
    remote: &RemoteModuleUpstream<'_>,
    coords: &ModuleCoords<'_>,
) -> Result<UpstreamModuleSource, Response> {
    let answer = proxy_helpers::proxy_fetch_terraform_module_location(
        remote.proxy,
        remote.repo.id,
        &remote.repo.key,
        remote.upstream_url,
        &coords.upstream_download_path(),
    )
    .await?;
    let location =
        upstream_module_location_value(answer.x_terraform_get.as_deref(), &answer.content)
            .ok_or_else(|| {
                (
                    StatusCode::BAD_GATEWAY,
                    "Upstream registry returned no module location",
                )
                    .into_response()
            })?;
    Ok(classify_upstream_module_location(
        &location,
        &answer.effective_url,
    ))
}

/// Whether two URLs share scheme, host and port.
fn same_origin(a: &str, b: &str) -> bool {
    match (reqwest::Url::parse(a), reqwest::Url::parse(b)) {
        (Ok(a), Ok(b)) => a.origin() == b.origin(),
        _ => false,
    }
}

/// Apply the outbound-URL (anti-SSRF) policy to an upstream-named archive URL
/// before fetching it. A URL on the configured upstream's own origin is as
/// trusted as the upstream itself and is exempt, so a registry on a private
/// network can still serve its archives from relative locations; any other
/// host is checked like the mirror's `download_url`.
#[allow(clippy::result_large_err)]
fn check_upstream_archive_url(
    remote: &RemoteModuleUpstream<'_>,
    fetch_url: &str,
) -> Result<(), Response> {
    if same_origin(fetch_url, remote.upstream_url) {
        return Ok(());
    }
    validate_outbound_url(fetch_url, "Terraform upstream module archive URL").map_err(|e| {
        // The URL is registry-controlled and may be signed; `e` names the
        // blocked host without echoing it.
        tracing::warn!(
            "SSRF check rejected upstream module archive URL for repo {}: {}",
            remote.repo.key,
            e
        );
        (
            StatusCode::BAD_GATEWAY,
            format!("Upstream registry returned a disallowed module location: {e}"),
        )
            .into_response()
    })
}

/// Fetch an upstream module archive through the proxy cache.
async fn fetch_upstream_module_archive(
    remote: &RemoteModuleUpstream<'_>,
    coords: &ModuleCoords<'_>,
    fetch_url: &str,
) -> Result<crate::services::proxy_service::StreamingFetchResult, Response> {
    check_upstream_archive_url(remote, fetch_url)?;
    proxy_helpers::proxy_fetch_streaming_with_cache_key(
        remote.proxy,
        remote.repo.id,
        &remote.repo.key,
        remote.upstream_url,
        fetch_url,
        &coords.archive_cache_path(),
        RepositoryFormat::Terraform,
    )
    .await
}

/// Identify an upstream archive whose location names no type by reading its
/// bytes. The archive is read to the end, through the proxy cache, so the
/// client's `/archive` request that follows is served from the cache rather
/// than abandoning a half-written cache entry here. Any failure is `None`:
/// the caller then hands the client the upstream location unchanged.
async fn sniff_upstream_module_archive(
    remote: &RemoteModuleUpstream<'_>,
    coords: &ModuleCoords<'_>,
    fetch_url: &str,
) -> Option<ModuleArchiveType> {
    let result = fetch_upstream_module_archive(remote, coords, fetch_url)
        .await
        .ok()?;
    let (archive, mut body) = peek_module_archive(result.body).await;
    while let Some(chunk) = body.next().await {
        chunk.ok()?;
    }
    archive
}

/// `GET .../download` on a remote repository: the `204` + `X-Terraform-Get`
/// answer, pointing at this server's `/archive` with the archive hint when the
/// upstream archive is one we serve, or at the upstream's own location when
/// it is not.
async fn remote_module_download(
    remote: &RemoteModuleUpstream<'_>,
    coords: &ModuleCoords<'_>,
) -> Result<Response, Response> {
    let location = remote_module_location(remote, coords, &remote.repo.key).await?;
    Ok(module_location_response(location))
}

/// The `204` + `X-Terraform-Get` answer to a module `/download`.
fn module_location_response(location: String) -> Response {
    Response::builder()
        .status(StatusCode::NO_CONTENT)
        .header("X-Terraform-Get", location)
        .body(Body::empty())
        .unwrap()
}

/// Where a remote's module version is to be fetched from: `advertise_key`'s
/// own `/archive` with the archive hint when the upstream archive is one we
/// serve, or the upstream's own location when it is not. `advertise_key` is
/// the remote itself, or the virtual a client reached it through (#4598).
async fn remote_module_location(
    remote: &RemoteModuleUpstream<'_>,
    coords: &ModuleCoords<'_>,
    advertise_key: &str,
) -> Result<String, Response> {
    let location = match resolve_upstream_module_source(remote, coords).await? {
        UpstreamModuleSource::Passthrough(location) => location,
        UpstreamModuleSource::Http {
            fetch_url,
            subdir,
            archive,
            absolute,
        } => {
            let archive = match archive {
                Some(archive) => Some(archive),
                None => sniff_upstream_module_archive(remote, coords, &fetch_url).await,
            };
            match archive {
                Some(archive) if archive != ModuleArchiveType::Tar => {
                    coords.archive_url(advertise_key, archive, subdir.as_deref())
                }
                _ => absolute,
            }
        }
    };
    Ok(location)
}

/// `GET .../archive` on a remote repository: stream the upstream archive
/// through the proxy cache.
async fn remote_module_archive(
    state: &SharedState,
    remote: &RemoteModuleUpstream<'_>,
    coords: &ModuleCoords<'_>,
    ctx: &crate::api::middleware::download_telemetry::DownloadContext,
) -> Result<Response, Response> {
    let UpstreamModuleSource::Http { fetch_url, .. } =
        resolve_upstream_module_source(remote, coords).await?
    else {
        return Err((
            StatusCode::NOT_FOUND,
            "The upstream registry serves this module from a source this \
             repository does not proxy; use the location its download endpoint returns",
        )
            .into_response());
    };
    let result = fetch_upstream_module_archive(remote, coords, &fetch_url).await?;
    // #3649: count the proxied serve, keyed on the cache path it commits under.
    proxy_helpers::record_proxy_download(
        state,
        remote.repo.id,
        &remote.repo.key,
        &coords.archive_cache_path(),
        ctx,
    )
    .await;
    serve_module_archive(result, coords).await
}

// ---------------------------------------------------------------------------
// Virtual modules (#4598)
// ---------------------------------------------------------------------------

/// A hosted repository's artifact id for a module version, if it holds one.
async fn hosted_module_artifact_id(
    db: &PgPool,
    repository_id: uuid::Uuid,
    coords: &ModuleCoords<'_>,
) -> Result<Option<uuid::Uuid>, Response> {
    sqlx::query_scalar(
        r#"
        SELECT id
        FROM artifacts
        WHERE repository_id = $1
          AND name = $2
          AND version = $3
          AND is_deleted = false
        LIMIT 1
        "#,
    )
    .bind(repository_id)
    .bind(build_module_name(
        coords.namespace,
        coords.name,
        coords.provider,
    ))
    .bind(coords.version)
    .fetch_optional(db)
    .await
    .map_err(crate::api::handlers::db_err)
}

/// The `404` a virtual answers when no member holds the module version. The
/// member walks below move past a member's `404`, keep its first other
/// failure, and surface that failure instead of this one, so an upstream
/// outage is not reported as "not found".
fn virtual_module_not_found(coords: &ModuleCoords<'_>) -> Response {
    (
        StatusCode::NOT_FOUND,
        format!(
            "Module {}/{}/{} version {} not found",
            coords.namespace, coords.name, coords.provider, coords.version
        ),
    )
        .into_response()
}

/// `GET .../download` on a virtual repository (#4598): resolve the member in
/// priority order and answer as that member would, a `204` whose
/// `X-Terraform-Get` points at this virtual's own `/archive` with the
/// member's archive hint. A remote member's source this server does not
/// proxy (`git::`, `s3::`, ...) is handed through unchanged, as by the remote
/// itself.
async fn virtual_module_download(
    state: &SharedState,
    auth: Option<&AuthExtension>,
    repo: &RepoInfo,
    coords: &ModuleCoords<'_>,
    ctx: &crate::api::middleware::download_telemetry::DownloadContext,
) -> Result<Response, Response> {
    let members = proxy_helpers::authorized_virtual_members(&state.db, auth, repo.id).await?;
    let mut upstream_err: Option<Response> = None;
    for member in &members {
        let info = proxy_helpers::repo_info_from_member(member);
        if member.repo_type.is_hosted() {
            let Some(artifact_id) = hosted_module_artifact_id(&state.db, member.id, coords).await?
            else {
                continue;
            };
            crate::services::artifact_service::record_download(&state.db, artifact_id, ctx).await;
            let archive = hosted_module_archive_type(state, &info, artifact_id, coords).await;
            return Ok(module_location_response(
                coords.archive_url(&repo.key, archive, None),
            ));
        }
        if member.repo_type != RepositoryType::Remote {
            continue;
        }
        let (Some(upstream_url), Some(proxy)) =
            (info.upstream_url.as_deref(), state.proxy_service.as_deref())
        else {
            continue;
        };
        let remote = RemoteModuleUpstream {
            repo: &info,
            upstream_url,
            proxy,
        };
        match remote_module_location(&remote, coords, &repo.key).await {
            Ok(location) => return Ok(module_location_response(location)),
            Err(resp) if resp.status() == StatusCode::NOT_FOUND => {}
            Err(resp) => {
                upstream_err.get_or_insert(resp);
            }
        }
    }
    Err(upstream_err.unwrap_or_else(|| virtual_module_not_found(coords)))
}

/// `GET .../archive` on a virtual repository (#4598): the archive
/// [`virtual_module_download`] advertised, from the same member, found by the
/// same priority walk: a hosted member's stored bytes (quarantine and scan
/// policy enforced), or a remote member's upstream archive through its proxy
/// cache.
async fn virtual_module_archive(
    state: &SharedState,
    auth: Option<&AuthExtension>,
    repo: &RepoInfo,
    coords: &ModuleCoords<'_>,
    ctx: &crate::api::middleware::download_telemetry::DownloadContext,
) -> Result<Response, Response> {
    let members = proxy_helpers::authorized_virtual_members(&state.db, auth, repo.id).await?;
    let mut upstream_err: Option<Response> = None;
    for member in &members {
        let info = proxy_helpers::repo_info_from_member(member);
        if member.repo_type.is_hosted() {
            let result = match proxy_helpers::local_fetch_by_path(
                &state.db,
                state,
                member.id,
                &info.storage_location(),
                &coords.artifact_path(),
            )
            .await
            {
                Ok(result) => result,
                Err(resp) if resp.status() == StatusCode::NOT_FOUND => continue,
                Err(resp) => return Err(resp),
            };
            proxy_helpers::gate_and_record_streamed_local(&state.db, result.artifact_id, ctx)
                .await?;
            return serve_module_archive(result, coords).await;
        }
        if member.repo_type != RepositoryType::Remote {
            continue;
        }
        let (Some(upstream_url), Some(proxy)) =
            (info.upstream_url.as_deref(), state.proxy_service.as_deref())
        else {
            continue;
        };
        let remote = RemoteModuleUpstream {
            repo: &info,
            upstream_url,
            proxy,
        };
        match remote_module_archive(state, &remote, coords, ctx).await {
            Ok(response) => return Ok(response),
            Err(resp) if resp.status() == StatusCode::NOT_FOUND => {}
            Err(resp) => {
                upstream_err.get_or_insert(resp);
            }
        }
    }
    Err(upstream_err.unwrap_or_else(|| virtual_module_not_found(coords)))
}

// ---------------------------------------------------------------------------
// GET /v1/modules/{namespace}/{name}/{provider} — Latest version
// ---------------------------------------------------------------------------

async fn latest_module_version(
    State(state): State<SharedState>,
    Path((repo_key, namespace, name, provider)): Path<(String, String, String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_terraform_repo(&state.db, &repo_key).await?;
    let module_name = build_module_name(&namespace, &name, &provider);

    let artifact = sqlx::query!(
        r#"
        SELECT version, created_at
        FROM artifacts
        WHERE repository_id = $1
          AND name = $2
          AND is_deleted = false
          AND version IS NOT NULL
        ORDER BY created_at DESC
        LIMIT 1
        "#,
        repo.id,
        module_name
    )
    .fetch_optional(&state.db)
    .await
    .map_err(crate::api::handlers::db_err)?
    .ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            format!("No versions found for module {}", module_name),
        )
            .into_response()
    })?;

    let version = artifact.version.unwrap_or_default();

    let json = serde_json::json!({
        "id": format!("{}/{}/{}/{}", namespace, name, provider, version),
        "owner": "",
        "namespace": namespace,
        "name": name,
        "version": version,
        "provider": provider,
        "description": "",
        "source": "",
        "published_at": artifact.created_at.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        "downloads": 0,
        "verified": false,
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&json).unwrap()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /v1/modules/search?q=query — Search modules
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
struct SearchQuery {
    q: Option<String>,
    #[serde(default = "default_offset")]
    offset: i64,
    #[serde(default = "default_limit")]
    limit: i64,
}

fn default_offset() -> i64 {
    0
}

fn default_limit() -> i64 {
    10
}

async fn search_modules(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
    Query(params): Query<SearchQuery>,
) -> Result<Response, Response> {
    let repo = resolve_terraform_repo(&state.db, &repo_key).await?;
    let query = params.q.unwrap_or_default();
    let search_pattern = build_search_pattern(&query);

    let modules = sqlx::query!(
        r#"
        SELECT DISTINCT name, version, created_at
        FROM artifacts
        WHERE repository_id = $1
          AND is_deleted = false
          AND name ILIKE $2 ESCAPE '\'
          AND version IS NOT NULL
        ORDER BY created_at DESC
        LIMIT $3 OFFSET $4
        "#,
        repo.id,
        search_pattern,
        params.limit,
        params.offset,
    )
    .fetch_all(&state.db)
    .await
    .map_err(crate::api::handlers::db_err)?;

    let module_list: Vec<serde_json::Value> = modules
        .iter()
        .map(|m| {
            let (namespace, name, provider) = parse_module_name(&m.name);
            let version = m.version.clone().unwrap_or_default();
            serde_json::json!({
                "id": format!("{}/{}", m.name, version),
                "namespace": namespace,
                "name": name,
                "provider": provider,
                "version": version,
                "description": "",
                "published_at": m.created_at.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            })
        })
        .collect();

    let json = serde_json::json!({
        "meta": {
            "limit": params.limit,
            "current_offset": params.offset,
        },
        "modules": module_list,
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&json).unwrap()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// PUT /v1/modules/{namespace}/{name}/{provider}/{version} — Upload module
// ---------------------------------------------------------------------------

async fn upload_module(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((repo_key, namespace, name, provider, version)): Path<(
        String,
        String,
        String,
        String,
        String,
    )>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, Response> {
    // GHSA-vvc3-h39c-mrq5: enforce token scope before processing.
    let user_id = require_auth_basic_scope(auth, "terraform", "write:artifacts")?.user_id;
    let repo = resolve_terraform_repo(&state.db, &repo_key).await?;
    proxy_helpers::reject_write_if_not_hosted(&repo.repo_type)?;
    repo.reject_if_promotion_only(false)?;
    let module_name = build_module_name(&namespace, &name, &provider);

    // Check for duplicate
    let existing = sqlx::query_scalar!(
        "SELECT id FROM artifacts WHERE repository_id = $1 AND name = $2 AND version = $3 AND is_deleted = false",
        repo.id,
        module_name,
        version
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        crate::api::handlers::db_err(e)
    })?;

    if existing.is_some() {
        return Err((
            StatusCode::CONFLICT,
            format!("Module {} version {} already exists", module_name, version),
        )
            .into_response());
    }

    // Stream the request body to a bounded scratch file, computing the content
    // digests in one pass — never buffering the module archive in memory
    // (#2517). The stager enforces `max_upload_size_bytes` mid-stream.
    let (staged, digests) =
        proxy_helpers::stage_stream_content_addressed(&state, body.into_data_stream()).await?;
    let checksum = digests.sha256.clone();
    let size_bytes = staged.size_bytes();

    // #4590: the archive type decides the hint `X-Terraform-Get` advertises,
    // so it is detected from the bytes now and recorded with the artifact.
    let archive = sniff_staged_module_archive(staged.path()).await?;

    let artifact_path = build_module_artifact_path(&namespace, &name, &provider, &version);
    let storage_key = build_module_storage_key(&namespace, &name, &provider, &version);

    // GHSA-vcq6-8hxw-4q67: URL segments are spliced into the path verbatim;
    // reject traversal at ingest.
    crate::services::upload_service::validate_artifact_path(&artifact_path)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()).into_response())?;

    super::cleanup_soft_deleted_artifact(&state.db, repo.id, &artifact_path).await;

    // Store the file, streamed from the staged scratch file.
    // `put_artifact_stream` runs the cross-repo write guard (#2584) before
    // writing, then streams the object to storage.
    proxy_helpers::put_artifact_stream(&state, &repo, &storage_key, staged).await?;

    // Insert artifact record
    let mut tx = super::publish_quota::begin_admitted_publish(
        &state.db,
        repo.id,
        &artifact_path,
        size_bytes,
    )
    .await?;
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
        module_name,
        version,
        size_bytes,
        checksum,
        archive.content_type(),
        storage_key,
        user_id,
    )
    .fetch_one(&mut *tx)
    .await
    .map_err(crate::api::handlers::db_err)?;
    tx.commit().await.map_err(crate::api::handlers::db_err)?;

    crate::services::quarantine_service::apply_upload_hold_hosted(&state.db, repo.id, artifact_id)
        .await;
    crate::services::scanner_service::trigger_scan_on_upload(
        &state.db,
        state.scanner_service.clone(),
        repo.id,
        artifact_id,
    )
    .await;

    // Store metadata
    let metadata = build_module_metadata(&namespace, &name, &provider, &version, archive);

    let _ = sqlx::query!(
        r#"
        INSERT INTO artifact_metadata (artifact_id, format, metadata)
        VALUES ($1, 'terraform', $2)
        ON CONFLICT (artifact_id) DO UPDATE SET metadata = $2
        "#,
        artifact_id,
        metadata,
    )
    .execute(&state.db)
    .await;

    // Update repository timestamp
    let _ = sqlx::query!(
        "UPDATE repositories SET updated_at = NOW() WHERE id = $1",
        repo.id,
    )
    .execute(&state.db)
    .await;

    // Surface the module on the Packages page (#3659), keyed on the registry
    // coordinate `namespace/name/provider` and the version.
    crate::services::package_service::register_published_package(
        &state.db,
        &state.event_bus,
        repo.id,
        "terraform",
        &module_name,
        &version,
        size_bytes,
        &checksum,
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
        "Terraform module upload: {}/{}/{} v{} to repo {}",
        namespace, name, provider, version, repo_key
    );

    Ok(Response::builder()
        .status(StatusCode::CREATED)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::to_string(&serde_json::json!({
                "id": format!("{}/{}/{}/{}", namespace, name, provider, version),
                "namespace": namespace,
                "name": name,
                "provider": provider,
                "version": version,
                "checksum": checksum,
            }))
            .unwrap(),
        ))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /v1/providers/{namespace}/{type}/versions
// ---------------------------------------------------------------------------

async fn list_provider_versions(
    State(state): State<SharedState>,
    Path((repo_key, namespace, type_name)): Path<(String, String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_terraform_repo(&state.db, &repo_key).await?;
    let provider_name = build_provider_name(&namespace, &type_name);

    // Get all stored packages with the inputs platform recovery needs.
    //
    // Held packages are excluded (#2662): the download surface refuses them via
    // `check_quarantine_row`, so listing them would advertise a version (and,
    // downstream, its `zh:` hash) the download routes then 409/403. The
    // predicate mirrors `quarantine_service::check_download_allowed`: a
    // `quarantined` row becomes listable again once its hold window expires.
    let artifacts = sqlx::query!(
        r#"
        SELECT DISTINCT a.version, a.path, am.metadata as "metadata?"
        FROM artifacts a
        LEFT JOIN artifact_metadata am ON am.artifact_id = a.id
        WHERE a.repository_id = $1
          AND a.name = $2
          AND a.is_deleted = false
          AND a.version IS NOT NULL
          AND (
            a.quarantine_status IS NULL
            OR a.quarantine_status NOT IN ('quarantined', 'rejected')
            OR (
              a.quarantine_status = 'quarantined'
              AND a.quarantine_until IS NOT NULL
              AND a.quarantine_until <= NOW()
            )
          )
        ORDER BY a.version
        "#,
        repo.id,
        provider_name,
    )
    .fetch_all(&state.db)
    .await
    .map_err(crate::api::handlers::db_err)?;

    let rows: Vec<(String, Option<serde_json::Value>, String)> = artifacts
        .into_iter()
        .filter_map(|a| Some((a.version?, a.metadata, a.path)))
        .collect();

    let versions = provider_versions_from_rows(&rows);

    if versions.is_empty() {
        return Err((
            StatusCode::NOT_FOUND,
            format!("Provider {} not found", provider_name),
        )
            .into_response());
    }

    let json = serde_json::json!({
        "versions": versions,
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&json).unwrap()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /v1/providers/{namespace}/{type}/{version}/download/{os}/{arch}
// ---------------------------------------------------------------------------

async fn download_provider(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((repo_key, namespace, type_name, version, os, arch)): Path<(
        String,
        String,
        String,
        String,
        String,
        String,
    )>,
    ctx: crate::api::middleware::download_telemetry::DownloadContext,
) -> Result<Response, Response> {
    let repo = resolve_terraform_repo(&state.db, &repo_key).await?;
    let provider_name = build_provider_name(&namespace, &type_name);
    let platform = build_platform(&os, &arch);
    // Resolve the package by the exact `artifacts.path` it is stored under —
    // the same coordinates the `binary` route this document advertises resolves
    // by, so a document can only be produced for a package that route can serve.
    let artifact_path = build_provider_artifact_path(&namespace, &type_name, &version, &os, &arch);

    let artifact = sqlx::query!(
        r#"
        SELECT id, storage_key, size_bytes, checksum_sha256, path
        FROM artifacts
        WHERE repository_id = $1
          AND name = $2
          AND version = $3
          AND path = $4
          AND is_deleted = false
        LIMIT 1
        "#,
        repo.id,
        provider_name,
        version,
        artifact_path,
    )
    .fetch_optional(&state.db)
    .await
    .map_err(crate::api::handlers::db_err)?
    .ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            format!(
                "Provider {}/{} version {} for {}/{} not found",
                namespace, type_name, version, os, arch
            ),
        )
            .into_response()
    });

    let artifact = match artifact {
        Ok(a) => a,
        Err(not_found) => {
            if repo.repo_type == RepositoryType::Remote {
                if let (Some(ref upstream_url), Some(ref proxy)) =
                    (&repo.upstream_url, &state.proxy_service)
                {
                    let upstream_path = format!(
                        "v1/providers/{}/{}/{}/download/{}/{}",
                        namespace, type_name, version, os, arch
                    );
                    // #1608 Phase 4: stream the terraform provider archive
                    // (.zip) to the client while teeing to the proxy cache,
                    // instead of buffering the whole provider in memory.
                    // Single-flight via the merged coordinator (#1609).
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
                let upstream_path = format!(
                    "v1/providers/{}/{}/{}/download/{}/{}",
                    namespace, type_name, version, os, arch
                );
                let vname = provider_name.clone();
                let vversion = version.clone();
                let result = proxy_helpers::resolve_virtual_download(
                    &state.db,
                    auth.as_ref(),
                    state.proxy_service.as_deref(),
                    repo.id,
                    &upstream_path,
                    Some(&ctx),
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

    // Record download
    crate::services::artifact_service::record_download(&state.db, artifact.id, &ctx).await;

    let filename = build_provider_filename(&type_name, &version, &platform);

    // Per the Provider Registry Protocol this endpoint returns the package
    // *document*, not the package: `download_url` points at the separate route
    // that streams the archive (`download_provider_binary`).
    let binary_path =
        build_provider_binary_url(&repo_key, &namespace, &type_name, &version, &os, &arch);

    // Protocols the uploader declared (or the manifest in the archive did); a
    // package stored before this was recorded keeps the legacy default.
    let metadata: Option<serde_json::Value> =
        sqlx::query_scalar("SELECT metadata FROM artifact_metadata WHERE artifact_id = $1")
            .bind(artifact.id)
            .fetch_optional(&state.db)
            .await
            .map_err(crate::api::handlers::db_err)?;
    let protocols = provider_protocols_from_metadata(metadata.as_ref());

    // Only a hosted repo can vouch for its packages: it holds the bytes the
    // checksum list is computed from. A repo with no usable OpenPGP key keeps
    // the legacy, unsigned package document (see the module docs).
    let mut signing = if classify_mirror_repo(&repo.repo_type, false, false) == MirrorGuard::Local {
        active_openpgp_key(&state, repo.id)
            .await?
            .map(|key| provider_signing_doc(&key, &repo_key, &namespace, &type_name, &version))
    } else {
        None
    };

    // Terraform/OpenTofu fetch `download_url`, `shasums_url` and
    // `shasums_signature_url` without the registry credentials they sent for
    // this document, so a private repo would answer each with 401. As for the
    // mirror archives (#3588), an authenticated caller gets single-use tickets
    // bound to each exact path; an anonymous caller (public repo) gets the
    // plain paths it can already reach.
    let download_url = ticketed_path(
        mint_path_ticket(
            &state,
            auth.as_ref(),
            &binary_path,
            "terraform-provider-archive",
        )
        .await,
        binary_path,
    );
    if let Some(doc) = signing.as_mut() {
        let shasums_path = std::mem::take(&mut doc.shasums_url);
        let signature_path = std::mem::take(&mut doc.shasums_signature_url);
        doc.shasums_url = ticketed_path(
            mint_path_ticket(
                &state,
                auth.as_ref(),
                &shasums_path,
                "terraform-provider-shasums",
            )
            .await,
            shasums_path,
        );
        doc.shasums_signature_url = ticketed_path(
            mint_path_ticket(
                &state,
                auth.as_ref(),
                &signature_path,
                "terraform-provider-shasums-sig",
            )
            .await,
            signature_path,
        );
    }

    let json = build_provider_download_json(
        &os,
        &arch,
        &filename,
        &download_url,
        &artifact.checksum_sha256,
        &protocols,
        signing.as_ref(),
    );

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&json).unwrap()))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /v1/providers/{namespace}/{type}/{version}/SHA256SUMS[.sig]
//
// The signed checksum list an origin registry must publish. Hosted repos only,
// computed from the stored packages on every request (no stored copy to go
// stale, nothing to backfill for packages uploaded before these routes), and
// signed with the repository's active OpenPGP key.
// ---------------------------------------------------------------------------

/// The repo's active signing key if it can sign OpenPGP; `None` when the repo
/// has no active key or the key is not a `gpg` one. A lookup failure is an
/// (already stabilised, #3667) error response, never a silent downgrade.
async fn active_openpgp_key(
    state: &SharedState,
    repo_id: uuid::Uuid,
) -> Result<Option<crate::models::signing_key::SigningKey>, Response> {
    let svc = SigningService::new(state.db.clone(), &state.config.jwt_secret);
    match svc.get_active_key_for_repo(repo_id).await {
        Ok(key) => Ok(key.filter(|k| k.supports_openpgp())),
        Err(e) => {
            tracing::error!(error = %e, "Failed to load repository signing key");
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to load signing key",
            )
                .into_response())
        }
    }
}

/// Everything both checksum routes need: the key that signs and the exact
/// document that is signed. Fails closed — no key, no document.
async fn load_provider_shasums(
    state: &SharedState,
    repo_key: &str,
    namespace: &str,
    type_name: &str,
    version: &str,
) -> Result<(crate::models::signing_key::SigningKey, String), Response> {
    let repo = resolve_terraform_repo(&state.db, repo_key).await?;
    if classify_mirror_repo(&repo.repo_type, false, false) != MirrorGuard::Local {
        return Err((
            StatusCode::NOT_FOUND,
            "Provider checksums are only published by hosted Terraform repositories",
        )
            .into_response());
    }

    let svc = SigningService::new(state.db.clone(), &state.config.jwt_secret);
    let key = crate::api::handlers::error_helpers::require_signing_key(
        svc.get_active_key_for_repo(repo.id).await,
    )?;
    let key = crate::api::handlers::error_helpers::require_openpgp_capable_key(key)?;

    let packages = local_provider_packages(&state.db, &repo, namespace, type_name, version).await?;
    if packages.is_empty() {
        return Err((StatusCode::NOT_FOUND, "Provider version not found").into_response());
    }
    Ok((key, build_provider_shasums(type_name, version, &packages)))
}

async fn provider_shasums(
    State(state): State<SharedState>,
    Path((repo_key, namespace, type_name, version)): Path<(String, String, String, String)>,
) -> Result<Response, Response> {
    let (_key, shasums) =
        load_provider_shasums(&state, &repo_key, &namespace, &type_name, &version).await?;
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Body::from(shasums))
        .unwrap())
}

/// How long a `SHA256SUMS.sig` is reused. Far below the minimum signature
/// expiry the signing service allows (`MIN_SIGNATURE_EXPIRY_SECONDS`), so a
/// cached signature is never served stale.
const SHASUMS_SIGNATURE_TTL: std::time::Duration = std::time::Duration::from_secs(5 * 60);

/// Binary `SHA256SUMS.sig` per (signing key id, SHA-256 of the signed
/// `SHA256SUMS`). `try_get_with` single-flights a miss; a failed signing is
/// never cached. Per replica: each replica signs at most once per entry.
static SHASUMS_SIGNATURE_CACHE: once_cell::sync::Lazy<
    moka::future::Cache<(uuid::Uuid, [u8; 32]), Bytes>,
> = once_cell::sync::Lazy::new(|| {
    moka::future::Cache::builder()
        .max_capacity(10_000)
        .time_to_live(SHASUMS_SIGNATURE_TTL)
        .build()
});

/// Convert an ASCII-armored detached signature into the binary OpenPGP packet
/// stream. Terraform/OpenTofu read `SHA256SUMS.sig` as raw packets (the same
/// bytes `gpg --detach-sign` writes without `--armor`) and reject armor.
fn dearmor_signature(armored: &str) -> crate::error::Result<Vec<u8>> {
    use pgp::composed::{Deserializable, StandaloneSignature};
    use pgp::ser::Serialize;
    let (signature, _) = StandaloneSignature::from_string(armored)
        .map_err(|e| crate::error::AppError::Internal(format!("Invalid signature armor: {e}")))?;
    signature.to_bytes().map_err(|e| {
        crate::error::AppError::Internal(format!("Failed to serialize signature: {e}"))
    })
}

async fn provider_shasums_signature(
    State(state): State<SharedState>,
    Path((repo_key, namespace, type_name, version)): Path<(String, String, String, String)>,
) -> Result<Response, Response> {
    let (key, shasums) =
        load_provider_shasums(&state, &repo_key, &namespace, &type_name, &version).await?;

    // The signature carries the configured signature expiry, like every other
    // detached signature the signing service makes. Signing decrypts the
    // private key, so a signature is reused for a short while per
    // (key, SHA256SUMS digest); a key rotation or a changed package set is a
    // different cache key and is signed afresh.
    let digest: [u8; 32] = <sha2::Sha256 as sha2::Digest>::digest(shasums.as_bytes()).into();
    let signature = SHASUMS_SIGNATURE_CACHE
        .try_get_with((key.id, digest), async {
            let svc = SigningService::new(state.db.clone(), &state.config.jwt_secret);
            let armored = svc
                .sign_openpgp_detached_with_key(&key, shasums.as_bytes())
                .await?;
            let _ = svc.mark_key_used(key.id).await;
            dearmor_signature(&armored).map(Bytes::from)
        })
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                crate::api::handlers::internal_err_message("Failed to sign provider checksums", &e),
            )
                .into_response()
        })?;

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/pgp-signature")
        .body(Body::from(signature))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /v1/providers/{namespace}/{type}/{version}/binary/{os}/{arch}
// ---------------------------------------------------------------------------

/// The location [`download_provider`] advertises as `download_url`. Built here
/// (rather than inline) so the advertised URL and the registered route are
/// derived from one shared definition.
fn build_provider_binary_url(
    repo_key: &str,
    namespace: &str,
    type_name: &str,
    version: &str,
    os: &str,
    arch: &str,
) -> String {
    format!(
        "{}/{}/v1/providers/{}/{}/{}/binary/{}/{}",
        MOUNT_PREFIX, repo_key, namespace, type_name, version, os, arch
    )
}

/// The archive filename Terraform expects for a provider package.
fn build_provider_filename(type_name: &str, version: &str, platform: &str) -> String {
    format!(
        "terraform-provider-{}_{}_{}.zip",
        type_name, version, platform
    )
}

/// The coordinates of one provider package (a single os/arch build). The five
/// segments always travel together, so they are passed as one value.
struct ProviderPackageRef<'a> {
    namespace: &'a str,
    type_name: &'a str,
    version: &'a str,
    os: &'a str,
    arch: &'a str,
}

impl ProviderPackageRef<'_> {
    /// `artifacts.path` this package is stored under.
    fn artifact_path(&self) -> String {
        build_provider_artifact_path(
            self.namespace,
            self.type_name,
            self.version,
            self.os,
            self.arch,
        )
    }

    /// The archive filename Terraform expects for this package.
    fn filename(&self) -> String {
        build_provider_filename(
            self.type_name,
            self.version,
            &build_platform(self.os, self.arch),
        )
    }
}

/// Stream a stored provider package's `.zip`.
///
/// Shared by the registry `binary` route (the location the package document
/// advertises) and by the hosted network mirror's archive route, so both serve
/// the same bytes resolved the same way.
async fn serve_provider_archive(
    state: &SharedState,
    repo: &RepoInfo,
    pkg: &ProviderPackageRef<'_>,
    ctx: &crate::api::middleware::download_telemetry::DownloadContext,
) -> Result<Response, Response> {
    let result = proxy_helpers::local_fetch_by_path(
        &state.db,
        state,
        repo.id,
        &repo.storage_location(),
        &pkg.artifact_path(),
    )
    .await?;

    // #3143: enforce quarantine + scan policy before streaming. Also covers
    // `mirror_download`'s hosted arm, which resolves through this function.
    proxy_helpers::gate_and_record_streamed_local(&state.db, result.artifact_id, ctx).await?;

    proxy_helpers::stream_fetch_result(result, "application/zip", Some(&pkg.filename()))
}

/// Stream the provider archive a package document's `download_url` points at.
async fn download_provider_binary(
    State(state): State<SharedState>,
    Path((repo_key, namespace, type_name, version, os, arch)): Path<(
        String,
        String,
        String,
        String,
        String,
        String,
    )>,
    ctx: crate::api::middleware::download_telemetry::DownloadContext,
) -> Result<Response, Response> {
    let repo = resolve_terraform_repo(&state.db, &repo_key).await?;
    serve_provider_archive(
        &state,
        &repo,
        &ProviderPackageRef {
            namespace: &namespace,
            type_name: &type_name,
            version: &version,
            os: &os,
            arch: &arch,
        },
        &ctx,
    )
    .await
}

async fn upload_provider(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((repo_key, namespace, type_name, version, os, arch)): Path<(
        String,
        String,
        String,
        String,
        String,
        String,
    )>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, Response> {
    // GHSA-vvc3-h39c-mrq5: enforce token scope before processing.
    let user_id = require_auth_basic_scope(auth, "terraform", "write:artifacts")?.user_id;
    let repo = resolve_terraform_repo(&state.db, &repo_key).await?;
    proxy_helpers::reject_write_if_not_hosted(&repo.repo_type)?;
    repo.reject_if_promotion_only(false)?;
    let declared_protocols = parse_protocols_header(&headers)
        .map_err(|msg| (StatusCode::BAD_REQUEST, msg).into_response())?;
    let provider_name = build_provider_name(&namespace, &type_name);
    let platform = build_platform(&os, &arch);

    let artifact_path = build_provider_artifact_path(&namespace, &type_name, &version, &os, &arch);

    // GHSA-vcq6-8hxw-4q67: URL segments are spliced into the path verbatim;
    // reject traversal at ingest.
    crate::services::upload_service::validate_artifact_path(&artifact_path)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()).into_response())?;

    // Check for duplicate
    let existing = sqlx::query_scalar!(
        "SELECT id FROM artifacts WHERE repository_id = $1 AND name = $2 AND version = $3 AND path = $4 AND is_deleted = false",
        repo.id,
        provider_name,
        version,
        artifact_path,
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        crate::api::handlers::db_err(e)
    })?;

    if existing.is_some() {
        return Err((
            StatusCode::CONFLICT,
            format!(
                "Provider {} version {} for {} already exists",
                provider_name, version, platform
            ),
        )
            .into_response());
    }

    super::cleanup_soft_deleted_artifact(&state.db, repo.id, &artifact_path).await;

    // Stream the request body to a bounded scratch file, computing the content
    // digests in one pass — never buffering the provider archive in memory
    // (#2517). The stager enforces `max_upload_size_bytes` mid-stream.
    let (staged, digests) =
        proxy_helpers::stage_stream_content_addressed(&state, body.into_data_stream()).await?;
    let checksum = digests.sha256.clone();
    let size_bytes = staged.size_bytes();

    // Header wins; otherwise the registry manifest shipped inside the archive
    // (the file `terraform-provider-*` release zips carry); otherwise nothing
    // is recorded and the package keeps the legacy default.
    let protocols = match declared_protocols {
        Some(p) => Some(p),
        None => read_manifest_protocols(staged.path().to_path_buf()).await,
    };

    let storage_key = build_provider_storage_key(&namespace, &type_name, &version, &platform);

    // Store the file, streamed from the staged scratch file.
    // `put_artifact_stream` runs the cross-repo write guard (#2584) before
    // writing, then streams the object to storage.
    proxy_helpers::put_artifact_stream(&state, &repo, &storage_key, staged).await?;

    // Insert artifact record
    let mut tx = super::publish_quota::begin_admitted_publish(
        &state.db,
        repo.id,
        &artifact_path,
        size_bytes,
    )
    .await?;
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
        provider_name,
        version,
        size_bytes,
        checksum,
        "application/zip",
        storage_key,
        user_id,
    )
    .fetch_one(&mut *tx)
    .await
    .map_err(crate::api::handlers::db_err)?;
    tx.commit().await.map_err(crate::api::handlers::db_err)?;

    crate::services::quarantine_service::apply_upload_hold_hosted(&state.db, repo.id, artifact_id)
        .await;
    crate::services::scanner_service::trigger_scan_on_upload(
        &state.db,
        state.scanner_service.clone(),
        repo.id,
        artifact_id,
    )
    .await;

    // Store metadata
    let metadata = build_provider_metadata(
        &namespace,
        &type_name,
        &version,
        &os,
        &arch,
        protocols.as_deref(),
    );

    let _ = sqlx::query!(
        r#"
        INSERT INTO artifact_metadata (artifact_id, format, metadata)
        VALUES ($1, 'terraform', $2)
        ON CONFLICT (artifact_id) DO UPDATE SET metadata = $2
        "#,
        artifact_id,
        metadata,
    )
    .execute(&state.db)
    .await;

    // Update repository timestamp
    let _ = sqlx::query!(
        "UPDATE repositories SET updated_at = NOW() WHERE id = $1",
        repo.id,
    )
    .execute(&state.db)
    .await;

    // Surface the provider on the Packages page (#3659), keyed on the
    // registry coordinate `namespace/type` and the version. Each platform
    // build of one version collapses into the same catalog version row.
    crate::services::package_service::register_published_package(
        &state.db,
        &state.event_bus,
        repo.id,
        "terraform",
        &provider_name,
        &version,
        size_bytes,
        &checksum,
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
        "Terraform provider upload: {}/{} v{} ({}) to repo {}",
        namespace, type_name, version, platform, repo_key
    );

    Ok(Response::builder()
        .status(StatusCode::CREATED)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::to_string(&serde_json::json!({
                "namespace": namespace,
                "type": type_name,
                "version": version,
                "os": os,
                "arch": arch,
                "checksum": checksum,
                "protocols": protocols.unwrap_or_else(default_provider_protocols),
            }))
            .unwrap(),
        ))
        .unwrap())
}

// ---------------------------------------------------------------------------
// Provider Network Mirror Protocol (#1566)
//
// Terraform/OpenTofu can be pointed at a "network mirror" via
// `provider_installation { network_mirror { url = "…" } }`. The mirror
// protocol is distinct from the registry protocol the registry handlers
// above implement: it has its own endpoints and JSON shapes.
//
//   GET <base>/:hostname/:namespace/:type/index.json
//       -> { "versions": { "<version>": {}, … } }
//   GET <base>/:hostname/:namespace/:type/<version>.json
//       -> { "archives": { "<os>_<arch>": { "url": "…", "hashes": [...] } } }
//
// The AK UI documents configuring a remote Terraform repository as a network
// mirror, so for a remote repo we translate these mirror requests into
// registry-protocol calls against the configured upstream (e.g.
// registry.opentofu.org) and rewrite the package URLs to flow the actual
// archive download back through AK (so it is cached/auth-gated like any other
// proxied artifact).
// ---------------------------------------------------------------------------

/// Strip the trailing `.json` from a mirror version filename (`2.0.0.json` ->
/// `2.0.0`). Returns `None` when the segment is not a `.json` document.
fn parse_mirror_version_file(version_file: &str) -> Option<&str> {
    version_file.strip_suffix(".json")
}

/// Build the upstream registry path that lists available versions of a
/// provider (Provider Registry Protocol).
fn build_registry_versions_path(namespace: &str, type_name: &str) -> String {
    format!("v1/providers/{}/{}/versions", namespace, type_name)
}

/// Build the upstream registry path that returns the download metadata for one
/// provider package (Provider Registry Protocol).
fn build_registry_download_path(
    namespace: &str,
    type_name: &str,
    version: &str,
    os: &str,
    arch: &str,
) -> String {
    format!(
        "v1/providers/{}/{}/{}/download/{}/{}",
        namespace, type_name, version, os, arch
    )
}

/// Build the AK-local mirror download URL emitted in `<version>.json` so the
/// archive is fetched back through this server (relative to the mirror base,
/// per the network-mirror spec).
fn build_mirror_archive_url(version: &str, os: &str, arch: &str, ticket: Option<&str>) -> String {
    // The mirror base the client configured already ends at
    // `<base>/:hostname/:namespace/:type/`, so a relative URL keeps the path
    // anchored there. Terraform resolves it against the request URL.
    //
    // #3588: the Network Mirror Protocol says Terraform does NOT send the
    // configured credentials when it fetches the archives named here, and
    // tells a mirror that needs to protect them to hand out "cryptographically
    // secure, user-specific, and time-limited URLs" instead. A single-use
    // download ticket bound to exactly this archive path is that URL.
    match ticket {
        Some(t) => format!("{}/download/{}/{}?ticket={}", version, os, arch, t),
        None => format!("{}/download/{}/{}", version, os, arch),
    }
}

/// Transform a registry-protocol `versions` document into a mirror-protocol
/// `index.json` document.
///
/// Registry shape: `{ "versions": [ { "version": "2.0.0", … }, … ] }`
/// Mirror shape:   `{ "versions": { "2.0.0": {}, … } }`
fn registry_versions_to_mirror_index(registry: &serde_json::Value) -> serde_json::Value {
    let mut versions = serde_json::Map::new();
    if let Some(arr) = registry.get("versions").and_then(|v| v.as_array()) {
        for entry in arr {
            if let Some(v) = entry.get("version").and_then(|v| v.as_str()) {
                versions.insert(v.to_string(), serde_json::json!({}));
            }
        }
    }
    serde_json::json!({ "versions": serde_json::Value::Object(versions) })
}

/// Collect the `(os, arch)` platform pairs advertised for a specific version
/// from a registry-protocol `versions` document.
fn platforms_for_version(registry: &serde_json::Value, version: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    if let Some(arr) = registry.get("versions").and_then(|v| v.as_array()) {
        for entry in arr {
            if entry.get("version").and_then(|v| v.as_str()) != Some(version) {
                continue;
            }
            if let Some(platforms) = entry.get("platforms").and_then(|v| v.as_array()) {
                for p in platforms {
                    let os = p.get("os").and_then(|v| v.as_str());
                    let arch = p.get("arch").and_then(|v| v.as_str());
                    if let (Some(os), Some(arch)) = (os, arch) {
                        out.push((os.to_string(), arch.to_string()));
                    }
                }
            }
        }
    }
    out
}

/// Convert a hex SHA-256 of a provider `.zip` into the `zh:` hash form
/// Terraform expects in a mirror archive entry.
///
/// `zh:` ("zip hash") is defined as the SHA-256 of the archive file itself,
/// which Terraform verifies against the package it downloads from the mirror
/// (`PackageMatchesAnyHash` -> `PackageHashLegacyZipSHA`). Returns `None` for
/// a missing/empty checksum, in which case the entry is advertised without
/// hashes rather than with a wrong one.
fn shasum_to_mirror_hash(shasum: Option<&str>) -> Option<String> {
    shasum
        .filter(|s| !s.is_empty())
        .map(|s| format!("zh:{}", s))
}

/// Convert a registry-protocol download document's `shasum` (hex SHA-256) into
/// the `zh:` hash form Terraform expects in a mirror archive entry. Returns
/// `None` when no usable shasum is present.
fn registry_shasum_to_mirror_hash(download: &serde_json::Value) -> Option<String> {
    shasum_to_mirror_hash(download.get("shasum").and_then(|v| v.as_str()))
}

/// Build one mirror archive entry from the AK-local archive URL plus an
/// optional hash list.
fn build_mirror_archive_entry(url: &str, hashes: Vec<String>) -> serde_json::Value {
    if hashes.is_empty() {
        serde_json::json!({ "url": url })
    } else {
        serde_json::json!({ "url": url, "hashes": hashes })
    }
}

/// How a repo must serve network-mirror requests, or why it cannot. Kept as a
/// pure enum so the (otherwise async) guard's branching is unit-testable.
#[derive(Debug, PartialEq, Eq)]
enum MirrorGuard {
    /// Hosted repo: serve the packages uploaded to this repo directly.
    Local,
    /// Remote repo configured for proxying: translate mirror requests into
    /// registry-protocol calls against the upstream.
    Proxy,
    /// Remote repo missing an upstream URL or with proxying disabled.
    NotProxyable,
    /// A repo type the mirror cannot serve (virtual: no single package source
    /// to mirror).
    Unsupported,
}

/// Decide how a resolved repo serves network-mirror requests, given its type
/// and whether an upstream URL and a proxy service are available.
///
/// A hosted repo mirrors its own uploaded providers; only remote repos need an
/// upstream and a proxy service.
///
/// Serving is opt-in per known repository type: an unrecognized `repo_type` is
/// [`MirrorGuard::Unsupported`], never `Local`. `Local` releases this repo's
/// own stored packages, so an `else` arm that caught everything would serve
/// them for the empty string `resolve_repo_by_key` yields when the column read
/// fails, and for any `RepositoryType` variant added after this match.
fn classify_mirror_repo(repo_type: &str, has_upstream: bool, has_proxy: bool) -> MirrorGuard {
    let Some(repo_type) = RepositoryType::from_db_str(repo_type) else {
        return MirrorGuard::Unsupported;
    };

    match repo_type {
        RepositoryType::Remote => {
            if has_upstream && has_proxy {
                MirrorGuard::Proxy
            } else {
                MirrorGuard::NotProxyable
            }
        }
        // Local / Staging: serve the repo's own uploaded providers.
        t if t.is_hosted() => MirrorGuard::Local,
        // Virtual: no single package source to mirror.
        _ => MirrorGuard::Unsupported,
    }
}

/// Map a non-servable [`MirrorGuard`] to the client-facing error response.
fn mirror_guard_error(guard: MirrorGuard) -> Response {
    let msg = match guard {
        MirrorGuard::Unsupported => {
            "Provider network mirror is not available on this Terraform repository type"
        }
        MirrorGuard::NotProxyable => "Remote repository is not configured for proxying",
        // Unreachable; callers only map the non-servable variants.
        MirrorGuard::Local | MirrorGuard::Proxy => "",
    };
    (StatusCode::NOT_FOUND, msg.to_string()).into_response()
}

// ---------------------------------------------------------------------------
// Hosted mirror source
//
// For a hosted repo the mirror documents are built from the packages uploaded
// to that repo, so `terraform init` can install a provider that only ever
// existed in Artifact Keeper. The document shapes are identical to the proxied
// (remote) source's — both funnel through `assemble_mirror_archives`.
// ---------------------------------------------------------------------------

/// A provider package a hosted repo stores locally.
struct LocalProviderPackage {
    os: String,
    arch: String,
    /// Hex SHA-256 of the stored `.zip` (`artifacts.checksum_sha256`).
    shasum: String,
}

/// Build the mirror `index.json` document from the versions a hosted repo
/// actually stores. Mirror shape: `{ "versions": { "1.0.0": {}, … } }`.
fn local_versions_to_mirror_index(versions: &[String]) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    for version in versions {
        map.insert(version.clone(), serde_json::json!({}));
    }
    serde_json::json!({ "versions": serde_json::Value::Object(map) })
}

/// Recover a stored package's `(os, arch)`: from its upload metadata when
/// present, else from the `<os>_<arch>` tail of its artifact path (the shape
/// [`build_provider_artifact_path`] writes). Returns `None` for a package whose
/// platform cannot be determined, so it is omitted rather than advertised under
/// a guessed platform.
fn provider_platform_from(
    metadata: Option<&serde_json::Value>,
    path: &str,
) -> Option<(String, String)> {
    if let Some(md) = metadata {
        let os = md.get("os").and_then(|v| v.as_str());
        let arch = md.get("arch").and_then(|v| v.as_str());
        if let (Some(os), Some(arch)) = (os, arch) {
            if !os.is_empty() && !arch.is_empty() {
                return Some((os.to_string(), arch.to_string()));
            }
        }
    }
    let (os, arch) = path.rsplit('/').next()?.split_once('_')?;
    if os.is_empty() || arch.is_empty() {
        return None;
    }
    Some((os.to_string(), arch.to_string()))
}

/// Build the registry-protocol `versions` array from stored provider rows
/// `(version, metadata, path)`. Each package's platform is recovered through
/// [`provider_platform_from`] — the same rule the network mirror uses — so the
/// `versions` route and the mirror advertise the same platforms. A package
/// whose platform cannot be determined is omitted rather than advertised under
/// a guessed one; a version whose packages are all unrecoverable is listed with
/// an empty `platforms` array instead of a fabricated `linux`/`amd64` entry.
fn provider_versions_from_rows(
    rows: &[(String, Option<serde_json::Value>, String)],
) -> Vec<serde_json::Value> {
    type VersionEntry = (Vec<serde_json::Value>, Vec<String>);
    let mut version_map: std::collections::BTreeMap<String, VersionEntry> =
        std::collections::BTreeMap::new();

    for (version, metadata, path) in rows {
        let (platforms, protocols) = version_map.entry(version.clone()).or_default();
        // A version advertises every protocol any of its packages speaks.
        for protocol in provider_protocols_from_metadata(metadata.as_ref()) {
            if !protocols.contains(&protocol) {
                protocols.push(protocol);
            }
        }
        if let Some((os, arch)) = provider_platform_from(metadata.as_ref(), path) {
            let platform = serde_json::json!({ "os": os, "arch": arch });
            if !platforms.contains(&platform) {
                platforms.push(platform);
            }
        }
    }

    version_map
        .into_iter()
        .map(|(version, (platforms, protocols))| {
            let protocols = normalize_protocols(protocols.iter().map(String::as_str))
                .unwrap_or_else(default_provider_protocols);
            serde_json::json!({
                "version": version,
                "protocols": protocols,
                "platforms": platforms,
            })
        })
        .collect()
}

/// Split locally stored packages into the `(platforms, shasums)` pair
/// [`assemble_mirror_archives`] consumes, so a hosted mirror emits the same
/// `<version>.json` shape as a proxied one.
#[allow(clippy::type_complexity)]
fn local_packages_to_archive_inputs(
    packages: &[LocalProviderPackage],
) -> (
    Vec<(String, String)>,
    std::collections::HashMap<(String, String), String>,
) {
    let mut platforms = Vec::new();
    let mut shasums = std::collections::HashMap::new();
    for pkg in packages {
        let platform = (pkg.os.clone(), pkg.arch.clone());
        if !platforms.contains(&platform) {
            platforms.push(platform.clone());
        }
        if let Some(hash) = shasum_to_mirror_hash(Some(pkg.shasum.as_str())) {
            shasums.insert(platform, hash);
        }
    }
    (platforms, shasums)
}

/// List the versions of a provider a hosted repo stores.
async fn local_provider_versions(
    db: &PgPool,
    repo: &RepoInfo,
    namespace: &str,
    type_name: &str,
) -> Result<Vec<String>, Response> {
    let provider_name = build_provider_name(namespace, type_name);
    // Held packages are excluded (#2662): `mirror_download` refuses their
    // bytes, so `index.json` must not advertise the version. Same predicate as
    // `list_provider_versions` / `local_provider_packages`.
    let versions: Vec<Option<String>> = sqlx::query_scalar!(
        r#"
        SELECT DISTINCT version
        FROM artifacts
        WHERE repository_id = $1
          AND name = $2
          AND is_deleted = false
          AND version IS NOT NULL
          AND (
            quarantine_status IS NULL
            OR quarantine_status NOT IN ('quarantined', 'rejected')
            OR (
              quarantine_status = 'quarantined'
              AND quarantine_until IS NOT NULL
              AND quarantine_until <= NOW()
            )
          )
        ORDER BY version
        "#,
        repo.id,
        provider_name,
    )
    .fetch_all(db)
    .await
    .map_err(crate::api::handlers::db_err)?;

    Ok(versions.into_iter().flatten().collect())
}

/// List the packages (one per platform) a hosted repo stores for one provider
/// version.
async fn local_provider_packages(
    db: &PgPool,
    repo: &RepoInfo,
    namespace: &str,
    type_name: &str,
    version: &str,
) -> Result<Vec<LocalProviderPackage>, Response> {
    let provider_name = build_provider_name(namespace, type_name);
    // Held packages are excluded (#2662): `<version>.json` would otherwise
    // publish the exact `zh:` SHA-256 of a package whose bytes the mirror's
    // download route refuses. Same predicate as `local_provider_versions`.
    let rows = sqlx::query!(
        r#"
        SELECT a.path, a.checksum_sha256, am.metadata as "metadata?"
        FROM artifacts a
        LEFT JOIN artifact_metadata am ON am.artifact_id = a.id
        WHERE a.repository_id = $1
          AND a.name = $2
          AND a.version = $3
          AND a.is_deleted = false
          AND (
            a.quarantine_status IS NULL
            OR a.quarantine_status NOT IN ('quarantined', 'rejected')
            OR (
              a.quarantine_status = 'quarantined'
              AND a.quarantine_until IS NOT NULL
              AND a.quarantine_until <= NOW()
            )
          )
        ORDER BY a.path
        "#,
        repo.id,
        provider_name,
        version,
    )
    .fetch_all(db)
    .await
    .map_err(crate::api::handlers::db_err)?;

    Ok(rows
        .into_iter()
        .filter_map(|row| {
            let (os, arch) = provider_platform_from(row.metadata.as_ref(), &row.path)?;
            Some(LocalProviderPackage {
                os,
                arch,
                // `checksum_sha256` is CHAR(64): trim so a short value's blank
                // padding can never be advertised as part of a `zh:` hash.
                shasum: row.checksum_sha256.trim().to_string(),
            })
        })
        .collect())
}

/// Assemble the mirror `<version>.json` `archives` object from the discovered
/// platforms and a (possibly partial) per-platform shasum lookup. Pure so the
/// archive shaping is exercised without any network I/O.
fn assemble_mirror_archives(
    version: &str,
    platforms: &[(String, String)],
    shasums: &std::collections::HashMap<(String, String), String>,
    tickets: &std::collections::HashMap<(String, String), String>,
) -> serde_json::Value {
    let mut archives = serde_json::Map::new();
    for (os, arch) in platforms {
        let url = build_mirror_archive_url(
            version,
            os,
            arch,
            tickets.get(&(os.clone(), arch.clone())).map(String::as_str),
        );
        let hashes = shasums
            .get(&(os.clone(), arch.clone()))
            .cloned()
            .map(|h| vec![h])
            .unwrap_or_default();
        archives.insert(
            format!("{}_{}", os, arch),
            build_mirror_archive_entry(&url, hashes),
        );
    }
    serde_json::json!({ "archives": serde_json::Value::Object(archives) })
}

/// Extract the upstream `download_url` from a registry download document.
fn extract_download_url(download: &serde_json::Value) -> Option<&str> {
    download
        .get("download_url")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
}

/// 404 response for a provider the mirror serves no versions of.
fn mirror_provider_not_found(namespace: &str, type_name: &str) -> Response {
    (
        StatusCode::NOT_FOUND,
        format!("Provider {}/{} not found", namespace, type_name),
    )
        .into_response()
}

/// 404 response for an unknown provider/version on the mirror.
fn mirror_not_found(namespace: &str, type_name: &str, version: &str) -> Response {
    (
        StatusCode::NOT_FOUND,
        format!("Provider {}/{} {} not found", namespace, type_name, version),
    )
        .into_response()
}

/// Parse the version from a mirror `<version>.json` filename, returning the
/// `404` error response when the document name is not recognized.
#[allow(clippy::result_large_err)] // Response-as-error matches the handler convention in this module.
fn version_from_mirror_file(version_file: &str) -> Result<&str, Response> {
    parse_mirror_version_file(version_file).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            format!("Unrecognized mirror document: {}", version_file),
        )
            .into_response()
    })
}

/// Resolve the upstream archive URL from a registry download document, mapping
/// a missing/empty `download_url` to the appropriate `502` response.
#[allow(clippy::result_large_err)] // Response-as-error matches the handler convention in this module.
fn resolve_archive_url(download: &serde_json::Value) -> Result<&str, Response> {
    extract_download_url(download).ok_or_else(|| {
        (
            StatusCode::BAD_GATEWAY,
            "Upstream registry did not provide a download_url".to_string(),
        )
            .into_response()
    })
}

/// Derive a scheme-less proxy-cache path for a network-mirror archive
/// download from the registry-provided (frequently absolute) `download_url`.
///
/// `archive_url` is used directly as the upstream fetch target (absolute
/// `http(s)://` URLs pass through `ProxyService::build_upstream_url`
/// unchanged), but it cannot double as the proxy-cache path: the `https://`
/// scheme's `//` trips `ProxyService::validate_cache_path`'s empty-segment
/// guard. This instead derives a canonical
/// `<namespace>/<type>/<version>/<os>/<arch>/<filename>` path from the
/// archive URL's own filename, keeping cache keys stable regardless of which
/// host or path shape the upstream registry serves archives from (#1998).
///
/// Parses `archive_url` instead of splitting the raw string so that a signed
/// URL's query string (e.g. `?X-Amz-Signature=...`) or fragment is dropped
/// along with everything else outside the path: query material must never
/// end up embedded in a proxy-cache object key.
fn mirror_archive_cache_path(
    namespace: &str,
    type_name: &str,
    version: &str,
    os: &str,
    arch: &str,
    archive_url: &str,
) -> String {
    let filename = reqwest::Url::parse(archive_url)
        .ok()
        .and_then(|url| url.path_segments()?.next_back().map(str::to_string))
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "provider.zip".to_string());

    format!("{namespace}/{type_name}/{version}/{os}/{arch}/{filename}")
}

/// Validated context for serving a network-mirror request against a remote
/// Terraform repository: the resolved repo plus its upstream registry URL.
struct MirrorRemote<'a> {
    repo: RepoInfo,
    upstream_url: String,
    proxy: &'a crate::services::proxy_service::ProxyService,
}

/// Where a repo's network-mirror documents come from.
enum MirrorSource<'a> {
    /// Hosted repo: its own uploaded provider packages.
    Local(RepoInfo),
    /// Remote repo: the configured upstream registry, proxied.
    Remote(MirrorRemote<'a>),
}

/// Resolve a Terraform repo for the network-mirror protocol into the source
/// that serves it. Centralizes the guard shared by all three mirror handlers so
/// the logic exists once (#1566).
async fn resolve_mirror_source<'a>(
    state: &'a SharedState,
    repo_key: &str,
) -> Result<MirrorSource<'a>, Response> {
    let repo = resolve_terraform_repo(&state.db, repo_key).await?;

    match classify_mirror_repo(
        &repo.repo_type,
        repo.upstream_url.is_some(),
        state.proxy_service.is_some(),
    ) {
        MirrorGuard::Local => Ok(MirrorSource::Local(repo)),
        MirrorGuard::Proxy => {
            // Both unwraps are guaranteed by the `Proxy` classification.
            let upstream_url = repo.upstream_url.clone().unwrap();
            let proxy = state.proxy_service.as_ref().unwrap();
            Ok(MirrorSource::Remote(MirrorRemote {
                repo,
                upstream_url,
                proxy,
            }))
        }
        guard => Err(mirror_guard_error(guard)),
    }
}

/// Fetch a registry-protocol document from the upstream and parse it as JSON,
/// mapping any failure to the appropriate client response.
async fn fetch_upstream_json(
    remote: &MirrorRemote<'_>,
    repo_key: &str,
    path: &str,
) -> Result<serde_json::Value, Response> {
    let (content, _ct) = proxy_helpers::proxy_fetch_capped(
        remote.proxy,
        remote.repo.id,
        repo_key,
        &remote.upstream_url,
        path,
        proxy_helpers::DEFAULT_METADATA_MAX_BYTES,
    )
    .await?;
    serde_json::from_slice(&content).map_err(|e| {
        (
            StatusCode::BAD_GATEWAY,
            format!("Invalid upstream registry response: {}", e),
        )
            .into_response()
    })
}

/// Wrap a serialized JSON value in a 200 `application/json` response.
fn json_ok_response(value: &serde_json::Value) -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(value).unwrap()))
        .unwrap()
}

/// The mirror coordinate a `<version>.json` document is being assembled for.
/// Grouped so the ticket helpers below take one argument instead of five.
struct MirrorCoords<'a> {
    repo_key: &'a str,
    hostname: &'a str,
    namespace: &'a str,
    type_name: &'a str,
    version: &'a str,
}

impl MirrorCoords<'_> {
    /// The exact request path [`mirror_download`] is reached at for one
    /// platform, which is also the path a #3588 archive ticket is bound to
    /// (tickets match by exact path, so nothing else authenticates).
    fn download_request_path(&self, os: &str, arch: &str) -> String {
        format!(
            "{}/{}/{}/{}/{}/{}/download/{}/{}",
            MOUNT_PREFIX,
            self.repo_key,
            self.hostname,
            self.namespace,
            self.type_name,
            self.version,
            os,
            arch
        )
    }
}

/// How long a provider-archive ticket stays valid (#3588).
///
/// Terraform reads the packages document and then installs each platform's
/// archive, so the gap is normally sub-second — but a real `terraform init`
/// resolves a whole dependency set, and the column's 30-second default is
/// tight enough to turn a slow plan into the very 401 this fixes. Still
/// single-use and still bound to one archive path.
const MIRROR_TICKET_TTL_SECS: i64 = 600;

/// Mint one single-use, path-bound download ticket per platform so Terraform's
/// un-credentialed archive fetch authenticates as the caller who asked for the
/// packages document (#3588).
///
/// Anonymous callers get no tickets: they are reading a repository that served
/// them the packages document without a credential, so the plain relative URL
/// they already resolve is reachable without one. A ticket that cannot be
/// minted is skipped rather than failing the request — the URL then behaves
/// exactly as it did before this change.
async fn mint_mirror_archive_tickets(
    state: &SharedState,
    auth: Option<&AuthExtension>,
    coords: &MirrorCoords<'_>,
    platforms: &[(String, String)],
) -> std::collections::HashMap<(String, String), String> {
    let mut tickets = std::collections::HashMap::new();
    if auth.is_none() {
        return tickets;
    }
    for (os, arch) in platforms {
        let resource_path = coords.download_request_path(os, arch);
        if let Some(ticket) =
            mint_path_ticket(state, auth, &resource_path, "terraform-mirror-archive").await
        {
            tickets.insert((os.clone(), arch.clone()), ticket);
        }
    }
    tickets
}

/// Mint one single-use download ticket bound to exactly `resource_path` for
/// the authenticated caller, or `None` for an anonymous caller or when minting
/// fails (the URL then behaves exactly as it would without a ticket).
async fn mint_path_ticket(
    state: &SharedState,
    auth: Option<&AuthExtension>,
    resource_path: &str,
    purpose: &str,
) -> Option<String> {
    let auth = auth?;
    // The ticket carries the caller's repository restriction
    // (GHSA-2mfv-xg68-gq4p).
    match crate::services::auth_config_service::AuthConfigService::create_download_ticket_with_ttl(
        &state.db,
        auth.user_id,
        &auth.allowed_repo_ids,
        purpose,
        Some(resource_path),
        MIRROR_TICKET_TTL_SECS,
    )
    .await
    {
        Ok(ticket) => Some(ticket),
        Err(e) => {
            tracing::warn!(
                error = %e,
                "terraform: could not mint download ticket for {}",
                resource_path
            );
            None
        }
    }
}

/// `path?ticket=<t>` when a ticket was minted, else `path` unchanged.
fn ticketed_path(ticket: Option<String>, path: String) -> String {
    match ticket {
        Some(t) => format!("{path}?ticket={t}"),
        None => path,
    }
}

/// GET /:repo_key/:hostname/:namespace/:type/index.json — mirror version list.
async fn mirror_index(
    State(state): State<SharedState>,
    Path((repo_key, _hostname, namespace, type_name)): Path<(String, String, String, String)>,
) -> Result<Response, Response> {
    match resolve_mirror_source(&state, &repo_key).await? {
        MirrorSource::Local(repo) => {
            let versions =
                local_provider_versions(&state.db, &repo, &namespace, &type_name).await?;
            if versions.is_empty() {
                return Err(mirror_provider_not_found(&namespace, &type_name));
            }
            Ok(json_ok_response(&local_versions_to_mirror_index(&versions)))
        }
        MirrorSource::Remote(remote) => {
            let path = build_registry_versions_path(&namespace, &type_name);
            let registry = fetch_upstream_json(&remote, &repo_key, &path).await?;
            Ok(json_ok_response(&registry_versions_to_mirror_index(
                &registry,
            )))
        }
    }
}

/// GET /:repo_key/:hostname/:namespace/:type/<version>.json — mirror packages.
async fn mirror_version(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((repo_key, hostname, namespace, type_name, version_file)): Path<(
        String,
        String,
        String,
        String,
        String,
    )>,
) -> Result<Response, Response> {
    let version = version_from_mirror_file(&version_file)?;

    let (platforms, shasums) = match resolve_mirror_source(&state, &repo_key).await? {
        MirrorSource::Local(repo) => {
            // The stored packages are the source of truth for both the
            // platform list and the hashes.
            let packages =
                local_provider_packages(&state.db, &repo, &namespace, &type_name, version).await?;
            local_packages_to_archive_inputs(&packages)
        }
        MirrorSource::Remote(remote) => {
            // Discover the platforms this version ships for via the registry's
            // `versions` document.
            let versions_path = build_registry_versions_path(&namespace, &type_name);
            let registry = fetch_upstream_json(&remote, &repo_key, &versions_path).await?;
            let platforms = platforms_for_version(&registry, version);

            // Best-effort: pull each per-platform download doc to obtain the
            // shasum. A failed/absent shasum just omits the hash (Terraform
            // downloads without pinning) rather than failing the whole request.
            let mut shasums = std::collections::HashMap::new();
            for (os, arch) in &platforms {
                let dl_path =
                    build_registry_download_path(&namespace, &type_name, version, os, arch);
                if let Some(hash) = fetch_upstream_json(&remote, &repo_key, &dl_path)
                    .await
                    .ok()
                    .as_ref()
                    .and_then(registry_shasum_to_mirror_hash)
                {
                    shasums.insert((os.clone(), arch.clone()), hash);
                }
            }
            (platforms, shasums)
        }
    };

    if platforms.is_empty() {
        return Err(mirror_not_found(&namespace, &type_name, version));
    }

    // #3588: Terraform sends no credentials to the archive URLs listed below,
    // so a private mirror answered every one of them with 401. Hand out
    // ticketed URLs instead — the protocol's prescribed remedy.
    let tickets = mint_mirror_archive_tickets(
        &state,
        auth.as_ref(),
        &MirrorCoords {
            repo_key: &repo_key,
            hostname: &hostname,
            namespace: &namespace,
            type_name: &type_name,
            version,
        },
        &platforms,
    )
    .await;

    Ok(json_ok_response(&assemble_mirror_archives(
        version, &platforms, &shasums, &tickets,
    )))
}

/// GET /:repo_key/:hostname/:namespace/:type/:version/download/:os/:arch —
/// stream the provider archive for a platform (referenced by `mirror_version`).
async fn mirror_download(
    State(state): State<SharedState>,
    Path((repo_key, _hostname, namespace, type_name, version, os, arch)): Path<(
        String,
        String,
        String,
        String,
        String,
        String,
        String,
    )>,
    ctx: crate::api::middleware::download_telemetry::DownloadContext,
) -> Result<Response, Response> {
    let remote = match resolve_mirror_source(&state, &repo_key).await? {
        // Hosted: the archive is our own stored package.
        MirrorSource::Local(repo) => {
            return serve_provider_archive(
                &state,
                &repo,
                &ProviderPackageRef {
                    namespace: &namespace,
                    type_name: &type_name,
                    version: &version,
                    os: &os,
                    arch: &arch,
                },
                &ctx,
            )
            .await;
        }
        MirrorSource::Remote(remote) => remote,
    };

    // Resolve the upstream registry download document to learn the real
    // archive URL, then stream that archive back through the proxy (cached).
    let dl_path = build_registry_download_path(&namespace, &type_name, &version, &os, &arch);
    let download = fetch_upstream_json(&remote, &repo_key, &dl_path).await?;

    let archive_url = resolve_archive_url(&download)?;

    // A malicious/compromised upstream registry could return an internal
    // address (e.g. the cloud metadata endpoint) as `download_url`. Validate
    // it against the same anti-SSRF policy used for other registries'
    // registry-discovered download URLs (see cargo.rs's `download` handler
    // and pypi.rs's `find_upstream_url_for_file` path) before fetching it.
    validate_outbound_url(archive_url, "Terraform upstream archive URL").map_err(|e| {
        // Deliberately omit `archive_url` from this log line: it is
        // registry-controlled and frequently a signed URL (e.g.
        // `?X-Amz-Signature=...`), so logging it verbatim would leak
        // credential-bearing query material. `e` already names the
        // specific blocked host/IP without echoing the query string.
        tracing::warn!(
            "SSRF check rejected upstream download_url for {}/{} {} {}/{}: {}",
            namespace,
            type_name,
            version,
            os,
            arch,
            e
        );
        (
            StatusCode::BAD_GATEWAY,
            format!("Upstream registry returned a disallowed download_url: {e}"),
        )
            .into_response()
    })?;

    // `archive_url` is frequently an absolute `https://` URL (#1998): fine as
    // the upstream fetch target (absolute URLs pass through unchanged), but
    // not as the proxy-cache path (its `https://` scheme trips the
    // empty-segment guard). Fetch from `archive_url` but cache under a
    // derived, scheme-less canonical path instead.
    let cache_path =
        mirror_archive_cache_path(&namespace, &type_name, &version, &os, &arch, archive_url);

    serve_mirror_archive(&state, &remote, &repo_key, archive_url, &cache_path, &ctx).await
}

/// Serve a remote mirror's provider archive through the proxy cache: a
/// presigned redirect to object storage when the cached copy is fresh and the
/// backend can sign, else the archive streamed from the cache or, on a miss,
/// from `archive_url` (cached under `cache_path`).
async fn serve_mirror_archive(
    state: &SharedState,
    remote: &MirrorRemote<'_>,
    repo_key: &str,
    archive_url: &str,
    cache_path: &str,
    ctx: &crate::api::middleware::download_telemetry::DownloadContext,
) -> Result<Response, Response> {
    let response = match proxy_helpers::proxy_cache_fresh_redirect(
        remote.proxy,
        state,
        repo_key,
        cache_path,
        ctx,
    )
    .await?
    {
        Some(redirect) => redirect,
        None => {
            proxy_helpers::proxy_fetch_streaming_response_with_cache_key(
                remote.proxy,
                remote.repo.id,
                repo_key,
                &remote.upstream_url,
                archive_url,
                cache_path,
                "application/zip",
                RepositoryFormat::Terraform,
            )
            .await?
        }
    };
    // #3649: count the proxied serve, a redirect, a warm cache HIT and a cold
    // MISS alike, while a 404/502 still counts nothing. Keyed on `cache_path`,
    // the scheme-less canonical key the fetch commits under, so the count lines
    // up with the catalog row the listing renders.
    proxy_helpers::record_proxy_download(state, remote.repo.id, repo_key, cache_path, ctx).await;
    Ok(response)
}

// ---------------------------------------------------------------------------
// Name/key/JSON builders (single source of truth; unit tests pin these
// against hardcoded literals so a format change here fails the tests — #2657)
// ---------------------------------------------------------------------------

/// Build a fully-qualified module name.
fn build_module_name(namespace: &str, name: &str, provider: &str) -> String {
    format!("{}/{}/{}", namespace, name, provider)
}

/// Build a fully-qualified provider name.
fn build_provider_name(namespace: &str, type_name: &str) -> String {
    format!("{}/{}", namespace, type_name)
}

/// Build the storage key for a Terraform module.
fn build_module_storage_key(namespace: &str, name: &str, provider: &str, version: &str) -> String {
    format!(
        "terraform/modules/{}/{}/{}/{}.tar.gz",
        namespace, name, provider, version
    )
}

/// Build the storage key for a Terraform provider.
fn build_provider_storage_key(
    namespace: &str,
    type_name: &str,
    version: &str,
    platform: &str,
) -> String {
    format!(
        "terraform/providers/{}/{}/{}/terraform-provider-{}_{}.zip",
        namespace, type_name, version, type_name, platform
    )
}

/// Build module metadata JSON.
///
/// `archive_type` records the detected archive format (#4590) as its go-getter
/// hint (`zip` / `tar.gz`), which is what `download_module` advertises.
fn build_module_metadata(
    namespace: &str,
    name: &str,
    provider: &str,
    version: &str,
    archive: ModuleArchiveType,
) -> serde_json::Value {
    serde_json::json!({
        "kind": "module",
        "namespace": namespace,
        "name": name,
        "provider": provider,
        "version": version,
        MODULE_ARCHIVE_METADATA_KEY: archive.getter_hint(),
    })
}

/// Build provider metadata JSON.
fn build_provider_metadata(
    namespace: &str,
    type_name: &str,
    version: &str,
    os: &str,
    arch: &str,
    protocols: Option<&[String]>,
) -> serde_json::Value {
    let mut metadata = serde_json::json!({
        "kind": "provider",
        "namespace": namespace,
        "type": type_name,
        "version": version,
        "os": os,
        "arch": arch,
    });
    // Recorded only when actually declared, so a package without a declaration
    // stays indistinguishable from one uploaded before protocols were tracked.
    if let Some(protocols) = protocols {
        metadata["protocols"] = serde_json::json!(protocols);
    }
    metadata
}

/// Build the version list JSON for a module.
fn build_version_list_json(versions: &[String]) -> serde_json::Value {
    let version_list: Vec<serde_json::Value> = versions
        .iter()
        .map(|v| serde_json::json!({ "version": v }))
        .collect();
    serde_json::json!({
        "modules": [{
            "versions": version_list,
        }]
    })
}

/// Build the provider download JSON response (the Provider Registry Protocol
/// package *document*; `download_url` points at the separate binary route).
///
/// With `signing`, the document additionally advertises the signed checksum
/// list (`shasums_url` / `shasums_signature_url`) and the public key that
/// verifies it — everything OpenTofu/Terraform need to authenticate the
/// package against an origin registry. Without it the legacy shape (empty
/// `gpg_public_keys`, no checksum URLs) is produced.
fn build_provider_download_json(
    os: &str,
    arch: &str,
    filename: &str,
    download_url: &str,
    shasum: &str,
    protocols: &[String],
    signing: Option<&ProviderSigningDoc>,
) -> serde_json::Value {
    let mut doc = serde_json::json!({
        "protocols": protocols,
        "os": os,
        "arch": arch,
        "filename": filename,
        "download_url": download_url,
        "shasum": shasum,
        "signing_keys": {
            "gpg_public_keys": []
        },
    });
    if let Some(signing) = signing {
        doc["shasums_url"] = serde_json::json!(signing.shasums_url);
        doc["shasums_signature_url"] = serde_json::json!(signing.shasums_signature_url);
        doc["signing_keys"]["gpg_public_keys"] = serde_json::json!([{
            "key_id": signing.key_id,
            "ascii_armor": signing.ascii_armor,
        }]);
    }
    doc
}

/// The signing-related fields of a provider package document.
struct ProviderSigningDoc {
    key_id: String,
    /// ASCII-armored OpenPGP *public* key.
    ascii_armor: String,
    shasums_url: String,
    shasums_signature_url: String,
}

/// Path-absolute location of a provider version's checksum list.
fn build_provider_shasums_url(
    repo_key: &str,
    namespace: &str,
    type_name: &str,
    version: &str,
) -> String {
    format!(
        "{}/{}/v1/providers/{}/{}/{}/SHA256SUMS",
        MOUNT_PREFIX, repo_key, namespace, type_name, version
    )
}

/// Assemble [`ProviderSigningDoc`] for the repo's active signing key. Only the
/// public half of the key is ever read here.
fn provider_signing_doc(
    key: &crate::models::signing_key::SigningKey,
    repo_key: &str,
    namespace: &str,
    type_name: &str,
    version: &str,
) -> ProviderSigningDoc {
    let shasums_url = build_provider_shasums_url(repo_key, namespace, type_name, version);
    ProviderSigningDoc {
        key_id: key
            .key_id
            .clone()
            .or_else(|| key.fingerprint.clone())
            .unwrap_or_default(),
        ascii_armor: key.public_key_pem.clone(),
        shasums_signature_url: format!("{shasums_url}.sig"),
        shasums_url,
    }
}

/// Build the `SHA256SUMS` document for one provider version: one
/// `<sha256>  <filename>` line per published platform archive, sorted by
/// filename and de-duplicated, so the same stored packages always yield the
/// same bytes (and therefore a signature over a stable payload).
fn build_provider_shasums(
    type_name: &str,
    version: &str,
    packages: &[LocalProviderPackage],
) -> String {
    let mut lines: Vec<(String, String)> = packages
        .iter()
        .map(|pkg| {
            (
                build_provider_filename(type_name, version, &build_platform(&pkg.os, &pkg.arch)),
                pkg.shasum.to_ascii_lowercase(),
            )
        })
        .collect();
    lines.sort();
    lines.dedup();
    lines
        .into_iter()
        .map(|(filename, sha)| format!("{sha}  {filename}\n"))
        .collect()
}

// ---------------------------------------------------------------------------
// Provider protocol versions
//
// The registry protocol version(s) a provider speaks ("5.0", "6.0") are listed
// in the `versions` document and in each package document. A hosted upload may
// declare them with `X-Terraform-Protocols: 5.0,6.0` or by carrying the
// standard `terraform-registry-manifest.json` in the archive.
// ---------------------------------------------------------------------------

const PROTOCOLS_HEADER: &str = "x-terraform-protocols";
const REGISTRY_MANIFEST_NAME: &str = "terraform-registry-manifest.json";
/// A manifest is a few dozen bytes; refuse to inflate anything larger.
const REGISTRY_MANIFEST_MAX_BYTES: u64 = 16 * 1024;
const MAX_PROTOCOL_VERSIONS: usize = 8;

/// What a package is assumed to speak when nothing was declared — the value
/// every package was advertised under before protocols were tracked.
fn default_provider_protocols() -> Vec<String> {
    vec!["5.0".to_string()]
}

/// `major.minor` as numbers, or `None` for anything else.
fn parse_protocol_version(raw: &str) -> Option<(u32, u32)> {
    let (major, minor) = raw.split_once('.')?;
    let digits = |s: &str| !s.is_empty() && s.len() <= 4 && s.bytes().all(|b| b.is_ascii_digit());
    if !digits(major) || !digits(minor) {
        return None;
    }
    Some((major.parse().ok()?, minor.parse().ok()?))
}

/// Validate, de-duplicate and numerically sort protocol versions. `None` when
/// the list is empty, too long or contains a malformed entry.
fn normalize_protocols<'a>(raw: impl IntoIterator<Item = &'a str>) -> Option<Vec<String>> {
    let mut parsed = Vec::new();
    for item in raw {
        let version = parse_protocol_version(item.trim())?;
        if !parsed.contains(&version) {
            parsed.push(version);
        }
        if parsed.len() > MAX_PROTOCOL_VERSIONS {
            return None;
        }
    }
    if parsed.is_empty() {
        return None;
    }
    parsed.sort_unstable();
    Some(
        parsed
            .into_iter()
            .map(|(major, minor)| format!("{major}.{minor}"))
            .collect(),
    )
}

/// Read the optional `X-Terraform-Protocols` upload header. `Ok(None)` when
/// absent; an error message when present but malformed (rejecting is safer than
/// silently advertising a different protocol than the uploader declared).
fn parse_protocols_header(headers: &HeaderMap) -> Result<Option<Vec<String>>, String> {
    let Some(value) = headers.get(PROTOCOLS_HEADER) else {
        return Ok(None);
    };
    value
        .to_str()
        .ok()
        .and_then(|v| normalize_protocols(v.split(',')))
        .map(Some)
        .ok_or_else(|| {
            "Invalid X-Terraform-Protocols header: expected a comma-separated list of \
             'major.minor' versions, e.g. '5.0' or '5.0,6.0'"
                .to_string()
        })
}

/// Extract `metadata.protocol_versions` from the text of a
/// `terraform-registry-manifest.json`.
fn protocols_from_manifest_json(raw: &[u8]) -> Option<Vec<String>> {
    let doc: serde_json::Value = serde_json::from_slice(raw).ok()?;
    let versions = doc.get("metadata")?.get("protocol_versions")?.as_array()?;
    normalize_protocols(
        versions
            .iter()
            .map(|v| v.as_str())
            .collect::<Option<Vec<_>>>()?,
    )
}

/// Best-effort read of the registry manifest from the staged archive. Any
/// failure (not a zip, no manifest, oversized, malformed) yields `None`: the
/// manifest is an optional hint, never a reason to reject an upload.
async fn read_manifest_protocols(zip_path: std::path::PathBuf) -> Option<Vec<String>> {
    tokio::task::spawn_blocking(move || {
        use std::io::Read;
        let file = std::fs::File::open(zip_path).ok()?;
        let mut archive = zip::ZipArchive::new(file).ok()?;
        let entry = archive.by_name(REGISTRY_MANIFEST_NAME).ok()?;
        if entry.size() > REGISTRY_MANIFEST_MAX_BYTES {
            return None;
        }
        let mut raw = Vec::new();
        entry
            .take(REGISTRY_MANIFEST_MAX_BYTES)
            .read_to_end(&mut raw)
            .ok()?;
        protocols_from_manifest_json(&raw)
    })
    .await
    .ok()
    .flatten()
}

/// Protocols recorded in a package's metadata, or the legacy default.
fn provider_protocols_from_metadata(metadata: Option<&serde_json::Value>) -> Vec<String> {
    metadata
        .and_then(|m| m.get("protocols"))
        .and_then(|p| p.as_array())
        .and_then(|items| {
            normalize_protocols(
                items
                    .iter()
                    .map(|v| v.as_str())
                    .collect::<Option<Vec<_>>>()?,
            )
        })
        .unwrap_or_else(default_provider_protocols)
}

/// Parse a module name into (namespace, name, provider).
fn parse_module_name(full_name: &str) -> (String, String, String) {
    let parts: Vec<&str> = full_name.splitn(3, '/').collect();
    match parts.as_slice() {
        [ns, n, p] => (ns.to_string(), n.to_string(), p.to_string()),
        _ => (full_name.to_string(), String::new(), String::new()),
    }
}

/// Build a SQL LIKE search pattern from a query string.
///
/// #3557: the free-text term is a literal substring, so `%`/`_`/`\` in it
/// must match themselves; escaped here and matched under `ESCAPE '\'`.
fn build_search_pattern(query: &str) -> String {
    format!("%{}%", crate::api::handlers::escape_like_literal(query))
}

#[cfg(ak_test_shard = "handlers-2")]
#[cfg(test)]
mod tests {

    /// Remote module chain as a client walks it (#4590, replacing the #1608
    /// test that pinned the old body-streaming `/download`): the upstream
    /// registry answers `/download` with `204` + a relative `X-Terraform-Get`;
    /// AK answers with its own `/archive?archive=zip`, and that streams the
    /// upstream archive (#1608 Phase 4 streaming, through the proxy cache).
    #[tokio::test]
    async fn test_remote_module_download_advertises_hinted_archive_4590() {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(fx) = tdh::Fixture::setup("remote", "terraform").await else {
            return;
        };
        let server = MockServer::start().await;
        let blob: &[u8] = b"PK\x03\x04 #4590 remote module zip bytes";
        Mock::given(method("GET"))
            .and(path("/v1/modules/hashicorp/consul/aws/1.2.3/download"))
            .respond_with(
                ResponseTemplate::new(204).insert_header("X-Terraform-Get", "/files/consul-1.2.3"),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/files/consul-1.2.3"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(blob))
            .mount(&server)
            .await;

        let (state, _cache) = tdh::rewire_remote_proxy(&fx, &server.uri()).await;
        let (doc_status, _, doc_headers) = tdh::send_with_headers(
            tdh::router_anon(super::router(), state.clone()),
            tdh::get(format!(
                "/{key}/v1/modules/hashicorp/consul/aws/1.2.3/download",
                key = fx.repo_key
            )),
        )
        .await;
        let advertised = doc_headers
            .get("X-Terraform-Get")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        // The router under test is not mounted at the prefix.
        let archive_path = advertised
            .strip_prefix(MOUNT_PREFIX)
            .unwrap_or(&advertised)
            .to_string();
        let (status, body, headers) = tdh::send_with_headers(
            tdh::router_anon(super::router(), state),
            tdh::get(archive_path),
        )
        .await;
        fx.teardown().await;

        assert_eq!(doc_status, axum::http::StatusCode::NO_CONTENT);
        // The location named no type, so the bytes decided it.
        assert_eq!(
            advertised,
            format!(
                "/terraform/{}/v1/modules/hashicorp/consul/aws/1.2.3/archive?archive=zip",
                fx.repo_key
            )
        );
        assert_eq!(status, axum::http::StatusCode::OK);
        assert_eq!(&body[..], blob, "streamed body must equal upstream bytes");
        assert_eq!(headers["content-type"], "application/zip");
    }

    /// #4590: the hint comes from the upstream location when it names one (a
    /// JSON `location` body here, the newer protocol form), and a `//subdir`
    /// survives onto AK's location.
    #[tokio::test]
    async fn test_remote_module_hint_from_upstream_location_4590() {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(fx) = tdh::Fixture::setup("remote", "terraform").await else {
            return;
        };
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/modules/acme/net/aws/2.0.0/download"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "location": "./blob//modules/vpc?archive=tar.gz"
            })))
            .mount(&server)
            .await;

        let (state, _cache) = tdh::rewire_remote_proxy(&fx, &server.uri()).await;
        let (status, _, headers) = tdh::send_with_headers(
            tdh::router_anon(super::router(), state),
            tdh::get(format!(
                "/{key}/v1/modules/acme/net/aws/2.0.0/download",
                key = fx.repo_key
            )),
        )
        .await;
        let requests = server.received_requests().await.unwrap_or_default();
        fx.teardown().await;

        assert_eq!(status, axum::http::StatusCode::NO_CONTENT);
        assert_eq!(
            headers["X-Terraform-Get"],
            format!(
                "/terraform/{}/v1/modules/acme/net/aws/2.0.0/archive//modules/vpc?archive=tar.gz",
                fx.repo_key
            )
            .as_str()
        );
        // A named type needs no sniffing fetch of the archive.
        assert_eq!(requests.len(), 1, "only the location document is fetched");
    }

    /// #4590: a source AK does not proxy (a `git::` address) goes to the client
    /// as the upstream wrote it, and `/archive` refuses it rather than guess.
    #[tokio::test]
    async fn test_remote_module_git_source_passes_through_4590() {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(fx) = tdh::Fixture::setup("remote", "terraform").await else {
            return;
        };
        let server = MockServer::start().await;
        let git = "git::https://github.com/acme/terraform-aws-net?ref=v3.0.0";
        Mock::given(method("GET"))
            .and(path("/v1/modules/acme/net/aws/3.0.0/download"))
            .respond_with(ResponseTemplate::new(204).insert_header("X-Terraform-Get", git))
            .mount(&server)
            .await;

        let (state, _cache) = tdh::rewire_remote_proxy(&fx, &server.uri()).await;
        let (status, _, headers) = tdh::send_with_headers(
            tdh::router_anon(super::router(), state.clone()),
            tdh::get(format!(
                "/{key}/v1/modules/acme/net/aws/3.0.0/download",
                key = fx.repo_key
            )),
        )
        .await;
        let (archive_status, _) = tdh::send(
            tdh::router_anon(super::router(), state),
            tdh::get(format!(
                "/{key}/v1/modules/acme/net/aws/3.0.0/archive?archive=zip",
                key = fx.repo_key
            )),
        )
        .await;
        fx.teardown().await;

        assert_eq!(status, axum::http::StatusCode::NO_CONTENT);
        assert_eq!(headers["X-Terraform-Get"], git);
        assert_eq!(archive_status, axum::http::StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_remote_provider_download_streams_upstream_blob_1608() {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(fx) = tdh::Fixture::setup("remote", "terraform").await else {
            return;
        };
        let server = MockServer::start().await;
        // A small deterministic body stands in for a large artifact; the point
        // is to exercise the streaming pull-through branch (proxy_fetch_streaming)
        // added in #1608 Phase 4, not the body size.
        let blob: &[u8] = b"\x00\x01\x02 #1608 phase4 streamed proxy blob \x03\x04\x05";
        Mock::given(method("GET"))
            .and(path(
                "/v1/providers/hashicorp/aws/1.2.3/download/linux/amd64",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(blob))
            .mount(&server)
            .await;

        let (state, _cache) = tdh::rewire_remote_proxy(&fx, &server.uri()).await;
        let app = tdh::router_anon(super::router(), state);
        let (status, body) = tdh::send(
            app,
            tdh::get(format!(
                "/{key}/v1/providers/hashicorp/aws/1.2.3/download/linux/amd64",
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

    // NOTE: `build_module_archive_url`, `build_provider_binary_url`,
    // `build_provider_filename` and `build_platform` are the production
    // functions (via `use super::*`). This module used to carry private copies
    // of them, so their tests only ever asserted that a test-local `format!`
    // matched a literal — which is why the advertised-but-unrouted
    // `download_url` went unnoticed. The copies are gone; the tests below
    // exercise the real builders, and `test_advertised_*` asserts the
    // resulting URLs against the real router.

    // -----------------------------------------------------------------------
    // default_offset / default_limit
    // -----------------------------------------------------------------------

    #[test]
    fn test_default_offset() {
        assert_eq!(default_offset(), 0);
    }

    #[test]
    fn test_default_limit() {
        assert_eq!(default_limit(), 10);
    }

    // -----------------------------------------------------------------------
    // SearchQuery deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_search_query_defaults() {
        let q: SearchQuery = serde_json::from_str(r#"{}"#).unwrap();
        assert!(q.q.is_none());
        assert_eq!(q.offset, 0);
        assert_eq!(q.limit, 10);
    }

    #[test]
    fn test_search_query_with_values() {
        let q: SearchQuery =
            serde_json::from_str(r#"{"q":"my-module","offset":5,"limit":20}"#).unwrap();
        assert_eq!(q.q, Some("my-module".to_string()));
        assert_eq!(q.offset, 5);
        assert_eq!(q.limit, 20);
    }

    // -----------------------------------------------------------------------
    // RepoInfo struct construction
    // -----------------------------------------------------------------------

    #[test]
    fn test_repo_info_construction() {
        let id = uuid::Uuid::new_v4();
        let info = RepoInfo {
            id,
            key: String::new(),
            storage_path: "/data/terraform".to_string(),
            storage_backend: "filesystem".to_string(),
            repo_type: "hosted".to_string(),
            upstream_url: Some("https://registry.terraform.io".to_string()),
            format: "generic".to_string(),
            promotion_only: false,
            age_gate_enabled: false,
            age_gate_min_age_days: 7,
            age_gate_mode: "upstream_publish_time".to_string(),
            curation_enabled: false,
            curation_default_action: "allow".to_string(),
        };
        assert_eq!(info.id, id);
        assert_eq!(info.storage_path, "/data/terraform");
        assert_eq!(info.repo_type, "hosted");
        assert_eq!(
            info.upstream_url,
            Some("https://registry.terraform.io".to_string())
        );
    }

    #[test]
    fn test_repo_info_no_upstream() {
        let info = RepoInfo {
            id: uuid::Uuid::new_v4(),
            key: String::new(),
            storage_path: "/data/tf".to_string(),
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
        assert!(info.upstream_url.is_none());
    }

    // -----------------------------------------------------------------------
    // Module name formatting
    // -----------------------------------------------------------------------

    #[test]
    fn test_module_name_format() {
        let namespace = "hashicorp";
        let name = "consul";
        let provider = "aws";
        let module_name = format!("{}/{}/{}", namespace, name, provider);
        assert_eq!(module_name, "hashicorp/consul/aws");
    }

    #[test]
    fn test_provider_name_format() {
        let namespace = "hashicorp";
        let type_name = "aws";
        let provider_name = format!("{}/{}", namespace, type_name);
        assert_eq!(provider_name, "hashicorp/aws");
    }

    // -----------------------------------------------------------------------
    // Storage key formatting
    // -----------------------------------------------------------------------

    #[test]
    fn test_module_storage_key_format() {
        let namespace = "hashicorp";
        let name = "consul";
        let provider = "aws";
        let version = "0.1.0";
        let storage_key = format!(
            "terraform/modules/{}/{}/{}/{}.tar.gz",
            namespace, name, provider, version
        );
        assert_eq!(
            storage_key,
            "terraform/modules/hashicorp/consul/aws/0.1.0.tar.gz"
        );
    }

    #[test]
    fn test_provider_storage_key_format() {
        let namespace = "hashicorp";
        let type_name = "aws";
        let version = "5.0.0";
        let platform = "linux_amd64";
        let storage_key = format!(
            "terraform/providers/{}/{}/{}/terraform-provider-{}_{}.zip",
            namespace, type_name, version, type_name, platform
        );
        assert_eq!(
            storage_key,
            "terraform/providers/hashicorp/aws/5.0.0/terraform-provider-aws_linux_amd64.zip"
        );
    }

    // -----------------------------------------------------------------------
    // SHA-256 checksum computation
    // -----------------------------------------------------------------------

    #[test]
    fn test_sha256_computation() {
        let data = b"terraform module content";
        let mut hasher = Sha256::new();
        hasher.update(data);
        let checksum = format!("{:x}", hasher.finalize());
        assert_eq!(checksum.len(), 64);
        assert!(checksum.chars().all(|c| c.is_ascii_hexdigit()));
    }

    // -----------------------------------------------------------------------
    // Platform path formatting
    // -----------------------------------------------------------------------

    #[test]
    fn test_platform_path() {
        let os = "linux";
        let arch = "amd64";
        let platform_path = format!("{}_{}", os, arch);
        assert_eq!(platform_path, "linux_amd64");
    }

    #[test]
    fn test_provider_filename_format() {
        let type_name = "aws";
        let version = "5.0.0";
        let platform_path = "linux_amd64";
        let filename = format!(
            "terraform-provider-{}_{}_{}.zip",
            type_name, version, platform_path
        );
        assert_eq!(filename, "terraform-provider-aws_5.0.0_linux_amd64.zip");
    }

    // -----------------------------------------------------------------------
    // Download URL formatting
    // -----------------------------------------------------------------------

    #[test]
    fn test_module_download_url_format() {
        let repo_key = "my-terraform";
        let namespace = "hashicorp";
        let name = "consul";
        let provider = "aws";
        let version = "0.1.0";
        let download_url = format!(
            "/terraform/{}/v1/modules/{}/{}/{}/{}/archive",
            repo_key, namespace, name, provider, version
        );
        assert_eq!(
            download_url,
            "/terraform/my-terraform/v1/modules/hashicorp/consul/aws/0.1.0/archive"
        );
    }

    #[test]
    fn test_provider_download_url_format() {
        let repo_key = "my-terraform";
        let namespace = "hashicorp";
        let type_name = "aws";
        let version = "5.0.0";
        let os = "linux";
        let arch = "amd64";
        let download_url = format!(
            "/terraform/{}/v1/providers/{}/{}/{}/binary/{}/{}",
            repo_key, namespace, type_name, version, os, arch
        );
        assert_eq!(
            download_url,
            "/terraform/my-terraform/v1/providers/hashicorp/aws/5.0.0/binary/linux/amd64"
        );
    }

    // -----------------------------------------------------------------------
    // Service discovery JSON structure
    // -----------------------------------------------------------------------

    #[test]
    fn test_service_discovery_json() {
        let repo_key = "my-tf-repo";
        let json = serde_json::json!({
            "modules.v1": format!("/terraform/{}/v1/modules/", repo_key),
            "providers.v1": format!("/terraform/{}/v1/providers/", repo_key),
        });
        assert_eq!(json["modules.v1"], "/terraform/my-tf-repo/v1/modules/");
        assert_eq!(json["providers.v1"], "/terraform/my-tf-repo/v1/providers/");
    }

    // -----------------------------------------------------------------------
    // Metadata JSON structure
    // -----------------------------------------------------------------------

    #[test]
    fn test_module_metadata_json() {
        let namespace = "hashicorp";
        let name = "consul";
        let provider = "aws";
        let version = "0.1.0";
        let metadata = serde_json::json!({
            "kind": "module",
            "namespace": namespace,
            "name": name,
            "provider": provider,
            "version": version,
        });
        assert_eq!(metadata["kind"], "module");
        assert_eq!(metadata["namespace"], "hashicorp");
    }

    #[test]
    fn test_provider_metadata_json() {
        let metadata = serde_json::json!({
            "kind": "provider",
            "namespace": "hashicorp",
            "type": "aws",
            "version": "5.0.0",
            "os": "linux",
            "arch": "amd64",
        });
        assert_eq!(metadata["kind"], "provider");
        assert_eq!(metadata["os"], "linux");
        assert_eq!(metadata["arch"], "amd64");
    }

    // -----------------------------------------------------------------------
    // Search results module name parsing
    // -----------------------------------------------------------------------

    #[test]
    fn test_module_name_parsing_three_parts() {
        let name = "hashicorp/consul/aws";
        let parts: Vec<&str> = name.splitn(3, '/').collect();
        let (ns, n, p) = match parts.as_slice() {
            [ns, n, p] => (ns.to_string(), n.to_string(), p.to_string()),
            _ => (name.to_string(), String::new(), String::new()),
        };
        assert_eq!(ns, "hashicorp");
        assert_eq!(n, "consul");
        assert_eq!(p, "aws");
    }

    #[test]
    fn test_module_name_parsing_one_part() {
        let name = "single-name";
        let parts: Vec<&str> = name.splitn(3, '/').collect();
        let (ns, n, p) = match parts.as_slice() {
            [ns, n, p] => (ns.to_string(), n.to_string(), p.to_string()),
            _ => (name.to_string(), String::new(), String::new()),
        };
        assert_eq!(ns, "single-name");
        assert_eq!(n, "");
        assert_eq!(p, "");
    }

    #[test]
    fn test_module_name_parsing_two_parts() {
        let name = "vendor/module";
        let parts: Vec<&str> = name.splitn(3, '/').collect();
        let (ns, n, p) = match parts.as_slice() {
            [ns, n, p] => (ns.to_string(), n.to_string(), p.to_string()),
            _ => (name.to_string(), String::new(), String::new()),
        };
        // With only 2 parts, we fall through to the default case
        assert_eq!(ns, "vendor/module");
        assert_eq!(n, "");
        assert_eq!(p, "");
    }

    // -----------------------------------------------------------------------
    // Version list response structure
    // -----------------------------------------------------------------------

    #[test]
    fn test_version_list_json_structure() {
        let versions = vec!["0.1.0", "0.2.0", "1.0.0"];
        let version_list: Vec<serde_json::Value> = versions
            .into_iter()
            .map(|v| serde_json::json!({ "version": v }))
            .collect();
        let json = serde_json::json!({
            "modules": [{
                "versions": version_list,
            }]
        });
        let modules = json["modules"].as_array().unwrap();
        assert_eq!(modules.len(), 1);
        let inner_versions = modules[0]["versions"].as_array().unwrap();
        assert_eq!(inner_versions.len(), 3);
        assert_eq!(inner_versions[0]["version"], "0.1.0");
    }

    // -----------------------------------------------------------------------
    // Provider version grouping logic
    // -----------------------------------------------------------------------

    #[test]
    fn test_provider_version_platform_grouping() {
        let mut version_map: std::collections::BTreeMap<String, Vec<serde_json::Value>> =
            std::collections::BTreeMap::new();

        let platforms = version_map.entry("1.0.0".to_string()).or_default();
        let p1 = serde_json::json!({"os": "linux", "arch": "amd64"});
        let p2 = serde_json::json!({"os": "darwin", "arch": "arm64"});
        platforms.push(p1.clone());
        platforms.push(p2.clone());

        // Verify dedup check
        assert!(platforms.contains(&p1));
        assert!(platforms.contains(&p2));
        assert_eq!(platforms.len(), 2);
    }

    #[test]
    fn test_provider_empty_platforms_default() {
        let platforms: Vec<serde_json::Value> = vec![];
        let result = if platforms.is_empty() {
            vec![serde_json::json!({"os": "linux", "arch": "amd64"})]
        } else {
            platforms
        };
        assert_eq!(result.len(), 1);
        assert_eq!(result[0]["os"], "linux");
        assert_eq!(result[0]["arch"], "amd64");
    }

    // -----------------------------------------------------------------------
    // build_service_discovery_json
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_service_discovery_json_basic() {
        let json = build_service_discovery_json("my-tf-repo");
        assert_eq!(json["modules.v1"], "/terraform/my-tf-repo/v1/modules/");
        assert_eq!(json["providers.v1"], "/terraform/my-tf-repo/v1/providers/");
    }

    #[test]
    fn test_build_service_discovery_json_different_key() {
        let json = build_service_discovery_json("prod-registry");
        assert!(json["modules.v1"]
            .as_str()
            .unwrap()
            .contains("prod-registry"));
    }

    // -----------------------------------------------------------------------
    // build_module_name / build_provider_name
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_module_name() {
        assert_eq!(
            build_module_name("hashicorp", "consul", "aws"),
            "hashicorp/consul/aws"
        );
    }

    #[test]
    fn test_build_provider_name() {
        assert_eq!(build_provider_name("hashicorp", "aws"), "hashicorp/aws");
    }

    // -----------------------------------------------------------------------
    // build_module_archive_url / build_provider_binary_url
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_module_archive_url() {
        // #4590: the hint is what makes go-getter unpack the location as an
        // archive instead of parsing it as an HTML page.
        let url = build_module_archive_url(
            "repo",
            "ns",
            "name",
            "prov",
            "1.0.0",
            ModuleArchiveType::Zip,
            None,
        );
        assert_eq!(
            url,
            "/terraform/repo/v1/modules/ns/name/prov/1.0.0/archive?archive=zip"
        );
        let url = build_module_archive_url(
            "repo",
            "ns",
            "name",
            "prov",
            "1.0.0",
            ModuleArchiveType::TarGz,
            None,
        );
        assert_eq!(
            url,
            "/terraform/repo/v1/modules/ns/name/prov/1.0.0/archive?archive=tar.gz"
        );
        let url = build_module_archive_url(
            "repo",
            "ns",
            "name",
            "prov",
            "1.0.0",
            ModuleArchiveType::Tar,
            None,
        );
        assert_eq!(
            url,
            "/terraform/repo/v1/modules/ns/name/prov/1.0.0/archive?archive=tar"
        );
    }

    #[test]
    fn test_build_module_archive_url_with_subdir_4590() {
        // go-getter splits `//subdir` off before the query and moves the query
        // back onto the source, so the subdir must sit between path and query.
        let url = build_module_archive_url(
            "repo",
            "ns",
            "name",
            "prov",
            "1.0.0",
            ModuleArchiveType::Zip,
            Some("modules/vpc"),
        );
        assert_eq!(
            url,
            "/terraform/repo/v1/modules/ns/name/prov/1.0.0/archive//modules/vpc?archive=zip"
        );
        assert_eq!(
            split_getter_subdir(&url),
            (
                "/terraform/repo/v1/modules/ns/name/prov/1.0.0/archive?archive=zip".to_string(),
                Some("modules/vpc".to_string())
            )
        );
        // An empty subdir is no subdir.
        assert!(!build_module_archive_url(
            "repo",
            "ns",
            "name",
            "prov",
            "1.0.0",
            ModuleArchiveType::Zip,
            Some("")
        )
        .contains("//"));
    }

    // -----------------------------------------------------------------------
    // #4590: module archive sniffing, upload classification, upstream hints
    // -----------------------------------------------------------------------

    /// A 512-byte POSIX tar header block with the `ustar` magic at 257.
    fn tar_header() -> Vec<u8> {
        let mut block = vec![0u8; 512];
        block[..7].copy_from_slice(b"main.tf");
        block[257..263].copy_from_slice(b"ustar\0");
        block
    }

    #[test]
    fn test_module_archive_sniff_4590() {
        assert_eq!(
            ModuleArchiveType::sniff(b"PK\x03\x04rest-of-zip"),
            Some(ModuleArchiveType::Zip)
        );
        assert_eq!(
            ModuleArchiveType::sniff(&[0x1f, 0x8b, 0x08, 0x00]),
            Some(ModuleArchiveType::TarGz)
        );
        assert_eq!(
            ModuleArchiveType::sniff(&tar_header()),
            Some(ModuleArchiveType::Tar)
        );
        // A tar header cut short of the magic is not recognised.
        assert_eq!(ModuleArchiveType::sniff(&tar_header()[..260]), None);
        // Empty-archive ZIP marker, HTML, plain text, empty: none of ours.
        assert_eq!(ModuleArchiveType::sniff(b"PK\x05\x06"), None);
        assert_eq!(ModuleArchiveType::sniff(b"<html><head>"), None);
        assert_eq!(ModuleArchiveType::sniff(b"module-archive-bytes"), None);
        assert_eq!(ModuleArchiveType::sniff(b""), None);
        assert_eq!(ModuleArchiveType::sniff(&[0x1f]), None);
    }

    #[test]
    fn test_module_archive_type_names_4590() {
        for (archive, hint, ct) in [
            (ModuleArchiveType::Zip, "zip", "application/zip"),
            (ModuleArchiveType::TarGz, "tar.gz", "application/gzip"),
            (ModuleArchiveType::Tar, "tar", "application/x-tar"),
        ] {
            assert_eq!(archive.getter_hint(), hint);
            assert_eq!(archive.extension(), hint);
            assert_eq!(archive.content_type(), ct);
            assert_eq!(ModuleArchiveType::from_getter_hint(hint), Some(archive));
            assert_eq!(
                ModuleArchiveType::from_metadata(&serde_json::json!({ "archive_type": hint })),
                Some(archive)
            );
        }
        assert_eq!(
            ModuleArchiveType::from_getter_hint("TGZ"),
            Some(ModuleArchiveType::TarGz)
        );
        assert_eq!(ModuleArchiveType::from_getter_hint("tar.xz"), None);
        assert_eq!(ModuleArchiveType::from_getter_hint("false"), None);
        // A module uploaded before #4590 has no recorded type.
        assert_eq!(
            ModuleArchiveType::from_metadata(&serde_json::json!({ "kind": "module" })),
            None
        );
    }

    #[test]
    fn test_classify_module_upload_4590() {
        assert_eq!(
            classify_module_upload(b"PK\x03\x04..."),
            Ok(ModuleArchiveType::Zip)
        );
        assert_eq!(
            classify_module_upload(&[0x1f, 0x8b, 0x08]),
            Ok(ModuleArchiveType::TarGz)
        );
        let tar = classify_module_upload(&tar_header()).unwrap_err();
        assert!(tar.contains("uncompressed tar"), "{tar}");
        let junk = classify_module_upload(b"module-archive-bytes").unwrap_err();
        assert!(junk.contains("not a ZIP or gzip-compressed tar"), "{junk}");
        assert!(classify_module_upload(b"").is_err());
    }

    #[test]
    fn test_module_coords_filename_follows_type_4590() {
        let c = ModuleCoords {
            namespace: "acme",
            name: "demo",
            provider: "aws",
            version: "1.0.0",
        };
        assert_eq!(
            c.filename(Some(ModuleArchiveType::Zip)),
            "acme-demo-aws-1.0.0.zip"
        );
        assert_eq!(
            c.filename(Some(ModuleArchiveType::TarGz)),
            "acme-demo-aws-1.0.0.tar.gz"
        );
        assert_eq!(c.filename(None), "acme-demo-aws-1.0.0");
        assert_eq!(
            c.archive_cache_path(),
            "v1/modules/acme/demo/aws/1.0.0/archive"
        );
        assert_eq!(
            c.upstream_download_path(),
            "v1/modules/acme/demo/aws/1.0.0/download"
        );
    }

    #[tokio::test]
    async fn test_peek_module_archive_replays_every_byte_4590() {
        use futures::StreamExt;
        // The magic arrives split across chunks and the body continues past
        // the sniff window: the type is still found and nothing is lost.
        let mut tar = tar_header();
        tar.extend_from_slice(b"trailing body bytes");
        let chunks: Vec<crate::error::Result<Bytes>> = tar
            .chunks(100)
            .map(|c| Ok(Bytes::copy_from_slice(c)))
            .collect();
        let (archive, body) = peek_module_archive(futures::stream::iter(chunks).boxed()).await;
        assert_eq!(archive, Some(ModuleArchiveType::Tar));
        let replayed: Vec<u8> = body
            .map(|c| c.unwrap().to_vec())
            .collect::<Vec<_>>()
            .await
            .concat();
        assert_eq!(replayed, tar);

        // A body shorter than the window ends cleanly.
        let short: Vec<crate::error::Result<Bytes>> = vec![Ok(Bytes::from_static(b"PK\x03\x04z"))];
        let (archive, body) = peek_module_archive(futures::stream::iter(short).boxed()).await;
        assert_eq!(archive, Some(ModuleArchiveType::Zip));
        assert_eq!(body.collect::<Vec<_>>().await.len(), 1);

        // A stream error is replayed, not swallowed.
        let failing: Vec<crate::error::Result<Bytes>> = vec![
            Ok(Bytes::from_static(&[0x1f, 0x8b])),
            Err(crate::error::AppError::BadGateway("cut".into())),
        ];
        let (archive, body) = peek_module_archive(futures::stream::iter(failing).boxed()).await;
        assert_eq!(archive, Some(ModuleArchiveType::TarGz));
        let items = body.collect::<Vec<_>>().await;
        assert_eq!(items.len(), 2);
        assert!(items[1].is_err());
    }

    #[test]
    fn test_split_getter_subdir_4590() {
        assert_eq!(
            split_getter_subdir("https://h/a.zip"),
            ("https://h/a.zip".to_string(), None)
        );
        assert_eq!(
            split_getter_subdir("https://h/a.zip//sub/dir?archive=zip"),
            (
                "https://h/a.zip?archive=zip".to_string(),
                Some("sub/dir".to_string())
            )
        );
        assert_eq!(
            split_getter_subdir("/rel/a.tgz//mod"),
            ("/rel/a.tgz".to_string(), Some("mod".to_string()))
        );
        // A `//` inside the query is not a subdir.
        assert_eq!(
            split_getter_subdir("https://h/a?u=https://x"),
            ("https://h/a?u=https://x".to_string(), None)
        );
    }

    #[test]
    fn test_getter_extension_4590() {
        assert_eq!(
            getter_extension("/m/x.ZIP"),
            GetterExtension::Known(ModuleArchiveType::Zip)
        );
        assert_eq!(
            getter_extension("/m/x.tar.gz"),
            GetterExtension::Known(ModuleArchiveType::TarGz)
        );
        assert_eq!(
            getter_extension("/m/x.tgz"),
            GetterExtension::Known(ModuleArchiveType::TarGz)
        );
        assert_eq!(getter_extension("/m/x.tar.xz"), GetterExtension::Foreign);
        assert_eq!(getter_extension("/m/x.tar.bz2"), GetterExtension::Foreign);
        assert_eq!(getter_extension("/m/archive"), GetterExtension::None);
        // Plain `.tar` is not a go-getter extension at all.
        assert_eq!(getter_extension("/m/x.tar"), GetterExtension::None);
    }

    #[test]
    fn test_classify_upstream_module_location_4590() {
        let base = "https://reg.example/v1/modules/acme/demo/aws/1.0.0/download";

        // Relative location with an extension: resolved against the answering
        // URL, typed from the extension.
        assert_eq!(
            classify_upstream_module_location("/files/demo.zip", base),
            UpstreamModuleSource::Http {
                fetch_url: "https://reg.example/files/demo.zip".into(),
                subdir: None,
                archive: Some(ModuleArchiveType::Zip),
                absolute: "https://reg.example/files/demo.zip".into(),
            }
        );

        // `archive=` wins over the extension, is stripped from the fetch URL,
        // and other query parameters (a signature) survive.
        assert_eq!(
            classify_upstream_module_location(
                "https://cdn.example/blob?sig=abc&archive=tar.gz",
                base
            ),
            UpstreamModuleSource::Http {
                fetch_url: "https://cdn.example/blob?sig=abc".into(),
                subdir: None,
                archive: Some(ModuleArchiveType::TarGz),
                absolute: "https://cdn.example/blob?sig=abc&archive=tar.gz".into(),
            }
        );

        // A query without a hint is left exactly as the upstream sent it.
        assert_eq!(
            classify_upstream_module_location(
                "https://cdn.example/m.tgz?X-Amz-Signature=a%2Fb",
                base
            ),
            UpstreamModuleSource::Http {
                fetch_url: "https://cdn.example/m.tgz?X-Amz-Signature=a%2Fb".into(),
                subdir: None,
                archive: Some(ModuleArchiveType::TarGz),
                absolute: "https://cdn.example/m.tgz?X-Amz-Signature=a%2Fb".into(),
            }
        );

        // Subdir is carried separately.
        assert_eq!(
            classify_upstream_module_location("https://cdn.example/m.zip//modules/vpc", base),
            UpstreamModuleSource::Http {
                fetch_url: "https://cdn.example/m.zip".into(),
                subdir: Some("modules/vpc".into()),
                archive: Some(ModuleArchiveType::Zip),
                absolute: "https://cdn.example/m.zip//modules/vpc".into(),
            }
        );

        // No type named: the bytes will decide.
        assert_eq!(
            classify_upstream_module_location("https://cdn.example/latest", base),
            UpstreamModuleSource::Http {
                fetch_url: "https://cdn.example/latest".into(),
                subdir: None,
                archive: None,
                absolute: "https://cdn.example/latest".into(),
            }
        );

        // Forced getters, other schemes, foreign archive types, an explicit
        // `archive=false` and plain tar go to the client unchanged (absolute).
        for (loc, want) in [
            (
                "git::https://github.com/acme/demo?ref=v1.0.0",
                "git::https://github.com/acme/demo?ref=v1.0.0",
            ),
            (
                "s3::https://s3.amazonaws.com/b/m.zip",
                "s3::https://s3.amazonaws.com/b/m.zip",
            ),
            ("github.com/acme/demo", "github.com/acme/demo"),
            ("ftp://files.example/m.zip", "ftp://files.example/m.zip"),
            (
                "https://cdn.example/m.tar.xz",
                "https://cdn.example/m.tar.xz",
            ),
            (
                "https://cdn.example/m?archive=false",
                "https://cdn.example/m?archive=false",
            ),
            (
                "https://cdn.example/m?archive=tar",
                "https://cdn.example/m?archive=tar",
            ),
            ("/m.tar.bz2", "https://reg.example/m.tar.bz2"),
        ] {
            assert_eq!(
                classify_upstream_module_location(loc, base),
                UpstreamModuleSource::Passthrough(want.into()),
                "{loc}"
            );
        }
    }

    #[test]
    fn test_upstream_module_location_value_4590() {
        assert_eq!(
            upstream_module_location_value(Some(" /a.zip "), b""),
            Some("/a.zip".into())
        );
        // Header wins over a JSON body.
        assert_eq!(
            upstream_module_location_value(Some("/h.zip"), br#"{"location":"/b.zip"}"#),
            Some("/h.zip".into())
        );
        assert_eq!(
            upstream_module_location_value(None, br#"{"location":"/b.zip"}"#),
            Some("/b.zip".into())
        );
        assert_eq!(upstream_module_location_value(Some(""), b""), None);
        assert_eq!(upstream_module_location_value(None, b"not json"), None);
        assert_eq!(
            upstream_module_location_value(None, br#"{"location":""}"#),
            None
        );
    }

    #[test]
    fn test_same_origin_4590() {
        assert!(same_origin(
            "https://r.example/a",
            "https://r.example:443/b"
        ));
        assert!(!same_origin("https://r.example/a", "http://r.example/a"));
        assert!(!same_origin("https://r.example/a", "https://cdn.example/a"));
        assert!(!same_origin("not a url", "https://r.example"));
    }

    #[test]
    fn test_build_provider_binary_url() {
        let url = build_provider_binary_url("repo", "ns", "aws", "5.0.0", "linux", "amd64");
        assert_eq!(
            url,
            "/terraform/repo/v1/providers/ns/aws/5.0.0/binary/linux/amd64"
        );
    }

    // -----------------------------------------------------------------------
    // build_provider_filename / build_platform
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_provider_filename() {
        assert_eq!(
            build_provider_filename("aws", "5.0.0", "linux_amd64"),
            "terraform-provider-aws_5.0.0_linux_amd64.zip"
        );
    }

    #[test]
    fn test_build_platform() {
        assert_eq!(build_platform("linux", "amd64"), "linux_amd64");
        assert_eq!(build_platform("darwin", "arm64"), "darwin_arm64");
    }

    // -----------------------------------------------------------------------
    // build_module_storage_key / build_provider_storage_key
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_module_storage_key() {
        assert_eq!(
            build_module_storage_key("hashicorp", "consul", "aws", "0.1.0"),
            "terraform/modules/hashicorp/consul/aws/0.1.0.tar.gz"
        );
    }

    #[test]
    fn test_build_provider_storage_key() {
        assert_eq!(
            build_provider_storage_key("hashicorp", "aws", "5.0.0", "linux_amd64"),
            "terraform/providers/hashicorp/aws/5.0.0/terraform-provider-aws_linux_amd64.zip"
        );
    }

    // -----------------------------------------------------------------------
    // build_module_artifact_path / build_provider_artifact_path
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_module_artifact_path() {
        assert_eq!(
            build_module_artifact_path("hashicorp", "consul", "aws", "0.1.0"),
            "hashicorp/consul/aws/0.1.0"
        );
    }

    #[test]
    fn test_build_provider_artifact_path() {
        assert_eq!(
            build_provider_artifact_path("hashicorp", "aws", "5.0.0", "linux", "amd64"),
            "hashicorp/aws/5.0.0/linux_amd64"
        );
    }

    #[test]
    fn test_upload_artifact_path_traversal_rejected() {
        // GHSA-vcq6-8hxw-4q67: `PUT /v1/modules/acme/victim/aws/%2e%2e%2f%2e%2e%2fx`
        // stored `acme/victim/aws/../../x` on 1.9.0 (axum percent-decodes the
        // captures before the handler sees them). The composed path is now
        // routed through validate_artifact_path in upload_module and
        // upload_provider.
        for (ns, name, provider, version) in [
            ("acme", "victim", "aws", "../../x"),
            ("..", "mod", "aws", "1.0.0"),
            ("acme", "mod", "aws", "%2e%2e%2f%2e%2e%2fx"),
        ] {
            let path = build_module_artifact_path(ns, name, provider, version);
            assert!(
                crate::services::upload_service::validate_artifact_path(&path).is_err(),
                "composed module path {path:?} must be rejected"
            );
        }
        let (ns, ty, version, os, arch) = ("acme", "aws", "../..", "linux", "amd64");
        let path = build_provider_artifact_path(ns, ty, version, os, arch);
        assert!(
            crate::services::upload_service::validate_artifact_path(&path).is_err(),
            "composed provider path {path:?} must be rejected"
        );
        assert!(crate::services::upload_service::validate_artifact_path(
            &build_module_artifact_path("acme", "victim", "aws", "1.0.0")
        )
        .is_ok());
        assert!(crate::services::upload_service::validate_artifact_path(
            &build_provider_artifact_path("hashicorp", "aws", "5.0.0", "linux", "amd64")
        )
        .is_ok());
    }

    // -----------------------------------------------------------------------
    // build_module_metadata / build_provider_metadata
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_module_metadata() {
        let meta = build_module_metadata(
            "hashicorp",
            "consul",
            "aws",
            "0.1.0",
            ModuleArchiveType::Zip,
        );
        assert_eq!(meta["archive_type"], "zip");
        assert_eq!(meta["kind"], "module");
        assert_eq!(meta["namespace"], "hashicorp");
        assert_eq!(meta["name"], "consul");
        assert_eq!(meta["provider"], "aws");
        assert_eq!(meta["version"], "0.1.0");
    }

    #[test]
    fn test_build_provider_metadata() {
        let meta = build_provider_metadata("hashicorp", "aws", "5.0.0", "linux", "amd64", None);
        assert_eq!(meta["kind"], "provider");
        assert_eq!(meta["namespace"], "hashicorp");
        assert_eq!(meta["type"], "aws");
        assert_eq!(meta["os"], "linux");
        assert_eq!(meta["arch"], "amd64");
        // Undeclared protocols are not recorded, so the package stays
        // indistinguishable from one uploaded before protocols were tracked.
        assert!(meta.get("protocols").is_none());
    }

    #[test]
    fn test_build_provider_metadata_records_declared_protocols() {
        let protocols = vec!["5.0".to_string(), "6.0".to_string()];
        let meta = build_provider_metadata("a", "b", "1.0.0", "linux", "arm64", Some(&protocols));
        assert_eq!(meta["protocols"], serde_json::json!(["5.0", "6.0"]));
    }

    // -----------------------------------------------------------------------
    // build_version_list_json
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_version_list_json_basic() {
        let versions = vec![
            "0.1.0".to_string(),
            "0.2.0".to_string(),
            "1.0.0".to_string(),
        ];
        let json = build_version_list_json(&versions);
        let modules = json["modules"].as_array().unwrap();
        assert_eq!(modules.len(), 1);
        let inner = modules[0]["versions"].as_array().unwrap();
        assert_eq!(inner.len(), 3);
        assert_eq!(inner[0]["version"], "0.1.0");
    }

    #[test]
    fn test_build_version_list_json_empty() {
        let json = build_version_list_json(&[]);
        let inner = json["modules"][0]["versions"].as_array().unwrap();
        assert!(inner.is_empty());
    }

    // -----------------------------------------------------------------------
    // build_provider_download_json
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_provider_download_json_basic() {
        let json = build_provider_download_json(
            "linux",
            "amd64",
            "terraform-provider-aws_5.0.0_linux_amd64.zip",
            "/download/url",
            "sha256hash",
            &default_provider_protocols(),
            None,
        );
        assert_eq!(json["os"], "linux");
        assert_eq!(json["arch"], "amd64");
        assert_eq!(json["shasum"], "sha256hash");
        assert!(json["protocols"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!("5.0")));
        assert!(json["signing_keys"]["gpg_public_keys"]
            .as_array()
            .unwrap()
            .is_empty());
    }

    #[test]
    fn test_build_provider_download_json_darwin() {
        let json = build_provider_download_json(
            "darwin",
            "arm64",
            "file.zip",
            "/url",
            "hash",
            &default_provider_protocols(),
            None,
        );
        assert_eq!(json["os"], "darwin");
        assert_eq!(json["arch"], "arm64");
    }

    // -----------------------------------------------------------------------
    // parse_module_name
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_module_name_three_parts() {
        let (ns, n, p) = parse_module_name("hashicorp/consul/aws");
        assert_eq!(ns, "hashicorp");
        assert_eq!(n, "consul");
        assert_eq!(p, "aws");
    }

    #[test]
    fn test_parse_module_name_one_part() {
        let (ns, n, p) = parse_module_name("single");
        assert_eq!(ns, "single");
        assert_eq!(n, "");
        assert_eq!(p, "");
    }

    #[test]
    fn test_parse_module_name_two_parts() {
        let (ns, n, p) = parse_module_name("vendor/module");
        assert_eq!(ns, "vendor/module");
        assert_eq!(n, "");
        assert_eq!(p, "");
    }

    // -----------------------------------------------------------------------
    // build_search_pattern
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_search_pattern_basic() {
        assert_eq!(build_search_pattern("consul"), "%consul%");
    }

    #[test]
    fn test_build_search_pattern_empty() {
        assert_eq!(build_search_pattern(""), "%%");
    }

    #[test]
    fn test_build_search_pattern_special_chars() {
        assert_eq!(build_search_pattern("my-module"), "%my-module%");
    }

    /// #3557. The `?q=` term is bound whole to `name ILIKE $2`, so a `LIKE`
    /// metacharacter typed into the module search must match itself: `%` and
    /// `_` are wildcards otherwise, and a backslash is Postgres's default
    /// escape character.
    #[test]
    fn test_build_search_pattern_escapes_like_metacharacters_3557() {
        assert_eq!(build_search_pattern("100%"), r"%100\%%");
        assert_eq!(build_search_pattern("a_b"), r"%a\_b%");
        assert_eq!(build_search_pattern(r"a\b"), r"%a\\b%");
    }

    // -----------------------------------------------------------------------
    // Provider Network Mirror Protocol (#1566)
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_mirror_version_file_valid() {
        assert_eq!(parse_mirror_version_file("2.0.0.json"), Some("2.0.0"));
        assert_eq!(
            parse_mirror_version_file("1.2.3-rc.1.json"),
            Some("1.2.3-rc.1")
        );
    }

    #[test]
    fn test_parse_mirror_version_file_invalid() {
        assert_eq!(parse_mirror_version_file("index.json"), Some("index"));
        assert_eq!(parse_mirror_version_file("2.0.0"), None);
        assert_eq!(parse_mirror_version_file("foo.txt"), None);
    }

    #[test]
    fn test_build_registry_versions_path() {
        assert_eq!(
            build_registry_versions_path("carlpett", "sops"),
            "v1/providers/carlpett/sops/versions"
        );
    }

    #[test]
    fn test_build_registry_download_path() {
        assert_eq!(
            build_registry_download_path("carlpett", "sops", "1.0.0", "linux", "amd64"),
            "v1/providers/carlpett/sops/1.0.0/download/linux/amd64"
        );
    }

    #[test]
    fn test_build_mirror_archive_url() {
        assert_eq!(
            build_mirror_archive_url("1.0.0", "linux", "amd64", None),
            "1.0.0/download/linux/amd64"
        );
    }

    #[test]
    fn test_registry_versions_to_mirror_index() {
        let registry = serde_json::json!({
            "versions": [
                { "version": "0.7.2", "protocols": ["5.0"], "platforms": [] },
                { "version": "1.0.0", "protocols": ["5.0"], "platforms": [] },
            ]
        });
        let mirror = registry_versions_to_mirror_index(&registry);
        let versions = mirror["versions"].as_object().unwrap();
        assert_eq!(versions.len(), 2);
        assert!(versions.contains_key("0.7.2"));
        assert!(versions.contains_key("1.0.0"));
        // Each value must be an (empty) object per the mirror spec.
        assert!(versions["1.0.0"].is_object());
    }

    #[test]
    fn test_registry_versions_to_mirror_index_empty() {
        let mirror = registry_versions_to_mirror_index(&serde_json::json!({}));
        assert!(mirror["versions"].as_object().unwrap().is_empty());
    }

    #[test]
    fn test_platforms_for_version() {
        let registry = serde_json::json!({
            "versions": [
                {
                    "version": "1.0.0",
                    "platforms": [
                        { "os": "linux", "arch": "amd64" },
                        { "os": "darwin", "arch": "arm64" }
                    ]
                },
                {
                    "version": "2.0.0",
                    "platforms": [ { "os": "windows", "arch": "amd64" } ]
                }
            ]
        });
        let p = platforms_for_version(&registry, "1.0.0");
        assert_eq!(
            p,
            vec![
                ("linux".to_string(), "amd64".to_string()),
                ("darwin".to_string(), "arm64".to_string()),
            ]
        );
        let p2 = platforms_for_version(&registry, "2.0.0");
        assert_eq!(p2, vec![("windows".to_string(), "amd64".to_string())]);
        assert!(platforms_for_version(&registry, "9.9.9").is_empty());
    }

    #[test]
    fn test_platforms_for_version_edge_branches() {
        // Version entry without a `platforms` key, malformed entries, and a
        // platform missing `arch` are all skipped without panicking.
        let registry = serde_json::json!({
            "versions": [
                { "version": "1.0.0" },
                { "version": "1.0.0", "platforms": "not-an-array" },
                { "version": "1.0.0", "platforms": [
                    { "os": "linux" },
                    { "arch": "amd64" },
                    { "os": "linux", "arch": "amd64" }
                ] }
            ]
        });
        assert_eq!(
            platforms_for_version(&registry, "1.0.0"),
            vec![("linux".to_string(), "amd64".to_string())]
        );
        // No `versions` array at all.
        assert!(platforms_for_version(&serde_json::json!({}), "1.0.0").is_empty());
    }

    #[test]
    fn test_registry_shasum_to_mirror_hash() {
        let dl = serde_json::json!({ "shasum": "abc123" });
        assert_eq!(
            registry_shasum_to_mirror_hash(&dl),
            Some("zh:abc123".to_string())
        );
        assert_eq!(
            registry_shasum_to_mirror_hash(&serde_json::json!({ "shasum": "" })),
            None
        );
        assert_eq!(registry_shasum_to_mirror_hash(&serde_json::json!({})), None);
    }

    #[test]
    fn test_build_mirror_archive_entry() {
        let with_hash =
            build_mirror_archive_entry("1.0.0/download/linux/amd64", vec!["zh:abc".to_string()]);
        assert_eq!(with_hash["url"], "1.0.0/download/linux/amd64");
        assert_eq!(with_hash["hashes"][0], "zh:abc");

        let no_hash = build_mirror_archive_entry("u", vec![]);
        assert_eq!(no_hash["url"], "u");
        assert!(no_hash.get("hashes").is_none());
    }

    #[test]
    fn test_classify_mirror_repo_remote_proxies_upstream() {
        assert_eq!(
            classify_mirror_repo("remote", true, true),
            MirrorGuard::Proxy
        );
        assert_eq!(
            classify_mirror_repo("remote", false, true),
            MirrorGuard::NotProxyable
        );
        assert_eq!(
            classify_mirror_repo("remote", true, false),
            MirrorGuard::NotProxyable
        );
    }

    /// A hosted repo mirrors its own uploaded providers, so it needs neither an
    /// upstream nor a proxy service to be servable.
    #[test]
    fn test_classify_mirror_repo_hosted_serves_locally() {
        assert_eq!(
            classify_mirror_repo("local", false, false),
            MirrorGuard::Local
        );
        assert_eq!(
            classify_mirror_repo("staging", false, false),
            MirrorGuard::Local
        );
        assert_eq!(
            classify_mirror_repo("local", true, true),
            MirrorGuard::Local
        );
    }

    #[test]
    fn test_classify_mirror_repo_virtual_unsupported() {
        assert_eq!(
            classify_mirror_repo("virtual", false, false),
            MirrorGuard::Unsupported
        );
        assert_eq!(
            classify_mirror_repo("virtual", true, true),
            MirrorGuard::Unsupported
        );
    }

    /// An unrecognized `repo_type` must not be served as if it were hosted.
    ///
    /// `MirrorGuard::Local` releases the repo's own stored packages, so the
    /// classifier opts each known type in rather than defaulting to it:
    /// `resolve_repo_by_key` yields `""` when the `repo_type` read fails, and a
    /// `RepositoryType` variant added later is unknown to this match. Both must
    /// 404 rather than serve.
    #[test]
    fn test_classify_mirror_repo_unknown_is_unsupported() {
        // The empty string a failed column read produces.
        assert_eq!(
            classify_mirror_repo("", false, false),
            MirrorGuard::Unsupported
        );
        assert_eq!(
            classify_mirror_repo("", true, true),
            MirrorGuard::Unsupported
        );
        // A repository type this match predates.
        assert_eq!(
            classify_mirror_repo("federated", false, false),
            MirrorGuard::Unsupported
        );
        // The DB enum is lowercase; anything else is not a known type.
        assert_eq!(
            classify_mirror_repo("LOCAL", false, false),
            MirrorGuard::Unsupported
        );
    }

    #[test]
    fn test_mirror_guard_error_status() {
        use axum::http::StatusCode;
        assert_eq!(
            mirror_guard_error(MirrorGuard::Unsupported).status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            mirror_guard_error(MirrorGuard::NotProxyable).status(),
            StatusCode::NOT_FOUND
        );
        // Servable variants map to a (degenerate) 404 too; callers never hit them.
        assert_eq!(
            mirror_guard_error(MirrorGuard::Local).status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            mirror_guard_error(MirrorGuard::Proxy).status(),
            StatusCode::NOT_FOUND
        );
    }

    #[test]
    fn test_extract_download_url() {
        let dl = serde_json::json!({ "download_url": "https://example/p.zip" });
        assert_eq!(extract_download_url(&dl), Some("https://example/p.zip"));
        assert_eq!(
            extract_download_url(&serde_json::json!({ "download_url": "" })),
            None
        );
        assert_eq!(extract_download_url(&serde_json::json!({})), None);
        assert_eq!(
            extract_download_url(&serde_json::json!({ "download_url": 5 })),
            None
        );
    }

    #[test]
    fn test_mirror_not_found_status() {
        use axum::http::StatusCode;
        let resp = mirror_not_found("carlpett", "sops", "1.0.0");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn test_version_from_mirror_file() {
        assert_eq!(version_from_mirror_file("2.0.0.json").unwrap(), "2.0.0");
        let err = version_from_mirror_file("nope").unwrap_err();
        assert_eq!(err.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn test_resolve_archive_url() {
        let ok = serde_json::json!({ "download_url": "https://x/p.zip" });
        assert_eq!(resolve_archive_url(&ok).unwrap(), "https://x/p.zip");

        let err = resolve_archive_url(&serde_json::json!({})).unwrap_err();
        assert_eq!(err.status(), StatusCode::BAD_GATEWAY);

        let err2 = resolve_archive_url(&serde_json::json!({ "download_url": "" })).unwrap_err();
        assert_eq!(err2.status(), StatusCode::BAD_GATEWAY);
    }

    /// Regression guard for the SSRF gap found in review of #1998: a
    /// malicious/compromised upstream Terraform registry must not be able to
    /// redirect `mirror_download` at an internal address via `download_url`.
    /// Mirrors `test_build_download_url_rejects_internal_addresses` in
    /// cargo.rs — one realistic bypass case pins the integration; the full
    /// bypass matrix lives in `api::validation::tests`.
    #[test]
    fn test_resolve_archive_url_rejects_ssrf_targets() {
        let metadata =
            serde_json::json!({ "download_url": "http://169.254.169.254/latest/meta-data/" });
        let archive_url = resolve_archive_url(&metadata).unwrap();
        let err = validate_outbound_url(archive_url, "Terraform upstream archive URL")
            .expect_err("cloud metadata download_url must be rejected");
        assert!(
            err.to_string().contains("private/internal network")
                || err.to_string().contains("not allowed"),
            "expected SSRF rejection reason in error message, got: {err}"
        );

        let legit = serde_json::json!({
            "download_url": "https://releases.hashicorp.com/terraform-provider-null/3.2.3/terraform-provider-null_3.2.3_linux_arm64.zip"
        });
        let archive_url = resolve_archive_url(&legit).unwrap();
        assert!(
            validate_outbound_url(archive_url, "Terraform upstream archive URL").is_ok(),
            "legitimate external archive URL should be accepted"
        );
    }

    #[test]
    fn test_mirror_archive_cache_path_strips_signed_url_query_string() {
        // A signed archive URL (e.g. an S3 presigned link) must not leak its
        // query-string credentials into the derived cache path / storage
        // object key.
        let cache_path = mirror_archive_cache_path(
            "hashicorp",
            "null",
            "3.2.3",
            "linux",
            "arm64",
            "https://provider-bucket.s3.amazonaws.com/terraform-provider-null_3.2.3_linux_arm64.zip\
             ?X-Amz-Signature=deadbeef&X-Amz-Credential=AKIAEXAMPLE%2F20260630%2Fus-east-1",
        );
        assert_eq!(
            cache_path,
            "hashicorp/null/3.2.3/linux/arm64/terraform-provider-null_3.2.3_linux_arm64.zip"
        );
        assert!(
            !cache_path.contains("X-Amz"),
            "cache path must not contain signed-URL query material, got: {cache_path}"
        );
    }

    #[test]
    fn test_mirror_archive_cache_path_hashicorp_release_url() {
        // Reproduces the exact #1998 repro: an absolute releases.hashicorp.com
        // archive URL must derive a clean, scheme-less canonical cache path.
        let cache_path = mirror_archive_cache_path(
            "hashicorp",
            "null",
            "3.2.3",
            "linux",
            "arm64",
            "https://releases.hashicorp.com/terraform-provider-null/3.2.3/terraform-provider-null_3.2.3_linux_arm64.zip",
        );
        assert_eq!(
            cache_path,
            "hashicorp/null/3.2.3/linux/arm64/terraform-provider-null_3.2.3_linux_arm64.zip"
        );
    }

    #[test]
    fn test_mirror_archive_cache_path_third_party_host() {
        // OpenTofu-style / third-party mirrors (e.g. a provider hosted on
        // GitHub Releases) serve from a different host and path shape; only
        // the archive's filename should influence the derived cache path.
        let cache_path = mirror_archive_cache_path(
            "carlpett",
            "sops",
            "1.0.0",
            "darwin",
            "arm64",
            "https://github.com/carlpett/terraform-provider-sops/releases/download/v1.0.0/terraform-provider-sops_1.0.0_darwin_arm64.zip",
        );
        assert_eq!(
            cache_path,
            "carlpett/sops/1.0.0/darwin/arm64/terraform-provider-sops_1.0.0_darwin_arm64.zip"
        );
    }

    #[test]
    fn test_mirror_archive_cache_path_trailing_slash_falls_back_to_default_filename() {
        // A URL ending in `/` has no filename segment; falling back to a
        // fixed name avoids producing an empty final path segment.
        let cache_path = mirror_archive_cache_path(
            "hashicorp",
            "null",
            "3.2.3",
            "linux",
            "arm64",
            "https://example.com/download/",
        );
        assert_eq!(cache_path, "hashicorp/null/3.2.3/linux/arm64/provider.zip");
    }

    #[test]
    fn test_mirror_archive_cache_path_accepted_by_cache_storage_key_1998() {
        // Regression guard for #1998: the raw absolute archive URL must NOT
        // be usable as a proxy-cache path (its `https://` scheme's `//`
        // trips the empty-segment guard), but the derived cache path must be.
        use crate::services::proxy_service::ProxyService;

        let archive_url = "https://releases.hashicorp.com/terraform-provider-null/3.2.3/terraform-provider-null_3.2.3_linux_arm64.zip";

        let raw_err = ProxyService::cache_storage_key(
            &crate::services::proxy_cache_scope::ProxyCacheScope::unscoped(),
            "tf-mirror",
            archive_url,
        )
        .unwrap_err();
        assert!(
            raw_err.to_string().contains("empty segments"),
            "raw absolute archive URL must be rejected as a cache path, got: {}",
            raw_err
        );

        let cache_path =
            mirror_archive_cache_path("hashicorp", "null", "3.2.3", "linux", "arm64", archive_url);
        ProxyService::cache_storage_key(
            &crate::services::proxy_cache_scope::ProxyCacheScope::unscoped(),
            "tf-mirror",
            &cache_path,
        )
        .expect("derived cache path must be a valid proxy-cache path");
    }

    #[test]
    fn test_json_ok_response_status_and_type() {
        let resp = json_ok_response(&serde_json::json!({ "a": 1 }));
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get(CONTENT_TYPE).unwrap(),
            "application/json"
        );
    }

    #[test]
    fn test_assemble_mirror_archives_with_and_without_hashes() {
        let platforms = vec![
            ("linux".to_string(), "amd64".to_string()),
            ("darwin".to_string(), "arm64".to_string()),
        ];
        let mut shasums = std::collections::HashMap::new();
        shasums.insert(
            ("linux".to_string(), "amd64".to_string()),
            "zh:abc".to_string(),
        );
        // darwin/arm64 intentionally has no shasum.
        let out = assemble_mirror_archives(
            "1.0.0",
            &platforms,
            &shasums,
            &std::collections::HashMap::new(),
        );
        let archives = out["archives"].as_object().unwrap();
        assert_eq!(archives.len(), 2);

        let lin = &archives["linux_amd64"];
        assert_eq!(lin["url"], "1.0.0/download/linux/amd64");
        assert_eq!(lin["hashes"][0], "zh:abc");

        let dar = &archives["darwin_arm64"];
        assert_eq!(dar["url"], "1.0.0/download/darwin/arm64");
        assert!(dar.get("hashes").is_none());
    }

    #[test]
    fn test_assemble_mirror_archives_empty() {
        let out = assemble_mirror_archives(
            "1.0.0",
            &[],
            &std::collections::HashMap::new(),
            &std::collections::HashMap::new(),
        );
        assert!(out["archives"].as_object().unwrap().is_empty());
    }

    #[test]
    fn test_full_mirror_version_assembly_for_sops() {
        // Mirrors the carlpett/sops flow from #1566 end to end (pure parts):
        // registry versions -> platforms -> archives doc.
        let registry = serde_json::json!({
            "versions": [
                { "version": "1.0.0", "protocols": ["5.0"],
                  "platforms": [ { "os": "linux", "arch": "amd64" } ] }
            ]
        });
        let platforms = platforms_for_version(&registry, "1.0.0");
        assert_eq!(platforms, vec![("linux".to_string(), "amd64".to_string())]);

        let download = serde_json::json!({
            "download_url": "https://github.com/carlpett/terraform-provider-sops/.../sops_1.0.0_linux_amd64.zip",
            "shasum": "deadbeef"
        });
        let mut shasums = std::collections::HashMap::new();
        if let Some(h) = registry_shasum_to_mirror_hash(&download) {
            shasums.insert(("linux".to_string(), "amd64".to_string()), h);
        }
        let archives = assemble_mirror_archives(
            "1.0.0",
            &platforms,
            &shasums,
            &std::collections::HashMap::new(),
        );
        assert_eq!(
            archives["archives"]["linux_amd64"]["url"],
            "1.0.0/download/linux/amd64"
        );
        assert_eq!(
            archives["archives"]["linux_amd64"]["hashes"][0],
            "zh:deadbeef"
        );
        assert_eq!(
            extract_download_url(&download),
            Some("https://github.com/carlpett/terraform-provider-sops/.../sops_1.0.0_linux_amd64.zip")
        );
    }

    #[test]
    fn test_router_builds_without_route_conflicts() {
        // axum panics at construction time on overlapping routes. Building the
        // router proves the network-mirror routes (#1566) coexist with the
        // existing registry routes.
        let _router: Router<SharedState> = router();
    }

    #[test]
    fn test_full_mirror_index_translation_roundtrip() {
        // End-to-end shape check mirroring what the upstream registry returns
        // for carlpett/sops (the provider from issue #1566).
        let registry = serde_json::json!({
            "versions": [
                { "version": "0.7.2", "protocols": ["5.0"],
                  "platforms": [ { "os": "linux", "arch": "amd64" } ] }
            ]
        });
        let index = registry_versions_to_mirror_index(&registry);
        assert_eq!(
            serde_json::to_value(&index).unwrap(),
            serde_json::json!({ "versions": { "0.7.2": {} } })
        );
    }

    // -----------------------------------------------------------------------
    // Hosted mirror document builders
    // -----------------------------------------------------------------------

    #[test]
    fn test_local_versions_to_mirror_index() {
        let index = local_versions_to_mirror_index(&["1.0.0".to_string(), "2.1.0".to_string()]);
        assert_eq!(
            index,
            serde_json::json!({ "versions": { "1.0.0": {}, "2.1.0": {} } })
        );
    }

    #[test]
    fn test_local_versions_to_mirror_index_empty() {
        // Shape stays valid with no versions; the handler 404s before emitting
        // this, but the document must never be malformed.
        assert_eq!(
            local_versions_to_mirror_index(&[]),
            serde_json::json!({ "versions": {} })
        );
    }

    #[test]
    fn test_shasum_to_mirror_hash() {
        assert_eq!(
            shasum_to_mirror_hash(Some("abc123")),
            Some("zh:abc123".to_string())
        );
        assert_eq!(shasum_to_mirror_hash(Some("")), None);
        assert_eq!(shasum_to_mirror_hash(None), None);
    }

    #[test]
    fn test_provider_platform_from_metadata() {
        let md = serde_json::json!({ "os": "darwin", "arch": "arm64" });
        assert_eq!(
            provider_platform_from(Some(&md), "ns/type/1.0.0/linux_amd64"),
            Some(("darwin".to_string(), "arm64".to_string())),
            "metadata must win over the path when both are present"
        );
    }

    #[test]
    fn test_provider_platform_from_path_fallback() {
        // No metadata row: recover the platform from the stored path.
        assert_eq!(
            provider_platform_from(None, "ns/type/1.0.0/linux_arm64"),
            Some(("linux".to_string(), "arm64".to_string()))
        );
        // Metadata present but unusable: same fallback.
        let md = serde_json::json!({ "kind": "provider" });
        assert_eq!(
            provider_platform_from(Some(&md), "ns/type/1.0.0/linux_arm64"),
            Some(("linux".to_string(), "arm64".to_string()))
        );
    }

    #[test]
    fn test_provider_platform_from_unrecoverable() {
        // A package whose platform cannot be determined is omitted rather than
        // advertised under a guessed platform.
        assert_eq!(
            provider_platform_from(None, "ns/type/1.0.0/noplatform"),
            None
        );
        assert_eq!(provider_platform_from(None, "ns/type/1.0.0/_amd64"), None);
        assert_eq!(provider_platform_from(None, ""), None);
    }

    /// The `versions` route must advertise the platforms actually stored for
    /// each version — recovered by the same rule as the mirror — not a guessed
    /// `linux`/`amd64`. Fails against the old grouping, which defaulted missing
    /// `os`/`arch` metadata keys to `linux`/`amd64`.
    #[test]
    fn test_provider_versions_from_rows_real_platforms() {
        let rows = vec![
            (
                "1.0.0".to_string(),
                Some(serde_json::json!({ "os": "darwin", "arch": "arm64" })),
                "ns/type/1.0.0/darwin_arm64".to_string(),
            ),
            (
                "1.0.0".to_string(),
                Some(serde_json::json!({ "os": "linux", "arch": "amd64" })),
                "ns/type/1.0.0/linux_amd64".to_string(),
            ),
            // Metadata row exists but has no os/arch keys: the platform must be
            // recovered from the stored path (linux_arm64), not guessed.
            (
                "2.0.0".to_string(),
                Some(serde_json::json!({ "kind": "provider" })),
                "ns/type/2.0.0/linux_arm64".to_string(),
            ),
            // No metadata row at all: same path recovery.
            (
                "2.0.0".to_string(),
                None,
                "ns/type/2.0.0/darwin_amd64".to_string(),
            ),
        ];
        assert_eq!(
            provider_versions_from_rows(&rows),
            vec![
                serde_json::json!({
                    "version": "1.0.0",
                    "protocols": ["5.0"],
                    "platforms": [
                        { "os": "darwin", "arch": "arm64" },
                        { "os": "linux", "arch": "amd64" },
                    ],
                }),
                serde_json::json!({
                    "version": "2.0.0",
                    "protocols": ["5.0"],
                    "platforms": [
                        { "os": "linux", "arch": "arm64" },
                        { "os": "darwin", "arch": "amd64" },
                    ],
                }),
            ]
        );
    }

    /// A version whose packages have no recoverable platform is still listed,
    /// but with an empty `platforms` array — never a fabricated entry. Fails
    /// against the old grouping, which emitted `linux`/`amd64` for it.
    #[test]
    fn test_provider_versions_from_rows_unrecoverable_platform_omitted() {
        let rows = vec![(
            "1.0.0".to_string(),
            None,
            "ns/type/1.0.0/noplatform".to_string(),
        )];
        assert_eq!(
            provider_versions_from_rows(&rows),
            vec![serde_json::json!({
                "version": "1.0.0",
                "protocols": ["5.0"],
                "platforms": [],
            })]
        );
    }

    /// Duplicate rows for one platform (e.g. a metadata join fan-out) collapse
    /// to a single platform entry.
    #[test]
    fn test_provider_versions_from_rows_dedupes_platforms() {
        let rows = vec![
            (
                "1.0.0".to_string(),
                Some(serde_json::json!({ "os": "linux", "arch": "amd64" })),
                "ns/type/1.0.0/linux_amd64".to_string(),
            ),
            (
                "1.0.0".to_string(),
                None,
                "ns/type/1.0.0/linux_amd64".to_string(),
            ),
        ];
        assert_eq!(
            provider_versions_from_rows(&rows),
            vec![serde_json::json!({
                "version": "1.0.0",
                "protocols": ["5.0"],
                "platforms": [{ "os": "linux", "arch": "amd64" }],
            })]
        );
    }

    #[test]
    fn test_local_packages_to_archive_inputs() {
        let packages = vec![
            LocalProviderPackage {
                os: "linux".to_string(),
                arch: "arm64".to_string(),
                shasum: "aaa".to_string(),
            },
            LocalProviderPackage {
                os: "darwin".to_string(),
                arch: "arm64".to_string(),
                shasum: String::new(),
            },
        ];
        let (platforms, shasums) = local_packages_to_archive_inputs(&packages);
        assert_eq!(
            platforms,
            vec![
                ("linux".to_string(), "arm64".to_string()),
                ("darwin".to_string(), "arm64".to_string())
            ]
        );
        assert_eq!(
            shasums.get(&("linux".to_string(), "arm64".to_string())),
            Some(&"zh:aaa".to_string())
        );
        assert!(
            !shasums.contains_key(&("darwin".to_string(), "arm64".to_string())),
            "a package with no checksum must be advertised without a hash, not with a wrong one"
        );
    }

    /// The hosted source must feed `assemble_mirror_archives` a shape that
    /// produces exactly the mirror `<version>.json` document Terraform parses.
    #[test]
    fn test_local_packages_produce_mirror_version_document() {
        let packages = vec![LocalProviderPackage {
            os: "linux".to_string(),
            arch: "arm64".to_string(),
            shasum: "21c38f6b".to_string(),
        }];
        let (platforms, shasums) = local_packages_to_archive_inputs(&packages);
        let doc = assemble_mirror_archives(
            "1.0.0",
            &platforms,
            &shasums,
            &std::collections::HashMap::new(),
        );
        assert_eq!(
            doc,
            serde_json::json!({
                "archives": {
                    "linux_arm64": {
                        "url": "1.0.0/download/linux/arm64",
                        "hashes": ["zh:21c38f6b"]
                    }
                }
            })
        );
    }

    // -----------------------------------------------------------------------
    // Advertised-location conformance (#2580 class)
    //
    // These assert the URL a document hands a client against the REAL router.
    // The unit tests above can only prove a builder emits the string it was
    // written to emit; only routing the advertised URL proves it resolves.
    // -----------------------------------------------------------------------

    /// The terraform routes mounted exactly where `api::routes` mounts them.
    ///
    /// The advertised URLs are absolute and carry [`MOUNT_PREFIX`], so a router
    /// mounted at the root could not resolve them — the mount point is part of
    /// what these tests are pinning.
    fn mounted_router() -> Router<SharedState> {
        Router::new().nest(MOUNT_PREFIX, super::router())
    }

    /// Publish a provider package through the real upload handler.
    async fn publish_provider(
        fx: &crate::api::handlers::test_db_helpers::Fixture,
        zip: &'static [u8],
    ) -> axum::http::StatusCode {
        publish_provider_version(fx, "1.0.0", zip).await
    }

    /// Publish a `dtf/marker` provider package at an arbitrary version through
    /// the real upload handler.
    async fn publish_provider_version(
        fx: &crate::api::handlers::test_db_helpers::Fixture,
        version: &str,
        zip: &'static [u8],
    ) -> axum::http::StatusCode {
        use crate::api::handlers::test_db_helpers as tdh;
        let (status, _) = tdh::send(
            fx.router_with_auth(mounted_router()),
            tdh::put(
                format!(
                    "{}/{}/v1/providers/dtf/marker/{}/linux/arm64",
                    MOUNT_PREFIX, fx.repo_key, version
                ),
                Bytes::from_static(zip),
            ),
        )
        .await;
        status
    }

    /// #4725: a hosted module upload must queue a push sync task for a
    /// subscribed push peer, and an upload arriving as peer replication must
    /// not be fanned back out. Fails on `main` (nothing queued).
    #[tokio::test]
    async fn terraform_module_upload_queues_push_sync_task_4725() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(fx) = tdh::Fixture::setup("local", "terraform").await else {
            return;
        };
        let peer_id = tdh::subscribe_push_peer(&fx.pool, fx.repo_id, "terraform").await;

        let (status, body) = tdh::send(
            fx.router_with_auth(mounted_router()),
            tdh::put(
                format!(
                    "{}/{}/v1/modules/acme/pushsync/aws/1.0.0",
                    MOUNT_PREFIX, fx.repo_key
                ),
                // #4590: a module upload must be a real archive type.
                Bytes::from_static(b"PK\x03\x04module-archive-bytes"),
            ),
        )
        .await;
        assert!(
            status.is_success(),
            "module upload failed: {status} {}",
            String::from_utf8_lossy(&body)
        );

        // A replicated upload (as the sync worker sends it) stores the module
        // but must not queue another task.
        let req = axum::http::Request::builder()
            .method("PUT")
            .uri(format!(
                "{}/{}/v1/modules/acme/pushsync/aws/2.0.0",
                MOUNT_PREFIX, fx.repo_key
            ))
            .header("x-artifact-keeper-replication", "true")
            .body(axum::body::Body::from(bytes::Bytes::from_static(
                b"PK\x03\x04module-archive-bytes",
            )))
            .unwrap();
        let (status, body) = tdh::send(fx.router_with_auth(mounted_router()), req).await;
        assert!(
            status.is_success(),
            "replicated module upload failed: {status} {}",
            String::from_utf8_lossy(&body)
        );

        let queued = tdh::queued_push_paths(&fx.pool, peer_id, fx.repo_id).await;
        tdh::delete_push_peer(&fx.pool, peer_id).await;
        fx.teardown().await;
        assert_eq!(
            queued,
            vec!["acme/pushsync/aws/1.0.0".to_string()],
            "only the client upload queues a push task; the replicated one must not"
        );
    }

    /// #4725: a hosted provider upload must queue a push sync task for a
    /// subscribed push peer, and an upload arriving as peer replication must
    /// not be fanned back out. Fails on `main` (nothing queued).
    #[tokio::test]
    async fn terraform_provider_upload_queues_push_sync_task_4725() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(fx) = tdh::Fixture::setup("local", "terraform").await else {
            return;
        };
        let peer_id = tdh::subscribe_push_peer(&fx.pool, fx.repo_id, "terraform").await;

        let (status, body) = tdh::send(
            fx.router_with_auth(mounted_router()),
            tdh::put(
                format!(
                    "{}/{}/v1/providers/acme/pushsync/1.0.0/linux/arm64",
                    MOUNT_PREFIX, fx.repo_key
                ),
                bytes::Bytes::from_static(b"PK\x03\x04provider-zip-bytes"),
            ),
        )
        .await;
        assert!(
            status.is_success(),
            "provider upload failed: {status} {}",
            String::from_utf8_lossy(&body)
        );

        // A replicated upload (as the sync worker sends it) stores the package
        // but must not queue another task.
        let req = axum::http::Request::builder()
            .method("PUT")
            .uri(format!(
                "{}/{}/v1/providers/acme/pushsync/2.0.0/linux/arm64",
                MOUNT_PREFIX, fx.repo_key
            ))
            .header("x-artifact-keeper-replication", "true")
            .body(axum::body::Body::from(bytes::Bytes::from_static(
                b"PK\x03\x04provider-zip-bytes",
            )))
            .unwrap();
        let (status, body) = tdh::send(fx.router_with_auth(mounted_router()), req).await;
        assert!(
            status.is_success(),
            "replicated provider upload failed: {status} {}",
            String::from_utf8_lossy(&body)
        );

        let queued = tdh::queued_push_paths(&fx.pool, peer_id, fx.repo_id).await;
        tdh::delete_push_peer(&fx.pool, peer_id).await;
        fx.teardown().await;
        assert_eq!(
            queued,
            vec!["acme/pushsync/1.0.0/linux_arm64".to_string()],
            "only the client upload queues a push task; the replicated one must not"
        );
    }

    /// Resolve a (possibly relative) advertised URL the way a client does —
    /// against the URL of the document that advertised it — and return the
    /// path+query to request.
    fn resolve_advertised(document_url: &str, advertised: &str) -> String {
        let base = reqwest::Url::parse(document_url).expect("document url");
        let joined = base.join(advertised).expect("advertised url must resolve");
        joined[url::Position::BeforePath..].to_string()
    }

    /// The `download_url` the provider package document advertises must be a
    /// live route that streams the package. Regression guard: the document
    /// advertised `.../binary/...` while no such route was registered, so
    /// publish + `versions` both passed while any protocol-conformant client
    /// 404'd on the download.
    #[tokio::test]
    async fn test_advertised_provider_download_url_resolves() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(fx) = tdh::Fixture::setup("local", "terraform").await else {
            return;
        };
        let zip: &[u8] = b"PK\x03\x04 terraform provider archive bytes";
        let published = publish_provider(&fx, zip).await;

        // The package document a client fetches first.
        let doc_path = format!(
            "{}/{}/v1/providers/dtf/marker/1.0.0/download/linux/arm64",
            MOUNT_PREFIX, fx.repo_key
        );
        let (doc_status, doc_body) =
            tdh::send(fx.router_anon(mounted_router()), tdh::get(doc_path.clone())).await;
        let doc: serde_json::Value = serde_json::from_slice(&doc_body).unwrap_or_default();
        let advertised = doc
            .get("download_url")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let filename = doc
            .get("filename")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();

        // Follow it exactly as a client would.
        let (dl_status, dl_body) = if advertised.is_empty() {
            (axum::http::StatusCode::NOT_FOUND, Bytes::new())
        } else {
            let path = resolve_advertised(&format!("http://ak.test{}", doc_path), &advertised);
            tdh::send(fx.router_anon(mounted_router()), tdh::get(path)).await
        };

        fx.teardown().await;

        assert_eq!(published, axum::http::StatusCode::CREATED, "publish");
        assert_eq!(doc_status, axum::http::StatusCode::OK, "package document");
        assert_eq!(
            dl_status,
            axum::http::StatusCode::OK,
            "the advertised download_url ({advertised}) must resolve, not 404"
        );
        assert_eq!(
            &dl_body[..],
            zip,
            "the advertised download_url must serve the published package bytes"
        );
        assert_eq!(
            filename, "terraform-provider-marker_1.0.0_linux_arm64.zip",
            "advertised filename must be the archive name, with no query-escaping \
             artifacts in it"
        );
    }

    /// #3588: the Network Mirror Protocol says Terraform sends NO credentials
    /// to the archive URLs listed in the "list available installation
    /// packages" document, and tells a mirror that must protect those archives
    /// to advertise "cryptographically secure, user-specific, and time-limited
    /// URLs". Before this fix the mirror advertised a bare relative path, so an
    /// authenticated `terraform init` resolved `index.json` and `<v>.json`
    /// fine and then took a flat `401` on the archive.
    ///
    /// Assert the whole contract the protocol asks for, against the real
    /// router: the advertised URL carries a `?ticket=`, that ticket is a live
    /// single-use row owned by the caller, and it is bound to EXACTLY the
    /// archive path Terraform will resolve the advertised URL to — a ticket
    /// bound to anything else authenticates nothing.
    #[tokio::test]
    async fn test_mirror_version_advertises_ticketed_archive_urls_3588() {
        use crate::api::handlers::test_db_helpers as tdh;
        use crate::services::auth_config_service::AuthConfigService;

        let Some(fx) = tdh::Fixture::setup("local", "terraform").await else {
            return;
        };
        let zip: &[u8] = b"PK\x03\x04 terraform provider archive bytes";
        let published = publish_provider(&fx, zip).await;

        // The packages document, fetched WITH credentials exactly as Terraform
        // fetches it (the mirror base is covered by the `credentials` block).
        let doc_path = format!(
            "{}/{}/registry.terraform.io/dtf/marker/1.0.0.json",
            MOUNT_PREFIX, fx.repo_key
        );
        let (doc_status, doc_body) = tdh::send(
            fx.router_with_auth(mounted_router()),
            tdh::get(doc_path.clone()),
        )
        .await;
        let doc: serde_json::Value = serde_json::from_slice(&doc_body).unwrap_or_default();
        let advertised = doc["archives"]["linux_arm64"]["url"]
            .as_str()
            .unwrap_or_default()
            .to_string();

        // Resolve it the way Terraform does: relative to the document URL.
        let resolved = if advertised.is_empty() {
            String::new()
        } else {
            resolve_advertised(&format!("http://ak.test{}", doc_path), &advertised)
        };
        let ticket = resolved
            .split_once("?ticket=")
            .map(|(_, t)| t.to_string())
            .unwrap_or_default();
        let resolved_path = resolved
            .split_once('?')
            .map(|(p, _)| p.to_string())
            .unwrap_or_else(|| resolved.clone());

        // Redeem the ticket the way the visibility middleware does.
        let redeemed = if ticket.is_empty() {
            None
        } else {
            AuthConfigService::validate_download_ticket(&fx.pool, &ticket)
                .await
                .ok()
        };

        // An ANONYMOUS reader of a public mirror needs no ticket and must keep
        // getting the plain relative URL it already resolves.
        let (anon_status, anon_body) =
            tdh::send(fx.router_anon(mounted_router()), tdh::get(doc_path.clone())).await;
        let anon_doc: serde_json::Value = serde_json::from_slice(&anon_body).unwrap_or_default();
        let anon_url = anon_doc["archives"]["linux_arm64"]["url"]
            .as_str()
            .unwrap_or_default()
            .to_string();

        let user_id = fx.user_id;
        fx.teardown().await;

        assert_eq!(published, axum::http::StatusCode::CREATED, "publish");
        assert_eq!(doc_status, axum::http::StatusCode::OK, "packages document");
        assert!(
            advertised.contains("?ticket="),
            "an authenticated caller must be handed a ticketed archive URL \
             (Terraform sends no credentials there), got {advertised:?}"
        );

        let crate::services::auth_config_service::DownloadTicket {
            user_id: ticket_user,
            purpose,
            resource_path: bound_path,
            repo_scope,
        } = redeemed.expect("the advertised ticket must be a live, redeemable ticket");
        assert!(
            repo_scope.is_some(),
            "the ticket must record the caller's repository scope (GHSA-2mfv-xg68-gq4p)"
        );
        assert_eq!(
            ticket_user, user_id,
            "the ticket must be user-specific: it authenticates as the caller \
             who asked for the packages document"
        );
        assert_eq!(purpose, "terraform-mirror-archive");
        assert_eq!(
            bound_path.as_deref(),
            Some(resolved_path.as_str()),
            "the ticket must be bound to the exact archive path Terraform \
             resolves the advertised URL to — tickets match by exact path, so \
             any other binding authenticates nothing"
        );

        assert_eq!(
            anon_status,
            axum::http::StatusCode::OK,
            "anonymous document"
        );
        assert_eq!(
            anon_url, "1.0.0/download/linux/arm64",
            "an anonymous caller gets no ticket: the plain relative URL is \
             already reachable on a public mirror"
        );
    }

    /// A platform the repo holds no package for must 404 at `download` — the
    /// negative half of [`test_advertised_provider_download_url_resolves`].
    ///
    /// The `download` document exists only to advertise a `download_url`, and
    /// the `binary` route it points at resolves by exact `artifacts.path`. A
    /// document for a platform `binary` cannot serve is therefore a dead
    /// advertisement by construction, so `download` must not emit one.
    ///
    /// Regression guard: `download` resolved by an unanchored
    /// `path LIKE '%' || os_arch || '%'` while `binary` resolved by exact path,
    /// so the two endpoints answered to different keys. Any *substring* of a
    /// stored platform returned a 200 document quoting the stored package's
    /// `shasum` under the requested platform's name, whose advertised
    /// `download_url` then 404'd. That was reachable with two real platforms,
    /// not only with truncations: `linux_arm` is a prefix of `linux_arm64`.
    #[tokio::test]
    async fn test_unadvertised_platform_404s_at_download() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(fx) = tdh::Fixture::setup("local", "terraform").await else {
            return;
        };
        let zip: &[u8] = b"PK\x03\x04 terraform provider archive bytes";
        let published = publish_provider(&fx, zip).await;

        // Only `linux/arm64` is published. Both of these are substrings of the
        // stored `linux_arm64`: a truncation of each segment, and the real
        // platform `linux/arm`.
        let mut probes = Vec::new();
        for (os, arch) in [("inux", "arm6"), ("linux", "arm")] {
            let (status, body) = tdh::send(
                fx.router_anon(mounted_router()),
                tdh::get(format!(
                    "{}/{}/v1/providers/dtf/marker/1.0.0/download/{}/{}",
                    MOUNT_PREFIX, fx.repo_key, os, arch
                )),
            )
            .await;
            probes.push((os, arch, status, body));
        }

        fx.teardown().await;

        assert_eq!(published, axum::http::StatusCode::CREATED, "publish");
        for (os, arch, status, body) in probes {
            assert_eq!(
                status,
                axum::http::StatusCode::NOT_FOUND,
                "{os}/{arch} was never published, so `download` must 404 instead \
                 of advertising a download_url that 404s (body: {})",
                String::from_utf8_lossy(&body)
            );
        }
    }

    /// The `X-Terraform-Get` location the module download advertises must be a
    /// live route too — same class as the provider `download_url`.
    #[tokio::test]
    async fn test_advertised_module_archive_url_resolves() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(fx) = tdh::Fixture::setup("local", "terraform").await else {
            return;
        };
        let tarball: &[u8] = b"\x1f\x8b terraform module tarball bytes";
        let k = fx.repo_key.clone();
        let m = MOUNT_PREFIX;

        let (published, _) = tdh::send(
            fx.router_with_auth(mounted_router()),
            tdh::put(
                format!("{m}/{k}/v1/modules/dtf/net/aws/1.0.0"),
                Bytes::from_static(tarball),
            ),
        )
        .await;

        let doc_path = format!("{m}/{k}/v1/modules/dtf/net/aws/1.0.0/download");
        let app = fx.router_anon(mounted_router());
        let response = tower::ServiceExt::oneshot(app, tdh::get(doc_path.clone()))
            .await
            .expect("module download");
        let doc_status = response.status();
        let advertised = response
            .headers()
            .get("X-Terraform-Get")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();

        let (dl_status, dl_body) = if advertised.is_empty() {
            (axum::http::StatusCode::NOT_FOUND, Bytes::new())
        } else {
            let path = resolve_advertised(&format!("http://ak.test{}", doc_path), &advertised);
            tdh::send(fx.router_anon(mounted_router()), tdh::get(path)).await
        };

        fx.teardown().await;

        assert_eq!(published, axum::http::StatusCode::CREATED, "publish");
        assert_eq!(
            doc_status,
            axum::http::StatusCode::NO_CONTENT,
            "module download document"
        );
        assert_eq!(
            dl_status,
            axum::http::StatusCode::OK,
            "the advertised X-Terraform-Get location ({advertised}) must resolve, not 404"
        );
        assert_eq!(
            &dl_body[..],
            tarball,
            "archive must serve the published bytes"
        );
    }

    /// Publish a module through the real upload handler, returning the status
    /// and response body.
    async fn publish_module(
        fx: &crate::api::handlers::test_db_helpers::Fixture,
        coord: &str,
        bytes: Vec<u8>,
    ) -> (axum::http::StatusCode, Bytes) {
        use crate::api::handlers::test_db_helpers as tdh;
        tdh::send(
            fx.router_with_auth(mounted_router()),
            tdh::put(
                format!("{}/{}/v1/modules/{coord}", MOUNT_PREFIX, fx.repo_key),
                Bytes::from(bytes),
            ),
        )
        .await
    }

    /// Walk what `tofu init` walks for a module version: `.../download`, then
    /// the advertised `X-Terraform-Get`. Returns the advertised location and
    /// the archive response (status, body, headers).
    async fn fetch_module_like_client(
        fx: &crate::api::handlers::test_db_helpers::Fixture,
        coord: &str,
    ) -> (
        axum::http::StatusCode,
        String,
        axum::http::StatusCode,
        Bytes,
        axum::http::HeaderMap,
    ) {
        use crate::api::handlers::test_db_helpers as tdh;
        let doc_path = format!(
            "{}/{}/v1/modules/{coord}/download",
            MOUNT_PREFIX, fx.repo_key
        );
        let (doc_status, _, doc_headers) =
            tdh::send_with_headers(fx.router_anon(mounted_router()), tdh::get(doc_path.clone()))
                .await;
        let advertised = doc_headers
            .get("X-Terraform-Get")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        let path = resolve_advertised(&format!("http://ak.test{doc_path}"), &advertised);
        let (status, body, headers) =
            tdh::send_with_headers(fx.router_anon(mounted_router()), tdh::get(path)).await;
        (doc_status, advertised, status, body, headers)
    }

    /// A small real ZIP module (one `main.tf`).
    fn zip_module() -> Vec<u8> {
        use std::io::Write;
        let mut buf = std::io::Cursor::new(Vec::new());
        {
            let mut zip = zip::ZipWriter::new(&mut buf);
            zip.start_file("main.tf", zip::write::SimpleFileOptions::default())
                .unwrap();
            zip.write_all(b"output \"x\" { value = 1 }\n").unwrap();
            zip.finish().unwrap();
        }
        buf.into_inner()
    }

    /// A small real tar.gz module (one `main.tf`).
    fn tar_gz_module() -> Vec<u8> {
        let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::default(),
        ));
        let content = b"output \"x\" { value = 1 }\n";
        let mut header = tar::Header::new_gnu();
        header.set_size(content.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, "main.tf", &content[..])
            .unwrap();
        builder.into_inner().unwrap().finish().unwrap()
    }

    /// #4590: a ZIP upload and a tar.gz upload each advertise the matching
    /// go-getter hint, and the archive is served under the matching name and
    /// type. Before the fix the location had no hint (go-getter parsed the
    /// ZIP as HTML) and every module was served as `.tar.gz`.
    #[tokio::test]
    async fn test_module_archive_hint_follows_upload_type_4590() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(fx) = tdh::Fixture::setup("local", "terraform").await else {
            return;
        };
        let zip = zip_module();
        let tgz = tar_gz_module();
        let (zip_pub, _) = publish_module(&fx, "acme/zipmod/aws/1.0.0", zip.clone()).await;
        let (tgz_pub, _) = publish_module(&fx, "acme/tgzmod/aws/1.0.0", tgz.clone()).await;
        let zip_dl = fetch_module_like_client(&fx, "acme/zipmod/aws/1.0.0").await;
        let tgz_dl = fetch_module_like_client(&fx, "acme/tgzmod/aws/1.0.0").await;
        let recorded: Vec<(String, Option<String>, String)> = sqlx::query_as(
            "SELECT a.name, m.metadata->>'archive_type', a.content_type
               FROM artifacts a LEFT JOIN artifact_metadata m ON m.artifact_id = a.id
              WHERE a.repository_id = $1 ORDER BY a.name",
        )
        .bind(fx.repo_id)
        .fetch_all(&fx.pool)
        .await
        .unwrap();
        fx.teardown().await;

        assert_eq!(zip_pub, axum::http::StatusCode::CREATED);
        assert_eq!(tgz_pub, axum::http::StatusCode::CREATED);
        assert_eq!(
            recorded,
            vec![
                (
                    "acme/tgzmod/aws".to_string(),
                    Some("tar.gz".to_string()),
                    "application/gzip".to_string()
                ),
                (
                    "acme/zipmod/aws".to_string(),
                    Some("zip".to_string()),
                    "application/zip".to_string()
                ),
            ]
        );

        for ((doc, advertised, status, body, headers), coord, hint, ct, ext, bytes) in [
            (zip_dl, "zipmod", "zip", "application/zip", "zip", &zip),
            (
                tgz_dl,
                "tgzmod",
                "tar.gz",
                "application/gzip",
                "tar.gz",
                &tgz,
            ),
        ] {
            assert_eq!(doc, axum::http::StatusCode::NO_CONTENT, "{coord}");
            assert!(
                advertised.ends_with(&format!(
                    "/v1/modules/acme/{coord}/aws/1.0.0/archive?archive={hint}"
                )),
                "{coord}: X-Terraform-Get must carry the {hint} hint, got {advertised}"
            );
            assert_eq!(status, axum::http::StatusCode::OK, "{coord}");
            assert_eq!(&body[..], &bytes[..], "{coord}: archive bytes");
            assert_eq!(headers["content-type"], ct, "{coord}");
            let disposition = headers["content-disposition"].to_str().unwrap();
            assert!(
                disposition.contains(&format!("acme-{coord}-aws-1.0.0.{ext}")),
                "{coord}: {disposition}"
            );
        }
    }

    /// #4590: a body that is not a ZIP or tar.gz is refused at upload with the
    /// reason, and nothing is stored. Plain tar is refused too: neither client
    /// can install it.
    #[tokio::test]
    async fn test_module_upload_rejects_non_archive_4590() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(fx) = tdh::Fixture::setup("local", "terraform").await else {
            return;
        };
        let (junk, junk_body) = publish_module(
            &fx,
            "acme/junk/aws/1.0.0",
            b"<html>not an archive</html>".to_vec(),
        )
        .await;
        let mut tar = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_ustar();
        header.set_size(1);
        header.set_cksum();
        tar.append_data(&mut header, "main.tf", &b"x"[..]).unwrap();
        let (plain_tar, tar_body) =
            publish_module(&fx, "acme/plain/aws/1.0.0", tar.into_inner().unwrap()).await;
        let stored: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM artifacts WHERE repository_id = $1")
                .bind(fx.repo_id)
                .fetch_one(&fx.pool)
                .await
                .unwrap();
        fx.teardown().await;

        assert_eq!(junk, axum::http::StatusCode::BAD_REQUEST);
        assert!(
            String::from_utf8_lossy(&junk_body).contains("not a ZIP or gzip-compressed tar"),
            "{}",
            String::from_utf8_lossy(&junk_body)
        );
        assert_eq!(plain_tar, axum::http::StatusCode::BAD_REQUEST);
        assert!(String::from_utf8_lossy(&tar_body).contains("uncompressed tar"));
        assert_eq!(stored, 0, "a refused upload must store nothing");
    }

    /// #4590: a module uploaded before the type was recorded (no
    /// `archive_type` in its metadata, `.tar.gz` content type whatever it
    /// holds) gets its hint from its stored bytes.
    #[tokio::test]
    async fn test_module_without_recorded_type_is_sniffed_4590() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(fx) = tdh::Fixture::setup("local", "terraform").await else {
            return;
        };
        let zip = zip_module();
        let (published, _) = publish_module(&fx, "acme/legacy/aws/1.0.0", zip.clone()).await;
        // Make it look exactly like a pre-#4590 upload.
        sqlx::query(
            "UPDATE artifact_metadata SET metadata = metadata - 'archive_type'
              WHERE artifact_id IN (SELECT id FROM artifacts WHERE repository_id = $1)",
        )
        .bind(fx.repo_id)
        .execute(&fx.pool)
        .await
        .unwrap();
        sqlx::query(
            "UPDATE artifacts SET content_type = 'application/gzip' WHERE repository_id = $1",
        )
        .bind(fx.repo_id)
        .execute(&fx.pool)
        .await
        .unwrap();
        let (doc, advertised, status, body, headers) =
            fetch_module_like_client(&fx, "acme/legacy/aws/1.0.0").await;
        fx.teardown().await;

        assert_eq!(published, axum::http::StatusCode::CREATED);
        assert_eq!(doc, axum::http::StatusCode::NO_CONTENT);
        assert!(advertised.ends_with("/archive?archive=zip"), "{advertised}");
        assert_eq!(status, axum::http::StatusCode::OK);
        assert_eq!(&body[..], &zip[..]);
        assert_eq!(headers["content-type"], "application/zip");
    }

    // -----------------------------------------------------------------------
    // Hosted network mirror
    // -----------------------------------------------------------------------

    /// The full network-mirror chain a real `terraform init` walks against a
    /// HOSTED repo: `index.json` -> `<version>.json` -> archive. Regression
    /// guard: the mirror was gated to remote/proxy repos, so a hosted repo's
    /// own uploaded providers 404'd on the very first request with "only
    /// available on remote Terraform repositories".
    #[tokio::test]
    async fn test_hosted_mirror_serves_uploaded_provider() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(fx) = tdh::Fixture::setup("local", "terraform").await else {
            return;
        };
        let zip: &[u8] = b"PK\x03\x04 hosted mirror provider archive";
        let published = publish_provider(&fx, zip).await;
        let expected_sha = format!("{:x}", Sha256::digest(zip));
        let k = fx.repo_key.clone();
        let m = MOUNT_PREFIX;

        // 1. index.json — the request `terraform init` makes first.
        let (index_status, index_body) = tdh::send(
            fx.router_anon(mounted_router()),
            tdh::get(format!("{m}/{k}/tf.dtf.local/dtf/marker/index.json")),
        )
        .await;
        let index: serde_json::Value = serde_json::from_slice(&index_body).unwrap_or_default();

        // 2. <version>.json.
        let version_doc_path = format!("{m}/{k}/tf.dtf.local/dtf/marker/1.0.0.json");
        let (version_status, version_body) = tdh::send(
            fx.router_anon(mounted_router()),
            tdh::get(version_doc_path.clone()),
        )
        .await;
        let version_doc: serde_json::Value =
            serde_json::from_slice(&version_body).unwrap_or_default();
        let archive_url = version_doc
            .pointer("/archives/linux_arm64/url")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let hashes = version_doc
            .pointer("/archives/linux_arm64/hashes")
            .cloned()
            .unwrap_or(serde_json::Value::Null);

        // 3. The archive, at the URL the mirror advertised (relative to the
        //    document that advertised it, exactly as Terraform resolves it).
        let (archive_status, archive_body) = if archive_url.is_empty() {
            (axum::http::StatusCode::NOT_FOUND, Bytes::new())
        } else {
            let path = resolve_advertised(
                &format!("http://tf.dtf.local{}", version_doc_path),
                &archive_url,
            );
            tdh::send(fx.router_anon(mounted_router()), tdh::get(path)).await
        };

        fx.teardown().await;

        assert_eq!(published, axum::http::StatusCode::CREATED, "publish");
        assert_eq!(
            index_status,
            axum::http::StatusCode::OK,
            "hosted mirror index.json must be served"
        );
        assert_eq!(
            index,
            serde_json::json!({ "versions": { "1.0.0": {} } }),
            "index must list the uploaded version"
        );
        assert_eq!(
            version_status,
            axum::http::StatusCode::OK,
            "hosted mirror <version>.json must be served"
        );
        assert_eq!(
            hashes,
            serde_json::json!([format!("zh:{expected_sha}")]),
            "the advertised zh: hash must be the SHA-256 of the stored archive"
        );
        assert_eq!(
            archive_status,
            axum::http::StatusCode::OK,
            "the mirror-advertised archive url ({archive_url}) must resolve"
        );
        assert_eq!(
            &archive_body[..],
            zip,
            "the mirror must serve the uploaded package bytes"
        );
    }

    /// A hosted mirror still 404s a provider it has no packages for, rather
    /// than advertising an empty version list.
    #[tokio::test]
    async fn test_hosted_mirror_404s_unknown_provider() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(fx) = tdh::Fixture::setup("local", "terraform").await else {
            return;
        };
        let k = fx.repo_key.clone();
        let m = MOUNT_PREFIX;

        let (index_status, _) = tdh::send(
            fx.router_anon(mounted_router()),
            tdh::get(format!("{m}/{k}/tf.dtf.local/dtf/absent/index.json")),
        )
        .await;
        let (version_status, _) = tdh::send(
            fx.router_anon(mounted_router()),
            tdh::get(format!("{m}/{k}/tf.dtf.local/dtf/absent/9.9.9.json")),
        )
        .await;
        let (archive_status, _) = tdh::send(
            fx.router_anon(mounted_router()),
            tdh::get(format!(
                "{m}/{k}/tf.dtf.local/dtf/absent/9.9.9/download/linux/arm64"
            )),
        )
        .await;

        fx.teardown().await;

        assert_eq!(index_status, axum::http::StatusCode::NOT_FOUND);
        assert_eq!(version_status, axum::http::StatusCode::NOT_FOUND);
        assert_eq!(archive_status, axum::http::StatusCode::NOT_FOUND);
    }

    /// #3143: terraform download routes must apply the repository's scan
    /// policy, not just the quarantine predicate.
    ///
    /// `download_provider_binary` -> `serve_provider_archive` resolves bytes via
    /// `local_fetch_by_path`, whose only gate is `check_quarantine_row` (the raw
    /// quarantine predicate). `block_unscanned` / `block_on_fail` /
    /// `max_severity` were therefore never consulted on ANY terraform download
    /// route — `terraform.rs` contained zero `check_artifact_download` calls —
    /// while the ~25 per-format handlers routed through `enforce_download_gate`
    /// and blocked. An artifact a format handler would 403 was downloadable here.
    ///
    /// Positive control in the SAME fixture: the identical request succeeds
    /// with no policy in force, so the 403 is attributable to the policy rather
    /// than to a broken fixture or a route that 403s unconditionally.
    #[tokio::test]
    async fn test_provider_binary_applies_scan_policy_3143() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(fx) = tdh::Fixture::setup("local", "terraform").await else {
            return;
        };
        let zip: &[u8] = b"PK\x03\x04 provider archive";
        let published = publish_provider_version(&fx, "1.0.0", zip).await;

        let k = fx.repo_key.clone();
        let m = MOUNT_PREFIX;
        let binary_path = format!("{m}/{k}/v1/providers/dtf/marker/1.0.0/binary/linux/arm64");

        // POSITIVE CONTROL: no scan policy in force -> the download must work.
        let (before_status, before_body) = tdh::send(
            fx.router_anon(mounted_router()),
            tdh::get(binary_path.clone()),
        )
        .await;

        // Enable a policy that blocks unscanned artifacts. The published
        // provider has no `scan_results` rows at all, so it is unscanned.
        sqlx::query(
            "INSERT INTO scan_policies (name, repository_id, max_severity, block_unscanned, \
                                        block_on_fail, is_enabled) \
             VALUES ($1, $2, 'critical', true, false, true)",
        )
        .bind(format!("gate-3143-tf-{}", fx.repo_id))
        .bind(fx.repo_id)
        .execute(&fx.pool)
        .await
        .expect("insert block_unscanned policy");

        let (blocked_status, blocked_body) = tdh::send(
            fx.router_anon(mounted_router()),
            tdh::get(binary_path.clone()),
        )
        .await;

        let _ = sqlx::query("DELETE FROM scan_policies WHERE repository_id = $1")
            .bind(fx.repo_id)
            .execute(&fx.pool)
            .await;

        // NEGATIVE CONTROL: with the policy removed the same request must serve
        // again, proving the block was the policy and is fully reversible.
        let (after_status, after_body) = tdh::send(
            fx.router_anon(mounted_router()),
            tdh::get(binary_path.clone()),
        )
        .await;

        fx.teardown().await;

        assert_eq!(
            published,
            axum::http::StatusCode::CREATED,
            "fixture: provider must publish"
        );
        assert_eq!(
            before_status,
            axum::http::StatusCode::OK,
            "positive control: with no scan policy the provider binary must download"
        );
        assert_eq!(
            before_body.as_ref(),
            zip,
            "positive control: the served bytes must be the published archive"
        );
        assert_eq!(
            blocked_status,
            axum::http::StatusCode::FORBIDDEN,
            "#3143: an unscanned provider under block_unscanned must be refused with 403, \
             got {blocked_status} body={:?}",
            String::from_utf8_lossy(&blocked_body)
        );
        assert_ne!(
            blocked_body.as_ref(),
            zip,
            "#3143: the archive bytes must not be served when the policy blocks"
        );
        assert_eq!(
            after_status,
            axum::http::StatusCode::OK,
            "negative control: removing the policy must restore the download"
        );
        assert_eq!(after_body.as_ref(), zip, "negative control: bytes restored");
    }

    /// A package under a quarantine hold must not appear in the metadata
    /// surface — the registry `versions` list, the mirror `index.json`, or the
    /// mirror `<version>.json` (which would publish its `zh:` SHA-256) — while
    /// the clean version stays fully served. Once the hold window expires the
    /// version is listable again (#2662).
    ///
    /// Regression guard: these listing queries filtered only on
    /// `is_deleted = false`, so a held package was advertised (hash included)
    /// even though the download routes refuse its bytes via
    /// `check_quarantine_row` — `terraform init` selected the version and then
    /// failed on the download instead of never seeing it.
    #[tokio::test]
    async fn test_held_provider_hidden_from_versions_and_mirror_2662() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(fx) = tdh::Fixture::setup("local", "terraform").await else {
            return;
        };
        let clean_zip: &[u8] = b"PK\x03\x04 clean provider archive";
        let held_zip: &[u8] = b"PK\x03\x04 held provider archive";
        let published_clean = publish_provider_version(&fx, "1.0.0", clean_zip).await;
        let published_held = publish_provider_version(&fx, "2.0.0", held_zip).await;

        // Put 2.0.0 under an active quarantine hold.
        sqlx::query(
            "UPDATE artifacts SET quarantine_status = 'quarantined', \
             quarantine_until = NOW() + interval '1 hour' \
             WHERE repository_id = $1 AND version = '2.0.0'",
        )
        .bind(fx.repo_id)
        .execute(&fx.pool)
        .await
        .expect("hold 2.0.0");

        let k = fx.repo_key.clone();
        let m = MOUNT_PREFIX;

        let (versions_status, versions_body) = tdh::send(
            fx.router_anon(mounted_router()),
            tdh::get(format!("{m}/{k}/v1/providers/dtf/marker/versions")),
        )
        .await;
        let versions_doc: serde_json::Value =
            serde_json::from_slice(&versions_body).unwrap_or_default();

        let (index_status, index_body) = tdh::send(
            fx.router_anon(mounted_router()),
            tdh::get(format!("{m}/{k}/tf.dtf.local/dtf/marker/index.json")),
        )
        .await;
        let index: serde_json::Value = serde_json::from_slice(&index_body).unwrap_or_default();

        let (held_doc_status, held_doc_body) = tdh::send(
            fx.router_anon(mounted_router()),
            tdh::get(format!("{m}/{k}/tf.dtf.local/dtf/marker/2.0.0.json")),
        )
        .await;

        let (clean_doc_status, clean_doc_body) = tdh::send(
            fx.router_anon(mounted_router()),
            tdh::get(format!("{m}/{k}/tf.dtf.local/dtf/marker/1.0.0.json")),
        )
        .await;
        let clean_doc: serde_json::Value =
            serde_json::from_slice(&clean_doc_body).unwrap_or_default();

        // Expire the hold: the version must become listable again without any
        // status transition having run.
        sqlx::query(
            "UPDATE artifacts SET quarantine_until = NOW() - interval '1 minute' \
             WHERE repository_id = $1 AND version = '2.0.0'",
        )
        .bind(fx.repo_id)
        .execute(&fx.pool)
        .await
        .expect("expire hold on 2.0.0");

        let (_, expired_index_body) = tdh::send(
            fx.router_anon(mounted_router()),
            tdh::get(format!("{m}/{k}/tf.dtf.local/dtf/marker/index.json")),
        )
        .await;
        let expired_index: serde_json::Value =
            serde_json::from_slice(&expired_index_body).unwrap_or_default();

        fx.teardown().await;

        assert_eq!(
            published_clean,
            axum::http::StatusCode::CREATED,
            "publish 1.0.0"
        );
        assert_eq!(
            published_held,
            axum::http::StatusCode::CREATED,
            "publish 2.0.0"
        );

        assert_eq!(versions_status, axum::http::StatusCode::OK, "versions list");
        let listed: Vec<&str> = versions_doc
            .pointer("/versions")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|e| e.get("version").and_then(|v| v.as_str()))
                    .collect()
            })
            .unwrap_or_default();
        assert_eq!(
            listed,
            vec!["1.0.0"],
            "the versions list must contain only the clean version, not the held one"
        );

        assert_eq!(
            index_status,
            axum::http::StatusCode::OK,
            "mirror index.json"
        );
        assert_eq!(
            index,
            serde_json::json!({ "versions": { "1.0.0": {} } }),
            "the mirror index must not advertise the held version"
        );

        assert_eq!(
            held_doc_status,
            axum::http::StatusCode::NOT_FOUND,
            "the held version's mirror document must 404 rather than publish its \
             zh: hash (body: {})",
            String::from_utf8_lossy(&held_doc_body)
        );

        assert_eq!(
            clean_doc_status,
            axum::http::StatusCode::OK,
            "the clean version's mirror document must still be served"
        );
        let expected_clean_sha = format!("{:x}", Sha256::digest(clean_zip));
        assert_eq!(
            clean_doc.pointer("/archives/linux_arm64/hashes"),
            Some(&serde_json::json!([format!("zh:{expected_clean_sha}")])),
            "the clean version keeps advertising its zh: hash"
        );

        assert_eq!(
            expired_index,
            serde_json::json!({ "versions": { "1.0.0": {}, "2.0.0": {} } }),
            "an expired hold must be listable again, matching check_download_allowed"
        );
    }
}

#[cfg(ak_test_shard = "handlers-2")]
#[cfg(test)]
mod db_cov_tests {
    use crate::api::handlers::test_db_helpers as tdh;

    // Exercises the DB-query happy paths so the sweep's db_err/db_status
    // call-site lines are covered by cargo llvm-cov --lib (#2083).
    #[tokio::test]
    async fn test_terraform_db_query_paths_smoke() {
        let Some(fx) = tdh::Fixture::setup("local", "terraform").await else {
            return;
        };
        let k = fx.repo_key.clone();
        let uris: Vec<String> = vec![
            format!("/{k}/v1/modules/search?q=x&limit=1"),
            format!("/{k}/v1/modules/ns/name/aws/versions"),
            format!("/{k}/v1/modules/ns/name/aws/1.0.0/download"),
            format!("/{k}/v1/modules/ns/name/aws"),
            format!("/{k}/v1/modules/ns/name/aws/1.0.0"),
            format!("/{k}/v1/providers/ns/type/versions"),
            format!("/{k}/v1/providers/ns/type/1.0.0/download/linux/amd64"),
            format!("/{k}/v1/providers/ns/type/1.0.0/linux/amd64"),
            format!("/{k}/host/ns/type/index.json"),
            format!("/{k}/host/ns/type/1.0.0.json"),
            format!("/{k}/host/ns/type/1.0.0/download/linux/amd64"),
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

#[cfg(ak_test_shard = "handlers-2")]
#[cfg(test)]
mod catalog_registration_tests {
    use crate::api::handlers::test_db_helpers as tdh;

    use crate::api::SharedState;
    use axum::Router;

    fn mounted() -> Router<SharedState> {
        Router::new().nest(super::MOUNT_PREFIX, super::router())
    }

    /// A module upload must register the catalog row under the registry
    /// coordinate `namespace/name/provider`.
    #[tokio::test]
    async fn module_upload_registers_catalog_row() {
        let Some(fx) = tdh::Fixture::setup("local", "terraform").await else {
            return;
        };
        let (status, body) = tdh::send(
            fx.router_with_auth(mounted()),
            tdh::put(
                format!(
                    "{}/{}/v1/modules/acme/vpc/aws/1.4.0",
                    super::MOUNT_PREFIX,
                    fx.repo_key
                ),
                // #4590: a module upload must be a real archive type.
                bytes::Bytes::from_static(b"PK\x03\x04module-archive-bytes"),
            ),
        )
        .await;
        assert!(
            status.is_success(),
            "module upload failed: {status} {}",
            String::from_utf8_lossy(&body)
        );

        let row = tdh::catalog_row(&fx.pool, fx.repo_id, "acme/vpc/aws").await;
        fx.teardown().await;

        let row = row.expect("a terraform module upload must write a packages row (#3659)");
        assert_eq!(row.version, "1.4.0");
        assert_eq!(row.versions, vec!["1.4.0".to_string()]);
    }

    /// A provider upload must register the catalog row under the registry
    /// coordinate `namespace/type`; each platform build of one version
    /// collapses into the same catalog version.
    #[tokio::test]
    async fn provider_upload_registers_catalog_row() {
        let Some(fx) = tdh::Fixture::setup("local", "terraform").await else {
            return;
        };
        for platform in ["linux/arm64", "linux/amd64"] {
            let (status, body) = tdh::send(
                fx.router_with_auth(mounted()),
                tdh::put(
                    format!(
                        "{}/{}/v1/providers/acme/marker/2.0.0/{platform}",
                        super::MOUNT_PREFIX,
                        fx.repo_key
                    ),
                    bytes::Bytes::from(format!("provider-zip-{platform}")),
                ),
            )
            .await;
            assert!(
                status.is_success(),
                "provider upload failed: {status} {}",
                String::from_utf8_lossy(&body)
            );
        }

        let row = tdh::catalog_row(&fx.pool, fx.repo_id, "acme/marker").await;
        fx.teardown().await;

        let row = row.expect("a terraform provider upload must write a packages row (#3659)");
        assert_eq!(row.version, "2.0.0");
        assert_eq!(row.versions, vec!["2.0.0".to_string()]);
    }
}

/// #4598: a virtual Terraform repository answers module `/download` the way
/// its resolving member does, `204` + `X-Terraform-Get` pointing at the
/// virtual's own `/archive` with the archive hint, and that `/archive`
/// streams the member's archive (hosted bytes, or the remote's upstream file).
#[cfg(ak_test_shard = "handlers-2")]
#[cfg(test)]
mod virtual_module_download_4598 {
    use super::MOUNT_PREFIX;
    use crate::api::handlers::test_db_helpers as tdh;
    use crate::api::SharedState;
    use axum::http::StatusCode;
    use axum::Router;
    use bytes::Bytes;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn mounted_router() -> Router<SharedState> {
        Router::new().nest(MOUNT_PREFIX, super::router())
    }

    fn zip_module() -> Vec<u8> {
        use std::io::Write;
        let mut buf = std::io::Cursor::new(Vec::new());
        {
            let mut zip = zip::ZipWriter::new(&mut buf);
            zip.start_file("main.tf", zip::write::SimpleFileOptions::default())
                .unwrap();
            zip.write_all(b"output \"x\" { value = \"hosted\" }\n")
                .unwrap();
            zip.finish().unwrap();
        }
        buf.into_inner()
    }

    /// `.../download` then the advertised location, as `tofu init` walks it.
    async fn walk(
        state: &SharedState,
        repo_key: &str,
        coord: &str,
    ) -> (StatusCode, String, StatusCode, Bytes, axum::http::HeaderMap) {
        let doc_path = format!("{MOUNT_PREFIX}/{repo_key}/v1/modules/{coord}/download");
        let (doc_status, doc_body, doc_headers) = tdh::send_with_headers(
            tdh::router_anon(mounted_router(), state.clone()),
            tdh::get(doc_path.clone()),
        )
        .await;
        let advertised = doc_headers
            .get("X-Terraform-Get")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        if advertised.is_empty() {
            return (
                doc_status,
                format!("<no X-Terraform-Get; body {} bytes>", doc_body.len()),
                StatusCode::NOT_FOUND,
                Bytes::new(),
                axum::http::HeaderMap::new(),
            );
        }
        let base = reqwest::Url::parse(&format!("http://ak.test{doc_path}")).unwrap();
        let joined = base.join(&advertised).unwrap();
        let archive_path = joined[url::Position::BeforePath..].to_string();
        let (status, body, headers) = tdh::send_with_headers(
            tdh::router_anon(mounted_router(), state.clone()),
            tdh::get(archive_path),
        )
        .await;
        (doc_status, advertised, status, body, headers)
    }

    #[tokio::test]
    async fn virtual_answers_204_with_hint_and_streams_hosted_and_remote_archives() {
        let Some(fx) = tdh::Fixture::setup("virtual", "terraform").await else {
            return;
        };
        tdh::publish_repo(&fx.pool, fx.repo_id).await;

        // Upstream registry for the remote member: relative location, no
        // archive type named, so the bytes decide the hint.
        let server = MockServer::start().await;
        let remote_blob = {
            let mut b = Vec::new();
            let mut gz = flate2::write::GzEncoder::new(&mut b, flate2::Compression::default());
            std::io::Write::write_all(&mut gz, b"not really a tar, gzip is enough").unwrap();
            gz.finish().unwrap();
            b
        };
        Mock::given(method("GET"))
            .and(path("/v1/modules/acme/proxied/aws/2.0.0/download"))
            .respond_with(
                ResponseTemplate::new(204).insert_header("X-Terraform-Get", "/files/proxied-2.0.0"),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v1/modules/acme/proxied/aws/versions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "modules": [{"versions": [{"version": "2.0.0"}]}]
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/files/proxied-2.0.0"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(remote_blob.clone()))
            .mount(&server)
            .await;

        let (hosted_id, hosted_key, hosted_dir) =
            tdh::create_repo(&fx.pool, "local", "terraform").await;
        tdh::grant_repo_access(&fx.pool, hosted_id, fx.user_id).await;
        tdh::publish_repo(&fx.pool, hosted_id).await;
        tdh::link_virtual_member(&fx.pool, fx.repo_id, hosted_id, 1).await;
        let (remote_id, _remote_key, remote_dir) =
            tdh::attach_remote_member(&fx.pool, fx.repo_id, "terraform", &server.uri(), 2).await;

        let cache = tempfile::tempdir().unwrap();
        let proxy =
            tdh::build_proxy_service_with_fs(fx.pool.clone(), cache.path().to_str().unwrap());
        let state =
            tdh::build_state_with_proxy(fx.pool.clone(), hosted_dir.to_str().unwrap(), proxy);

        let zip = zip_module();
        let auth = tdh::make_auth(fx.user_id, &fx.username);
        let (published, _) = tdh::send(
            tdh::router_with_auth(mounted_router(), state.clone(), auth),
            tdh::put(
                format!("{MOUNT_PREFIX}/{hosted_key}/v1/modules/acme/hosted/aws/1.0.0"),
                Bytes::from(zip.clone()),
            ),
        )
        .await;

        // `tofu init` lists versions before it downloads.
        let mut listed = Vec::new();
        for module in ["acme/hosted/aws", "acme/proxied/aws"] {
            let (status, body) = tdh::send(
                tdh::router_anon(mounted_router(), state.clone()),
                tdh::get(format!(
                    "{MOUNT_PREFIX}/{}/v1/modules/{module}/versions",
                    fx.repo_key
                )),
            )
            .await;
            listed.push((status, String::from_utf8_lossy(&body).into_owned()));
        }
        let hosted = walk(&state, &fx.repo_key, "acme/hosted/aws/1.0.0").await;
        let proxied = walk(&state, &fx.repo_key, "acme/proxied/aws/2.0.0").await;
        let missing = walk(&state, &fx.repo_key, "acme/nothere/aws/9.9.9").await;

        tdh::cleanup_member_repo(&fx.pool, hosted_id, &hosted_dir).await;
        tdh::cleanup_member_repo(&fx.pool, remote_id, &remote_dir).await;
        fx.teardown().await;

        assert_eq!(published, StatusCode::CREATED);
        assert_eq!(listed[0].0, StatusCode::OK, "{}", listed[0].1);
        assert!(listed[0].1.contains("\"1.0.0\""), "{}", listed[0].1);
        assert_eq!(listed[1].0, StatusCode::OK, "{}", listed[1].1);
        assert!(listed[1].1.contains("\"2.0.0\""), "{}", listed[1].1);

        let (doc, advertised, status, body, headers) = hosted;
        assert_eq!(
            doc,
            StatusCode::NO_CONTENT,
            "hosted member via virtual: {advertised}"
        );
        assert_eq!(
            advertised,
            format!(
                "/terraform/{}/v1/modules/acme/hosted/aws/1.0.0/archive?archive=zip",
                fx.repo_key
            )
        );
        assert_eq!(status, StatusCode::OK);
        assert_eq!(&body[..], &zip[..]);
        assert_eq!(headers["content-type"], "application/zip");

        let (doc, advertised, status, body, headers) = proxied;
        assert_eq!(
            doc,
            StatusCode::NO_CONTENT,
            "remote member via virtual: {advertised}"
        );
        assert_eq!(
            advertised,
            format!(
                "/terraform/{}/v1/modules/acme/proxied/aws/2.0.0/archive?archive=tar.gz",
                fx.repo_key
            )
        );
        assert_eq!(status, StatusCode::OK);
        assert_eq!(&body[..], &remote_blob[..]);
        assert_eq!(headers["content-type"], "application/gzip");

        assert_eq!(missing.0, StatusCode::NOT_FOUND);
    }

    /// A source the proxy does not fetch (`git::`) is handed through unchanged
    /// by a virtual, exactly as by the remote itself.
    #[tokio::test]
    async fn virtual_passes_a_git_source_through() {
        let Some(fx) = tdh::Fixture::setup("virtual", "terraform").await else {
            return;
        };
        tdh::publish_repo(&fx.pool, fx.repo_id).await;
        let server = MockServer::start().await;
        let git = "git::https://example.com/acme/vpc.git?ref=v3.0.0";
        Mock::given(method("GET"))
            .and(path("/v1/modules/acme/vpc/aws/3.0.0/download"))
            .respond_with(ResponseTemplate::new(204).insert_header("X-Terraform-Get", git))
            .mount(&server)
            .await;
        let (remote_id, _k, remote_dir) =
            tdh::attach_remote_member(&fx.pool, fx.repo_id, "terraform", &server.uri(), 1).await;
        let cache = tempfile::tempdir().unwrap();
        let proxy =
            tdh::build_proxy_service_with_fs(fx.pool.clone(), cache.path().to_str().unwrap());
        let state =
            tdh::build_state_with_proxy(fx.pool.clone(), cache.path().to_str().unwrap(), proxy);

        let (status, _, headers) = tdh::send_with_headers(
            tdh::router_anon(mounted_router(), state),
            tdh::get(format!(
                "{MOUNT_PREFIX}/{}/v1/modules/acme/vpc/aws/3.0.0/download",
                fx.repo_key
            )),
        )
        .await;
        tdh::cleanup_member_repo(&fx.pool, remote_id, &remote_dir).await;
        fx.teardown().await;

        assert_eq!(status, StatusCode::NO_CONTENT);
        assert_eq!(headers["x-terraform-get"], git);
    }
}

// ---------------------------------------------------------------------------
// Origin provider registry: signed SHA256SUMS, package-document signing
// fields, protocol versions and host-level discovery.
// ---------------------------------------------------------------------------

#[cfg(ak_test_shard = "handlers-2")]
#[cfg(test)]
mod origin_registry_tests {
    use super::*;
    use crate::api::handlers::test_db_helpers as tdh;
    use crate::services::signing_service::{verify_detached, CreateKeyRequest};
    use axum::http::Request;
    use sha2::{Digest, Sha256};

    #[test]
    fn dearmor_signature_rejects_garbage() {
        assert!(dearmor_signature("not a signature").is_err());
    }

    fn pkg(os: &str, arch: &str, shasum: &str) -> LocalProviderPackage {
        LocalProviderPackage {
            os: os.to_string(),
            arch: arch.to_string(),
            shasum: shasum.to_string(),
        }
    }

    fn protocols(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    fn mounted() -> Router<SharedState> {
        Router::new().nest(MOUNT_PREFIX, router())
    }

    fn sha256_hex(data: &[u8]) -> String {
        format!("{:x}", Sha256::digest(data))
    }

    // -- SHA256SUMS builder --------------------------------------------------

    #[test]
    fn shasums_has_one_sorted_line_per_platform_archive() {
        let doc = build_provider_shasums(
            "contrail",
            "0.5.0",
            &[
                pkg("linux", "arm64", "BBBB"),
                pkg("darwin", "amd64", "cccc"),
                pkg("linux", "amd64", "aaaa"),
            ],
        );
        assert_eq!(
            doc,
            "cccc  terraform-provider-contrail_0.5.0_darwin_amd64.zip\n\
             aaaa  terraform-provider-contrail_0.5.0_linux_amd64.zip\n\
             bbbb  terraform-provider-contrail_0.5.0_linux_arm64.zip\n"
        );
    }

    #[test]
    fn shasums_is_independent_of_input_order_and_duplicates() {
        let a = pkg("linux", "amd64", "aa");
        let b = pkg("linux", "arm64", "bb");
        let forward = build_provider_shasums("t", "1.0.0", &[a.clone_pkg(), b.clone_pkg()]);
        let backward = build_provider_shasums("t", "1.0.0", &[b.clone_pkg(), a.clone_pkg(), a]);
        assert_eq!(forward, backward);
        assert_eq!(forward.lines().count(), 2);
    }

    impl LocalProviderPackage {
        fn clone_pkg(&self) -> Self {
            pkg(&self.os, &self.arch, &self.shasum)
        }
    }

    #[test]
    fn shasums_line_format_is_two_spaces_between_hash_and_name() {
        let hash = "0".repeat(64);
        let doc = build_provider_shasums("t", "1.0.0", &[pkg("linux", "amd64", &hash)]);
        assert_eq!(
            doc,
            format!("{hash}  terraform-provider-t_1.0.0_linux_amd64.zip\n")
        );
    }

    #[test]
    fn shasums_url_is_under_the_mount_point() {
        assert_eq!(
            build_provider_shasums_url("tf", "ns", "type", "1.2.3"),
            "/terraform/tf/v1/providers/ns/type/1.2.3/SHA256SUMS"
        );
    }

    // -- package document ----------------------------------------------------

    fn signing_doc() -> ProviderSigningDoc {
        ProviderSigningDoc {
            key_id: "ABCD1234".to_string(),
            ascii_armor:
                "-----BEGIN PGP PUBLIC KEY BLOCK-----\nx\n-----END PGP PUBLIC KEY BLOCK-----\n"
                    .to_string(),
            shasums_url: "/terraform/tf/v1/providers/ns/t/1.0.0/SHA256SUMS".to_string(),
            shasums_signature_url: "/terraform/tf/v1/providers/ns/t/1.0.0/SHA256SUMS.sig"
                .to_string(),
        }
    }

    #[test]
    fn download_json_without_signing_keeps_legacy_shape() {
        let json = build_provider_download_json(
            "linux",
            "amd64",
            "f.zip",
            "/u",
            "h",
            &protocols(&["5.0"]),
            None,
        );
        assert!(json.get("shasums_url").is_none());
        assert!(json.get("shasums_signature_url").is_none());
        assert!(json["signing_keys"]["gpg_public_keys"]
            .as_array()
            .unwrap()
            .is_empty());
    }

    #[test]
    fn download_json_with_signing_advertises_checksums_and_key() {
        let signing = signing_doc();
        let json = build_provider_download_json(
            "linux",
            "amd64",
            "f.zip",
            "/u",
            "h",
            &protocols(&["5.0", "6.0"]),
            Some(&signing),
        );
        assert_eq!(json["protocols"], serde_json::json!(["5.0", "6.0"]));
        assert_eq!(json["shasums_url"], signing.shasums_url);
        assert_eq!(json["shasums_signature_url"], signing.shasums_signature_url);
        let keys = json["signing_keys"]["gpg_public_keys"].as_array().unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0]["key_id"], "ABCD1234");
        assert_eq!(keys[0]["ascii_armor"], signing.ascii_armor);
    }

    fn test_key(
        key_id: Option<&str>,
        fingerprint: Option<&str>,
    ) -> crate::models::signing_key::SigningKey {
        crate::models::signing_key::SigningKey {
            id: uuid::Uuid::new_v4(),
            repository_id: None,
            name: "k".to_string(),
            key_type: "gpg".to_string(),
            fingerprint: fingerprint.map(str::to_string),
            key_id: key_id.map(str::to_string),
            public_key_pem: "PUBLIC".to_string(),
            private_key_enc: b"never-served-private-material".to_vec(),
            algorithm: "rsa2048".to_string(),
            uid_name: None,
            uid_email: None,
            expires_at: None,
            is_active: true,
            created_at: chrono::Utc::now(),
            created_by: None,
            rotated_from: None,
            last_used_at: None,
        }
    }

    #[test]
    fn signing_doc_prefers_key_id_then_fingerprint_and_only_exposes_public_half() {
        let doc = provider_signing_doc(
            &test_key(Some("KID"), Some("FPR")),
            "tf",
            "ns",
            "t",
            "1.0.0",
        );
        assert_eq!(doc.key_id, "KID");
        assert_eq!(doc.ascii_armor, "PUBLIC");
        assert_eq!(
            doc.shasums_signature_url,
            format!("{}.sig", doc.shasums_url)
        );
        let serialised =
            build_provider_download_json("l", "a", "f", "u", "h", &protocols(&["5.0"]), Some(&doc))
                .to_string();
        assert!(!serialised.contains("never-served-private-material"));

        let doc = provider_signing_doc(&test_key(None, Some("FPR")), "tf", "ns", "t", "1.0.0");
        assert_eq!(doc.key_id, "FPR");
        let doc = provider_signing_doc(&test_key(None, None), "tf", "ns", "t", "1.0.0");
        assert_eq!(doc.key_id, "");
    }

    // -- protocols -------------------------------------------------------------

    #[test]
    fn protocol_normalisation_sorts_numerically_and_dedups() {
        assert_eq!(
            normalize_protocols(["6.0", "5.0", " 5.0 ", "10.1"]),
            Some(protocols(&["5.0", "6.0", "10.1"]))
        );
    }

    #[test]
    fn protocol_normalisation_rejects_malformed_empty_and_oversized() {
        assert_eq!(normalize_protocols(["5"]), None);
        assert_eq!(normalize_protocols(["5.x"]), None);
        assert_eq!(normalize_protocols(["a.b"]), None);
        assert_eq!(normalize_protocols(["5.0", ""]), None);
        assert_eq!(normalize_protocols(["99999.0"]), None);
        assert_eq!(normalize_protocols(Vec::<&str>::new()), None);
        let many: Vec<String> = (0..=MAX_PROTOCOL_VERSIONS)
            .map(|i| format!("{i}.0"))
            .collect();
        assert_eq!(normalize_protocols(many.iter().map(String::as_str)), None);
    }

    #[test]
    fn protocols_header_absent_valid_and_malformed() {
        let mut headers = HeaderMap::new();
        assert_eq!(parse_protocols_header(&headers), Ok(None));
        headers.insert(PROTOCOLS_HEADER, "6.0, 5.0".parse().unwrap());
        assert_eq!(
            parse_protocols_header(&headers),
            Ok(Some(protocols(&["5.0", "6.0"])))
        );
        headers.insert(PROTOCOLS_HEADER, "five".parse().unwrap());
        assert!(parse_protocols_header(&headers)
            .unwrap_err()
            .contains("X-Terraform-Protocols"));
    }

    #[test]
    fn protocols_from_manifest_json_reads_metadata_protocol_versions() {
        let raw = br#"{"version":1,"metadata":{"protocol_versions":["6.0","5.0"]}}"#;
        assert_eq!(
            protocols_from_manifest_json(raw),
            Some(protocols(&["5.0", "6.0"]))
        );
        assert_eq!(protocols_from_manifest_json(b"not json"), None);
        assert_eq!(protocols_from_manifest_json(br#"{"version":1}"#), None);
        assert_eq!(
            protocols_from_manifest_json(br#"{"metadata":{"protocol_versions":[6]}}"#),
            None
        );
    }

    fn zip_with(entries: &[(&str, &[u8])]) -> Vec<u8> {
        use std::io::Write;
        let mut cursor = std::io::Cursor::new(Vec::new());
        {
            let mut w = zip::ZipWriter::new(&mut cursor);
            let opts: zip::write::FileOptions<'_, '_, ()> = zip::write::FileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);
            for (name, body) in entries {
                w.start_file(*name, opts).unwrap();
                w.write_all(body).unwrap();
            }
            w.finish().unwrap();
        }
        cursor.into_inner()
    }

    fn scratch_file(name: &str, body: &[u8]) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("tf-origin-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(name);
        std::fs::write(&path, body).unwrap();
        path
    }

    #[tokio::test]
    async fn manifest_protocols_are_read_from_the_archive() {
        let zip = zip_with(&[
            ("terraform-provider-x_v1.0.0", b"placeholder"),
            (
                REGISTRY_MANIFEST_NAME,
                br#"{"version":1,"metadata":{"protocol_versions":["6.0"]}}"#,
            ),
        ]);
        let path = scratch_file("p.zip", &zip);
        assert_eq!(
            read_manifest_protocols(path.clone()).await,
            Some(protocols(&["6.0"]))
        );
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[tokio::test]
    async fn manifest_protocols_are_none_for_missing_oversized_or_non_zip() {
        let no_manifest = scratch_file("a.zip", &zip_with(&[("terraform-provider-x_v1", b"x")]));
        assert_eq!(read_manifest_protocols(no_manifest.clone()).await, None);

        let big = vec![b' '; (REGISTRY_MANIFEST_MAX_BYTES + 1) as usize];
        let oversized = scratch_file("b.zip", &zip_with(&[(REGISTRY_MANIFEST_NAME, &big)]));
        assert_eq!(read_manifest_protocols(oversized.clone()).await, None);

        let not_zip = scratch_file("c.zip", b"definitely not a zip");
        assert_eq!(read_manifest_protocols(not_zip.clone()).await, None);

        assert_eq!(
            read_manifest_protocols(std::path::PathBuf::from("/nonexistent/nope.zip")).await,
            None
        );
        for p in [no_manifest, oversized, not_zip] {
            std::fs::remove_dir_all(p.parent().unwrap()).ok();
        }
    }

    #[test]
    fn protocols_from_metadata_default_for_legacy_or_garbage() {
        assert_eq!(provider_protocols_from_metadata(None), protocols(&["5.0"]));
        let legacy = serde_json::json!({"kind": "provider"});
        assert_eq!(
            provider_protocols_from_metadata(Some(&legacy)),
            protocols(&["5.0"])
        );
        let garbage = serde_json::json!({"protocols": ["x"]});
        assert_eq!(
            provider_protocols_from_metadata(Some(&garbage)),
            protocols(&["5.0"])
        );
        let recorded = serde_json::json!({"protocols": ["6.0"]});
        assert_eq!(
            provider_protocols_from_metadata(Some(&recorded)),
            protocols(&["6.0"])
        );
    }

    #[test]
    fn version_list_unions_protocols_across_platform_packages() {
        let rows = vec![
            (
                "1.0.0".to_string(),
                Some(serde_json::json!({"os":"linux","arch":"amd64","protocols":["6.0"]})),
                "ns/t/1.0.0/linux/amd64".to_string(),
            ),
            (
                "1.0.0".to_string(),
                Some(serde_json::json!({"os":"linux","arch":"arm64"})),
                "ns/t/1.0.0/linux/arm64".to_string(),
            ),
        ];
        let versions = provider_versions_from_rows(&rows);
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0]["protocols"], serde_json::json!(["5.0", "6.0"]));
    }

    // -- host-level discovery ----------------------------------------------------

    fn discovery_router(state: SharedState) -> Router {
        Router::new()
            .route("/.well-known/terraform.json", get(host_service_discovery))
            .with_state(state)
    }

    #[tokio::test]
    async fn host_discovery_is_404_when_no_default_repo_is_configured() {
        // Never touches the database: the unset case short-circuits.
        let state = tdh::build_state(tdh::lazy_pool(), "/nonexistent-storage");
        let (status, body) = tdh::send(
            discovery_router(state),
            tdh::get("/.well-known/terraform.json".to_string()),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(String::from_utf8_lossy(&body).contains("No default Terraform registry"));
    }

    #[tokio::test]
    async fn host_discovery_points_at_the_configured_terraform_repo() {
        let Some(fx) = tdh::Fixture::setup("local", "terraform").await else {
            return;
        };
        let key = fx.repo_key.clone();
        let state = tdh::build_state_with(
            fx.pool.clone(),
            &fx.storage_dir.to_string_lossy(),
            move |c| c.terraform_default_repo = Some(key),
        );
        let (status, body) = tdh::send(
            discovery_router(state),
            tdh::get("/.well-known/terraform.json".to_string()),
        )
        .await;
        fx.teardown().await;
        assert_eq!(status, StatusCode::OK);
        let doc: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            doc["providers.v1"],
            format!("/terraform/{}/v1/providers/", fx.repo_key)
        );
        assert_eq!(doc, build_service_discovery_json(&fx.repo_key));
    }

    #[tokio::test]
    async fn host_discovery_hides_missing_and_non_terraform_repos_behind_one_404() {
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let mut bodies = Vec::new();
        for configured in [fx.repo_key.clone(), "no-such-repo-key".to_string()] {
            let state = tdh::build_state_with(
                fx.pool.clone(),
                &fx.storage_dir.to_string_lossy(),
                move |c| c.terraform_default_repo = Some(configured),
            );
            let (status, body) = tdh::send(
                discovery_router(state),
                tdh::get("/.well-known/terraform.json".to_string()),
            )
            .await;
            assert_eq!(status, StatusCode::NOT_FOUND);
            bodies.push(body);
        }
        fx.teardown().await;
        assert_eq!(
            bodies[0], bodies[1],
            "the 404 must not reveal which case it was"
        );
    }

    // -- hosted registry end to end (router level) ----------------------------------

    async fn attach_key(fx: &tdh::Fixture, key_type: &str) -> String {
        let svc = SigningService::new(fx.pool.clone(), &fx.state.config.jwt_secret);
        let key = svc
            .create_key(CreateKeyRequest {
                repository_id: Some(fx.repo_id),
                name: format!("tf-sign-{}", fx.repo_key),
                key_type: key_type.to_string(),
                algorithm: "rsa2048".to_string(),
                uid_name: Some("AK Terraform".to_string()),
                uid_email: Some("tf@example.com".to_string()),
                created_by: None,
            })
            .await
            .expect("create signing key");
        svc.update_signing_config(fx.repo_id, Some(key.id), true, false, false)
            .await
            .expect("attach signing key");
        key.public_key_pem
    }

    async fn upload(
        fx: &tdh::Fixture,
        version: &str,
        platform: &str,
        body: &[u8],
        protocols_header: Option<&str>,
    ) -> StatusCode {
        let mut req = Request::builder().method("PUT").uri(format!(
            "{}/{}/v1/providers/ns/ty/{}/{}",
            MOUNT_PREFIX, fx.repo_key, version, platform
        ));
        if let Some(value) = protocols_header {
            req = req.header(PROTOCOLS_HEADER, value);
        }
        let (status, _) = tdh::send(
            fx.router_with_auth(mounted()),
            req.body(axum::body::Body::from(body.to_vec())).unwrap(),
        )
        .await;
        status
    }

    async fn get_path(fx: &tdh::Fixture, suffix: &str) -> (StatusCode, bytes::Bytes) {
        tdh::send(
            fx.router_anon(mounted()),
            tdh::get(format!(
                "{}/{}/v1/providers/ns/ty/{}",
                MOUNT_PREFIX, fx.repo_key, suffix
            )),
        )
        .await
    }

    #[tokio::test]
    async fn hosted_origin_registry_serves_verifiable_signed_checksums() {
        let Some(fx) = tdh::Fixture::setup("local", "terraform").await else {
            return;
        };
        let amd64: &[u8] = b"PK placeholder provider zip amd64";
        let arm64: &[u8] = b"PK placeholder provider zip arm64";
        assert!(upload(&fx, "1.0.0", "linux/amd64", amd64, Some("6.0"))
            .await
            .is_success());
        assert!(upload(&fx, "1.0.0", "linux/arm64", arm64, None)
            .await
            .is_success());

        // A package uploaded before any key existed: legacy document, no URLs.
        let (status, body) = get_path(&fx, "1.0.0/download/linux/amd64").await;
        assert_eq!(status, StatusCode::OK);
        let legacy: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(legacy.get("shasums_url").is_none());
        assert_eq!(legacy["protocols"], serde_json::json!(["6.0"]));

        // Fail closed without a signing key.
        let (status, _) = get_path(&fx, "1.0.0/SHA256SUMS").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, _) = get_path(&fx, "1.0.0/SHA256SUMS.sig").await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // Attaching a key needs no re-upload: the document is computed from the
        // stored artifacts.
        let public_key = attach_key(&fx, "gpg").await;

        let (status, sums) = get_path(&fx, "1.0.0/SHA256SUMS").await;
        assert_eq!(status, StatusCode::OK);
        let expected = build_provider_shasums(
            "ty",
            "1.0.0",
            &[
                pkg("linux", "amd64", &sha256_hex(amd64)),
                pkg("linux", "arm64", &sha256_hex(arm64)),
            ],
        );
        assert_eq!(String::from_utf8_lossy(&sums), expected);
        assert_eq!(expected.lines().count(), 2);

        // Deterministic bytes across requests.
        let (_, again) = get_path(&fx, "1.0.0/SHA256SUMS").await;
        assert_eq!(sums, again);

        // The detached signature verifies against the advertised key.
        let (status, sig) = get_path(&fx, "1.0.0/SHA256SUMS.sig").await;
        assert_eq!(status, StatusCode::OK);
        // Binary packets (what OpenTofu expects), not ASCII armor.
        assert!(!sig.starts_with(b"-----BEGIN"));
        assert_eq!(sig[0] & 0x80, 0x80, "must start with an OpenPGP packet tag");
        let armored_sig = {
            use pgp::composed::{Deserializable, StandaloneSignature};
            use pgp::ArmorOptions;
            StandaloneSignature::from_bytes(&sig[..])
                .unwrap()
                .to_armored_string(ArmorOptions::default())
                .unwrap()
        };
        verify_detached(&public_key, &sums, &armored_sig).expect("signature must verify");
        // ... and not against different data.
        assert!(verify_detached(&public_key, b"tampered", &armored_sig).is_err());

        // The package document now advertises everything a client needs.
        let (status, body) = get_path(&fx, "1.0.0/download/linux/amd64").await;
        assert_eq!(status, StatusCode::OK);
        let doc: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            doc["shasums_url"],
            format!(
                "/terraform/{}/v1/providers/ns/ty/1.0.0/SHA256SUMS",
                fx.repo_key
            )
        );
        assert_eq!(
            doc["shasums_signature_url"],
            format!("{}.sig", doc["shasums_url"].as_str().unwrap())
        );
        assert_eq!(doc["shasum"], sha256_hex(amd64));
        let keys = doc["signing_keys"]["gpg_public_keys"].as_array().unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0]["ascii_armor"], public_key);
        assert!(!keys[0]["key_id"].as_str().unwrap().is_empty());

        // The advertised URLs resolve against the document's own URL.
        let doc_url = format!(
            "http://h{}/{}/v1/providers/ns/ty/1.0.0/download/linux/amd64",
            MOUNT_PREFIX, fx.repo_key
        );
        let advertised = resolve_url(&doc_url, doc["shasums_url"].as_str().unwrap());
        let (status, via_doc) = tdh::send(fx.router_anon(mounted()), tdh::get(advertised)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(via_doc, sums);

        // Unknown version.
        let (status, _) = get_path(&fx, "9.9.9/SHA256SUMS").await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        fx.teardown().await;
    }

    /// Terraform/OpenTofu fetch `download_url`, `shasums_url` and
    /// `shasums_signature_url` without the credentials they sent for the
    /// package document, so an authenticated caller must get a single-use
    /// ticket bound to each exact path (as for the #3588 mirror archives),
    /// and an anonymous caller the plain paths.
    #[tokio::test]
    async fn package_document_tickets_every_advertised_url_for_an_authenticated_caller() {
        use crate::services::auth_config_service::AuthConfigService;
        let Some(fx) = tdh::Fixture::setup("local", "terraform").await else {
            return;
        };
        let zip: &[u8] = b"PK placeholder provider zip for tickets";
        assert!(upload(&fx, "2.0.0", "linux/amd64", zip, None)
            .await
            .is_success());
        attach_key(&fx, "gpg").await;

        let doc_path = format!(
            "{}/{}/v1/providers/ns/ty/2.0.0/download/linux/amd64",
            MOUNT_PREFIX, fx.repo_key
        );
        let (status, body) =
            tdh::send(fx.router_with_auth(mounted()), tdh::get(doc_path.clone())).await;
        assert_eq!(status, StatusCode::OK);
        let doc: serde_json::Value = serde_json::from_slice(&body).unwrap();

        let base = format!("{}/{}/v1/providers/ns/ty/2.0.0", MOUNT_PREFIX, fx.repo_key);
        let expected = [
            (
                "download_url",
                format!("{base}/binary/linux/amd64"),
                "terraform-provider-archive",
            ),
            (
                "shasums_url",
                format!("{base}/SHA256SUMS"),
                "terraform-provider-shasums",
            ),
            (
                "shasums_signature_url",
                format!("{base}/SHA256SUMS.sig"),
                "terraform-provider-shasums-sig",
            ),
        ];
        let mut redeemed = Vec::new();
        for (field, path, _) in &expected {
            let url = doc[*field].as_str().unwrap_or_default().to_string();
            let (url_path, ticket) = url
                .split_once("?ticket=")
                .unwrap_or_else(|| panic!("{field} must carry a ticket, got {url:?}"));
            assert_eq!(url_path, path, "{field} path");
            redeemed.push(
                AuthConfigService::validate_download_ticket(&fx.pool, ticket)
                    .await
                    .unwrap_or_else(|e| panic!("{field} ticket must be live: {e}")),
            );
        }

        let (status, body) = tdh::send(fx.router_anon(mounted()), tdh::get(doc_path.clone())).await;
        assert_eq!(status, StatusCode::OK);
        let anon: serde_json::Value = serde_json::from_slice(&body).unwrap();

        let user_id = fx.user_id;
        fx.teardown().await;

        for ((field, path, purpose), ticket) in expected.iter().zip(redeemed) {
            assert_eq!(ticket.user_id, user_id, "{field} ticket owner");
            assert_eq!(ticket.purpose, *purpose, "{field} ticket purpose");
            assert_eq!(
                ticket.resource_path.as_deref(),
                Some(path.as_str()),
                "{field} ticket must be bound to exactly the advertised path"
            );
            assert!(
                ticket.repo_scope.is_some(),
                "{field} ticket must carry the caller's repository scope"
            );
            assert_eq!(anon[*field], *path, "anonymous {field} carries no ticket");
        }
    }

    /// A `SHA256SUMS.sig` is reused per (key, checksum list) instead of
    /// decrypting the private key on every anonymous request.
    #[tokio::test]
    async fn checksum_signature_is_reused_for_the_same_key_and_checksums() {
        let Some(fx) = tdh::Fixture::setup("local", "terraform").await else {
            return;
        };
        assert!(upload(&fx, "3.0.0", "linux/amd64", b"PK sig cache", None)
            .await
            .is_success());
        attach_key(&fx, "gpg").await;

        let (status, first) = get_path(&fx, "3.0.0/SHA256SUMS.sig").await;
        assert_eq!(status, StatusCode::OK);
        let (_, second) = get_path(&fx, "3.0.0/SHA256SUMS.sig").await;
        // A fresh signature embeds a new creation time, so identical bytes
        // mean the cached one was served.
        assert_eq!(first, second);

        // A new package changes the checksum list, which is signed afresh.
        assert!(
            upload(&fx, "3.0.0", "linux/arm64", b"PK sig cache arm", None)
                .await
                .is_success()
        );
        let (status, third) = get_path(&fx, "3.0.0/SHA256SUMS.sig").await;
        assert_eq!(status, StatusCode::OK);
        assert_ne!(first, third);

        fx.teardown().await;
    }

    fn resolve_url(document_url: &str, advertised: &str) -> String {
        let base = reqwest::Url::parse(document_url).unwrap();
        base.join(advertised).unwrap()[url::Position::BeforePath..].to_string()
    }

    #[tokio::test]
    async fn non_openpgp_key_fails_closed_and_keeps_the_legacy_document() {
        let Some(fx) = tdh::Fixture::setup("local", "terraform").await else {
            return;
        };
        assert!(upload(&fx, "1.0.0", "linux/amd64", b"zip", None)
            .await
            .is_success());
        attach_key(&fx, "rsa").await;

        let (status, _) = get_path(&fx, "1.0.0/SHA256SUMS").await;
        assert_eq!(status, StatusCode::CONFLICT);
        let (status, _) = get_path(&fx, "1.0.0/SHA256SUMS.sig").await;
        assert_eq!(status, StatusCode::CONFLICT);

        let (status, body) = get_path(&fx, "1.0.0/download/linux/amd64").await;
        assert_eq!(status, StatusCode::OK);
        let doc: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(doc.get("shasums_url").is_none());
        assert!(doc["signing_keys"]["gpg_public_keys"]
            .as_array()
            .unwrap()
            .is_empty());
        fx.teardown().await;
    }

    #[tokio::test]
    async fn upload_rejects_malformed_protocols_header_and_records_manifest_protocols() {
        let Some(fx) = tdh::Fixture::setup("local", "terraform").await else {
            return;
        };
        assert_eq!(
            upload(&fx, "1.0.0", "linux/amd64", b"zip", Some("bogus")).await,
            StatusCode::BAD_REQUEST
        );

        let manifest_zip = zip_with(&[
            ("terraform-provider-ty_v2.0.0", b"placeholder"),
            (
                REGISTRY_MANIFEST_NAME,
                br#"{"version":1,"metadata":{"protocol_versions":["6.0"]}}"#,
            ),
        ]);
        assert!(upload(&fx, "2.0.0", "linux/amd64", &manifest_zip, None)
            .await
            .is_success());
        let (status, body) = get_path(&fx, "versions").await;
        assert_eq!(status, StatusCode::OK);
        let doc: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let versions = doc["versions"].as_array().unwrap();
        assert_eq!(versions.len(), 1, "the rejected upload must not be stored");
        assert_eq!(versions[0]["version"], "2.0.0");
        assert_eq!(versions[0]["protocols"], serde_json::json!(["6.0"]));
        fx.teardown().await;
    }

    #[tokio::test]
    async fn checksums_are_not_published_for_non_hosted_repos() {
        let Some(fx) = tdh::Fixture::setup("remote", "terraform").await else {
            return;
        };
        let (status, _) = get_path(&fx, "1.0.0/SHA256SUMS").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, _) = get_path(&fx, "1.0.0/SHA256SUMS.sig").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        fx.teardown().await;
    }
}

#[cfg(ak_test_shard = "handlers-2")]
#[cfg(test)]
mod mirror_archive_redirect {
    use super::{serve_mirror_archive, MirrorRemote};
    use crate::api::handlers::test_db_helpers as tdh;
    use crate::api::middleware::download_telemetry::DownloadContext;
    use crate::services::proxy_cache_scope::ProxyCacheScope;
    use crate::services::proxy_service::ProxyService;
    use axum::http::{header, StatusCode};
    use axum::response::Response;

    const REPO_KEY: &str = "tf-mirror";
    const UPSTREAM: &str = "https://registry.invalid";
    const CACHE_PATH: &str =
        "hashicorp/null/3.2.3/linux/amd64/terraform-provider-null_3.2.3_linux_amd64.zip";

    /// Serve a fresh cached archive from a presign-capable cache. The archive
    /// URL does not resolve, so any upstream fetch would fail the request.
    async fn serve(is_head: bool) -> Response {
        let pool = tdh::lazy_pool();
        let scope = ProxyCacheScope::unscoped();
        let (proxy, backend) = tdh::build_scoped_presign_proxy(pool.clone(), scope.clone());
        backend.seed_fresh_entry(
            &ProxyService::cache_storage_key(&scope, REPO_KEY, CACHE_PATH).unwrap(),
            &ProxyService::cache_metadata_key(&scope, REPO_KEY, CACHE_PATH).unwrap(),
        );
        let dir = tempfile::tempdir().unwrap();
        let state = tdh::build_state_with_proxy_presigned(
            pool,
            dir.path().to_str().unwrap(),
            proxy.clone(),
        );
        let remote = MirrorRemote {
            repo: tdh::make_repo_info(
                uuid::Uuid::new_v4(),
                REPO_KEY,
                dir.path(),
                "remote",
                Some(UPSTREAM),
            ),
            upstream_url: UPSTREAM.to_string(),
            proxy: proxy.as_ref(),
        };
        let ctx = DownloadContext {
            client_ip: None,
            user_id: None,
            user_agent: None,
            is_head,
        };
        serve_mirror_archive(
            &state,
            &remote,
            REPO_KEY,
            &format!("{UPSTREAM}/p.zip"),
            CACHE_PATH,
            &ctx,
        )
        .await
        .unwrap_or_else(|err| err)
    }

    #[tokio::test]
    async fn cached_archive_is_redirected_to_object_storage() {
        let resp = serve(false).await;
        assert_eq!(resp.status(), StatusCode::FOUND);
        let loc = resp.headers()[header::LOCATION].to_str().unwrap();
        assert!(loc.contains(CACHE_PATH), "signed the wrong key: {loc}");
    }

    #[tokio::test]
    async fn head_is_answered_from_the_cache_not_redirected() {
        assert_eq!(serve(true).await.status(), StatusCode::OK);
    }
}
