//! MCP Registry package policy (#5253): resolve every `packages[]` entry of a
//! server.json to an artifact this instance hosts or proxies, pin it, hold the
//! pin, and collect the backing-package gates `decide_mcp_serve` evaluates.
//!
//! Every lookup is a database (or object storage) read. Nothing here opens an
//! outbound connection: a package that has not been published to, or pulled
//! through, one of this instance's repositories is refused, never fetched.

use std::collections::{BTreeMap, HashMap, HashSet};

use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::formats::mcp::{
    self, BackingGate, GateOutcome, McpError, OciChild, PackagePin, PackagePolicy, ResolvedPin,
    ServerJson, SubmittedRef,
};
use crate::models::repository::RepositoryFormat;
use crate::storage::StorageLocation;

/// `repository_config` keys of an MCP repository.
pub const POLICY_KEY: &str = "mcp_package_policy";
pub const REPOS_KEY: &str = "mcp_package_repos";
pub const NAMESPACE_ALLOW_KEY: &str = "mcp_namespace_allow";

/// A repository a `registryType` resolves to.
#[derive(Debug, Clone)]
pub struct BackingRepo {
    pub id: Uuid,
    pub key: String,
    pub repo_type: String,
    pub format: String,
    pub upstream_url: Option<String>,
    pub location: StorageLocation,
}

impl BackingRepo {
    fn is_remote(&self) -> bool {
        self.repo_type == "remote"
    }

    fn is_virtual(&self) -> bool {
        self.repo_type == "virtual"
    }
}

/// The package settings of one MCP repository.
#[derive(Debug, Clone)]
pub struct McpSettings {
    pub policy: PackagePolicy,
    pub repos: BTreeMap<String, BackingRepo>,
    pub namespace_allow: Vec<String>,
}

fn db_err(e: impl std::fmt::Display) -> McpError {
    McpError::Internal(e.to_string())
}

/// Whether a repository of `format` (a `repository_format` label) can back
/// packages of `registry_type`: the format's handler must be the registry
/// type's (`yarn`/`pnpm` repositories back `npm`, `docker`/`podman` back `oci`).
pub fn format_backs(registry_type: &str, format: &str) -> bool {
    if !mcp::ARTIFACT_REGISTRY_TYPES.contains(&registry_type) && registry_type != "oci" {
        return false;
    }
    crate::services::repository_service::parse_format_str(format)
        .is_some_and(|f: RepositoryFormat| f.handler_key() == registry_type)
}

/// Parse the stored `mcp_package_repos` value (`{"npm": "<repo key>", ...}`).
pub fn parse_package_repos(value: &str) -> Result<BTreeMap<String, String>, String> {
    let map: BTreeMap<String, String> = serde_json::from_str(value)
        .map_err(|_| "must be a JSON object of registryType to repository key".to_string())?;
    for (ty, key) in &map {
        if !(mcp::ARTIFACT_REGISTRY_TYPES.contains(&ty.as_str()) || ty == "oci") {
            return Err(format!(
                "`{ty}` is not a registryType AK can back (npm, pypi, nuget, cargo, oci)"
            ));
        }
        if key.trim().is_empty() {
            return Err(format!("`{ty}` names no repository"));
        }
    }
    Ok(map)
}

/// Parse the stored `mcp_namespace_allow` value (a JSON array of prefixes).
pub fn parse_namespace_allow(value: &str) -> Result<Vec<String>, String> {
    let list: Vec<String> = serde_json::from_str(value)
        .map_err(|_| "must be a JSON array of namespace prefixes".to_string())?;
    if list.iter().any(|p| {
        let p = p.trim();
        p.is_empty()
            || !p
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
    }) {
        return Err("each namespace prefix uses letters, digits, `.` and `-`".to_string());
    }
    Ok(list)
}

/// Whether `caller` may name `repo_id` as a backing repository: the token
/// scope must cover it, and the caller must be an instance administrator,
/// the repository public, or hold `read` on it through a grant. An
/// `internal` repository needs the grant too (as a Virtual member does,
/// #4346): a mapping re-exports what it holds (existence, versions, digests)
/// to every reader of the MCP registry, who may be a wider audience.
async fn caller_may_map(
    db: &PgPool,
    caller: &crate::api::middleware::auth::AuthExtension,
    repo_id: Uuid,
) -> crate::error::Result<bool> {
    use crate::services::repository_service::{RepoAccess, RepositoryService};
    if !caller.can_access_repo(repo_id) {
        return Ok(false);
    }
    if caller.is_admin {
        return Ok(true);
    }
    let service = RepositoryService::new(db.clone());
    let repo = service.get_by_id(repo_id).await?;
    if repo.visibility.allows_anonymous_read() {
        return Ok(true);
    }
    service
        .user_can_access_repo(repo_id, caller.user_id, RepoAccess::READ)
        .await
}

/// Validate MCP settings submitted through the repository API (#5253) and
/// return the `repository_config` rows to write. Settings on a non-MCP
/// repository are refused; creating an MCP repository records the default
/// `own-repos` policy explicitly. Every repository `mcp_package_repos` names
/// must be one `caller` may read ([`caller_may_map`]); one that does not
/// exist and one the caller may not read get the same answer, so the setting
/// is not an existence oracle.
pub async fn settings_to_store(
    db: &PgPool,
    caller: &crate::api::middleware::auth::AuthExtension,
    format: &RepositoryFormat,
    policy: Option<&str>,
    repos: Option<&BTreeMap<String, String>>,
    namespace_allow: Option<&[String]>,
    creating: bool,
) -> crate::error::Result<Vec<(&'static str, String)>> {
    use crate::error::AppError;
    let supplied = policy.is_some() || repos.is_some() || namespace_allow.is_some();
    if format != &RepositoryFormat::Mcp {
        if supplied {
            return Err(AppError::Validation(
                "mcp_package_policy, mcp_package_repos and mcp_namespace_allow are only valid \
                 for MCP repositories"
                    .to_string(),
            ));
        }
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    match policy {
        Some(p) => {
            let parsed = PackagePolicy::parse(p).ok_or_else(|| {
                AppError::Validation("mcp_package_policy must be `own-repos` or `open`".to_string())
            })?;
            out.push((POLICY_KEY, parsed.as_str().to_string()));
        }
        None if creating => out.push((POLICY_KEY, PackagePolicy::OwnRepos.as_str().to_string())),
        None => {}
    }
    if let Some(map) = repos {
        let text = serde_json::to_string(map).unwrap_or_default();
        parse_package_repos(&text)
            .map_err(|e| AppError::Validation(format!("mcp_package_repos {e}")))?;
        let keys: Vec<String> = map.values().cloned().collect();
        let found = repos_by_key(db, &keys)
            .await
            .map_err(|e| AppError::Database(e.detail()))?;
        for (ty, key) in map {
            let unknown = || {
                AppError::Validation(format!(
                    "mcp_package_repos: repository '{key}' does not exist"
                ))
            };
            let Some(r) = found.iter().find(|r| &r.key == key) else {
                return Err(unknown());
            };
            if !caller_may_map(db, caller, r.id).await? {
                return Err(unknown());
            }
            if !format_backs(ty, &r.format) {
                return Err(AppError::Validation(format!(
                    "mcp_package_repos: `{ty}` needs a {ty} repository; '{key}' is a {} repository",
                    r.format
                )));
            }
        }
        out.push((REPOS_KEY, text));
    }
    if let Some(list) = namespace_allow {
        let text = serde_json::to_string(list).unwrap_or_default();
        parse_namespace_allow(&text)
            .map_err(|e| AppError::Validation(format!("mcp_namespace_allow {e}")))?;
        out.push((NAMESPACE_ALLOW_KEY, text));
    }
    Ok(out)
}

/// Whether a repository of `format` and `repo_type` may be created in this
/// release: MCP registries are hosted only (Local, Staging).
pub fn creatable(format: &RepositoryFormat, repo_type: &str) -> Result<(), &'static str> {
    if format == &RepositoryFormat::Mcp
        && !matches!(repo_type, "local" | "staging" | "remote" | "virtual")
    {
        return Err("MCP registries support Local, Staging, Remote and Virtual repositories");
    }
    Ok(())
}

/// Look repositories up by key.
pub async fn repos_by_key(db: &PgPool, keys: &[String]) -> Result<Vec<BackingRepo>, McpError> {
    let rows = sqlx::query(
        "SELECT id, key, repo_type::text AS repo_type, format::text AS format, upstream_url, \
                storage_backend, storage_path \
         FROM repositories WHERE key = ANY($1) AND key NOT LIKE '~deleting~%'",
    )
    .bind(keys)
    .fetch_all(db)
    .await
    .map_err(db_err)?;
    Ok(rows
        .iter()
        .map(|r| BackingRepo {
            id: r.get("id"),
            key: r.get("key"),
            repo_type: r.get("repo_type"),
            format: r.get("format"),
            upstream_url: r.get("upstream_url"),
            location: StorageLocation {
                backend: r.get("storage_backend"),
                path: r.get("storage_path"),
            },
        })
        .collect())
}

/// Load an MCP repository's package policy, backing repositories and
/// namespace allowlist. An absent policy is `own-repos`. A mapping that does
/// not resolve to a repository of the right format is a configuration error
/// (the settings write path validates on save, so this is a 500).
pub async fn load_settings(db: &PgPool, repo_id: Uuid) -> Result<McpSettings, McpError> {
    let rows: Vec<(String, Option<String>)> = sqlx::query_as(
        "SELECT key, value FROM repository_config \
         WHERE repository_id = $1 AND key = ANY($2)",
    )
    .bind(repo_id)
    .bind([POLICY_KEY, REPOS_KEY, NAMESPACE_ALLOW_KEY])
    .fetch_all(db)
    .await
    .map_err(db_err)?;
    let value = |k: &str| {
        rows.iter()
            .find(|(key, _)| key == k)
            .and_then(|(_, v)| v.clone())
            .filter(|v| !v.trim().is_empty())
    };
    let misconfigured = |what: &str, why: String| {
        tracing::error!(repository_id = %repo_id, key = what, "MCP repository setting is invalid: {why}");
        McpError::Misconfigured(format!("{what}: {why}"))
    };
    let policy = match value(POLICY_KEY) {
        None => PackagePolicy::OwnRepos,
        Some(v) => PackagePolicy::parse(&v)
            .ok_or_else(|| misconfigured(POLICY_KEY, format!("unknown policy {v:?}")))?,
    };
    let namespace_allow = match value(NAMESPACE_ALLOW_KEY) {
        None => Vec::new(),
        Some(v) => parse_namespace_allow(&v).map_err(|e| misconfigured(NAMESPACE_ALLOW_KEY, e))?,
    };
    let mapping = match value(REPOS_KEY) {
        None => BTreeMap::new(),
        Some(v) => parse_package_repos(&v).map_err(|e| misconfigured(REPOS_KEY, e))?,
    };
    let found = repos_by_key(db, &mapping.values().cloned().collect::<Vec<_>>()).await?;
    let mut repos = BTreeMap::new();
    for (ty, key) in mapping {
        let repo = found.iter().find(|r| r.key == key).ok_or_else(|| {
            misconfigured(
                REPOS_KEY,
                format!("`{ty}` names unknown repository {key:?}"),
            )
        })?;
        if !format_backs(&ty, &repo.format) {
            return Err(misconfigured(
                REPOS_KEY,
                format!("`{ty}` names {key:?}, a {} repository", repo.format),
            ));
        }
        repos.insert(ty, repo.clone());
    }
    Ok(McpSettings {
        policy,
        repos,
        namespace_allow,
    })
}

/// The repositories whose rows a backing repository serves: its virtual
/// members for a Virtual, itself otherwise.
async fn content_repo_ids(db: &PgPool, repo: &BackingRepo) -> Result<Vec<Uuid>, McpError> {
    if !repo.is_virtual() {
        return Ok(vec![repo.id]);
    }
    sqlx::query_scalar(
        "SELECT member_repo_id FROM virtual_repo_members WHERE virtual_repo_id = $1 \
         ORDER BY priority",
    )
    .bind(repo.id)
    .fetch_all(db)
    .await
    .map_err(db_err)
}

/// The SQL predicate on `artifacts` that matches a package name as each
/// format's publish path stores it (`$2` name, `$3` version).
fn name_predicate(registry_type: &str) -> &'static str {
    match registry_type {
        // PEP 503: compare normalised forms; `$2` arrives normalised.
        "pypi" => "lower(regexp_replace(a.name, '[-_.]+', '-', 'g')) = $2 AND a.version = $3",
        // NuGet ids and versions are case-insensitive.
        "nuget" => "lower(a.name) = lower($2) AND lower(a.version) = lower($3)",
        // Cargo stores the lower-cased crate name.
        "cargo" => "lower(a.name) = lower($2) AND a.version = $3",
        // npm: exact (scoped names included).
        _ => "a.name = $2 AND a.version = $3",
    }
}

fn lookup_name(registry_type: &str, identifier: &str) -> String {
    match registry_type {
        "pypi" => crate::formats::pypi::PypiHandler::normalize_name(identifier),
        _ => identifier.to_string(),
    }
}

/// The base URL AK serves `registry_type` from `repo_key` under.
pub fn backing_base_url(base_url: &str, registry_type: &str, repo_key: &str) -> String {
    let base = base_url.trim_end_matches('/');
    match registry_type {
        "nuget" => format!("{base}/nuget/{repo_key}/v3/index.json"),
        other => format!("{base}/{other}/{repo_key}"),
    }
}

fn not_pulled_hint(repo: &BackingRepo) -> &'static str {
    if repo.is_remote() {
        "; pull it through this repository first"
    } else {
        ""
    }
}

async fn resolve_artifact_package(
    db: &PgPool,
    index: usize,
    pkg: &mcp::Package,
    repo: &BackingRepo,
    base_url: &str,
) -> Result<PackagePin, McpError> {
    if let Some(given) = pkg.registry_base_url.as_deref() {
        let own = backing_base_url(base_url, &pkg.registry_type, &repo.key);
        if given.trim_end_matches('/') != own.trim_end_matches('/') {
            return Err(McpError::ExternalRegistry {
                index,
                detail: format!(
                    "registryBaseUrl must be omitted or be this registry's {} repository ({own}); \
                     publish the package to it first",
                    pkg.registry_type
                ),
            });
        }
    }
    let version = pkg
        .version
        .as_deref()
        .ok_or(McpError::PackageVersionUnpinned { index })?;
    let repo_ids = content_repo_ids(db, repo).await?;
    let sql = format!(
        "SELECT a.id, a.checksum_sha256 FROM artifacts a \
         WHERE a.repository_id = ANY($1) AND a.is_deleted = false AND {} \
         ORDER BY a.path",
        name_predicate(&pkg.registry_type)
    );
    let rows: Vec<(Uuid, String)> = sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .bind(&repo_ids)
        .bind(lookup_name(&pkg.registry_type, &pkg.identifier))
        .bind(version)
        .fetch_all(db)
        .await
        .map_err(db_err)?;
    let Some((_, sha256)) = rows.first().cloned() else {
        return Err(McpError::PackageNotFound {
            index,
            detail: format!(
                "{} {}@{} is not in repository '{}'{}",
                pkg.registry_type,
                pkg.identifier,
                version,
                repo.key,
                not_pulled_hint(repo)
            ),
        });
    };
    Ok(PackagePin {
        index,
        registry_type: pkg.registry_type.clone(),
        submitted: SubmittedRef {
            identifier: pkg.identifier.clone(),
            version: Some(version.to_string()),
        },
        resolved: ResolvedPin {
            repository: repo.key.clone(),
            repository_id: repo.id,
            artifact_ids: rows.iter().map(|(id, _)| *id).collect(),
            sha256: Some(sha256),
            name: None,
            tag: None,
            digest: None,
            media_type: None,
            children: Vec::new(),
            gate_digest: None,
            resolved_at: Utc::now(),
            warnings: Vec::new(),
        },
        drift: None,
    })
}

/// Hosts that all name Docker Hub.
fn same_registry_host(a: &str, b: &str) -> bool {
    let canon = |h: &str| -> String {
        let h = h.to_ascii_lowercase();
        match h.as_str() {
            "docker.io"
            | "index.docker.io"
            | "registry-1.docker.io"
            | "registry.hub.docker.com" => "docker.io".to_string(),
            _ => h,
        }
    };
    canon(a) == canon(b)
}

/// The image names a submitted path may be stored under in the backing
/// repository: the path itself, and for Docker Hub official images the path
/// without `library/`.
fn oci_name_candidates(host: &str, path: &str) -> Vec<String> {
    let mut out = vec![path.to_string()];
    if same_registry_host(host, "docker.io") {
        if let Some(short) = path.strip_prefix("library/") {
            out.push(short.to_string());
        }
    }
    out
}

/// The image path inside `repo` an identifier names, or why it is foreign.
fn oci_backing_path(r: &mcp::OciRef, repo: &BackingRepo, base_url: &str) -> Result<String, String> {
    // An identifier that already names this instance's repository.
    if same_registry_host(&r.host, &mcp::host_of(base_url)) {
        if let Some(rest) = r.path.strip_prefix(&format!("{}/", repo.key)) {
            return Ok(rest.to_string());
        }
    }
    if repo.is_remote() {
        let upstream = repo
            .upstream_url
            .as_deref()
            .map(mcp::host_of)
            .unwrap_or_default();
        if !same_registry_host(&r.host, &upstream) {
            return Err(format!(
                "image host '{}' is not the upstream of repository '{}' ({upstream})",
                r.host, repo.key
            ));
        }
    }
    Ok(r.path.clone())
}

/// One manifest found in the backing repository.
struct FoundManifest {
    repo_id: Uuid,
    name: String,
    digest: String,
    media_type: String,
    tag_digest_mismatch: bool,
}

async fn find_oci_manifest(
    db: &PgPool,
    repo_ids: &[Uuid],
    names: &[String],
    r: &mcp::OciRef,
) -> Result<Option<FoundManifest>, McpError> {
    let tagged: Option<(Uuid, String, String, String)> = match r.tag.as_deref() {
        Some(tag) => sqlx::query_as(
            "SELECT repository_id, name, manifest_digest, manifest_content_type FROM oci_tags \
             WHERE repository_id = ANY($1) AND name = ANY($2) AND tag = $3 \
             ORDER BY array_position($1, repository_id), array_position($2, name) LIMIT 1",
        )
        .bind(repo_ids)
        .bind(names)
        .bind(tag)
        .fetch_optional(db)
        .await
        .map_err(db_err)?,
        None => None,
    };
    let Some(digest) = r.digest.as_deref() else {
        return Ok(
            tagged.map(|(repo_id, name, digest, media_type)| FoundManifest {
                repo_id,
                name,
                digest,
                media_type,
                tag_digest_mismatch: false,
            }),
        );
    };
    // A digest was given: it is the pin, whatever the tag says now. It must
    // exist under the submitted image name (a tag row, or a manifest row at
    // `v2/<name>/manifests/...`), never merely somewhere in the repository.
    let by_digest: Option<(Uuid, String, String)> = sqlx::query_as(
        "SELECT repository_id, name, manifest_content_type FROM oci_tags \
         WHERE repository_id = ANY($1) AND name = ANY($2) AND manifest_digest = $3 \
         UNION ALL \
         SELECT m.repository_id, split_part(a.name, ':', 1), m.content_type FROM oci_manifests m \
           JOIN artifacts a ON a.repository_id = m.repository_id \
         WHERE m.repository_id = ANY($1) AND m.digest = $3 \
           AND a.is_deleted = false AND a.checksum_sha256 = $4 \
           AND split_part(a.name, ':', 1) = ANY($2) AND a.path LIKE 'v2/%/manifests/%' \
         LIMIT 1",
    )
    .bind(repo_ids)
    .bind(names)
    .bind(digest)
    .bind(hex_of(digest))
    .fetch_optional(db)
    .await
    .map_err(db_err)?;
    Ok(by_digest.map(|(repo_id, name, media_type)| FoundManifest {
        repo_id,
        name,
        digest: digest.to_string(),
        media_type,
        tag_digest_mismatch: tagged.as_ref().is_some_and(|t| t.2 != digest),
    }))
}

/// `os/arch[/variant]` children of an image index, attestation and unknown
/// platforms excluded (the same rule `resolve_scan_reference` applies).
pub fn index_children(body: &[u8]) -> Vec<OciChild> {
    let Ok(json) = serde_json::from_slice::<serde_json::Value>(body) else {
        return Vec::new();
    };
    let Some(manifests) = json.get("manifests").and_then(|m| m.as_array()) else {
        return Vec::new();
    };
    manifests
        .iter()
        .filter(|c| !crate::services::scanner_service::is_excluded_index_child(c))
        .filter_map(|c| {
            let digest = c.get("digest")?.as_str()?.to_string();
            let p = c.get("platform");
            let field = |k: &str| {
                p.and_then(|p| p.get(k))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string()
            };
            let mut platform = format!("{}/{}", field("os"), field("architecture"));
            let variant = field("variant");
            if !variant.is_empty() {
                platform = format!("{platform}/{variant}");
            }
            Some(OciChild { platform, digest })
        })
        .collect()
}

/// The digest the scanner gate keys on: an index's runner-arch child, else
/// the manifest itself.
pub fn gate_digest_for(body: &[u8], digest: &str) -> String {
    match crate::services::scanner_service::resolve_scan_reference(body, digest) {
        crate::services::scanner_service::ScanReferenceResolution::ResolvedIndexChild(d) => d,
        _ => digest.to_string(),
    }
}

fn hex_of(digest: &str) -> &str {
    digest.split_once(':').map(|(_, h)| h).unwrap_or(digest)
}

async fn resolve_oci_package(
    state: &crate::api::SharedState,
    index: usize,
    pkg: &mcp::Package,
    repo: &BackingRepo,
    base_url: &str,
) -> Result<PackagePin, McpError> {
    let r = match mcp::parse_oci_identifier(&pkg.identifier) {
        Ok(r) => r,
        Err(mcp::OciRefError::Floating) => return Err(McpError::OciFloatingTag { index }),
        Err(mcp::OciRefError::Invalid(m)) => {
            return Err(McpError::invalid(
                format!("packages[{index}].identifier"),
                m,
            ))
        }
    };
    let path = oci_backing_path(&r, repo, base_url)
        .map_err(|detail| McpError::ExternalRegistry { index, detail })?;
    let repo_ids = content_repo_ids(&state.db, repo).await?;
    let names = oci_name_candidates(&r.host, &path);
    let found = find_oci_manifest(&state.db, &repo_ids, &names, &r)
        .await?
        .ok_or_else(|| McpError::PackageNotFound {
            index,
            detail: format!(
                "image {} is not in repository '{}'{}",
                pkg.identifier,
                repo.key,
                not_pulled_hint(repo)
            ),
        })?;
    let location = if found.repo_id == repo.id {
        repo.location.clone()
    } else {
        repos_location(&state.db, found.repo_id).await?
    };
    let storage = state
        .storage_for_repo(&location)
        .map_err(|e| McpError::Internal(e.to_string()))?;
    let body = storage
        .get(&crate::api::handlers::oci_v2::manifest_storage_key(
            &found.digest,
        ))
        .await
        .map_err(|_| McpError::PackageNotFound {
            index,
            detail: format!(
                "the manifest of {} is not stored in repository '{}'",
                pkg.identifier, repo.key
            ),
        })?;
    if !crate::services::scanner_service::oci_manifest_is_scannable_image(&body) {
        return Err(McpError::OciNotAnImage { index });
    }
    let gate_digest = gate_digest_for(&body, &found.digest);
    let hexes = vec![
        hex_of(&found.digest).to_string(),
        hex_of(&gate_digest).to_string(),
    ];
    let artifact_ids: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM artifacts WHERE repository_id = $1 AND is_deleted = false \
         AND checksum_sha256 = ANY($2) AND path LIKE 'v2/%/manifests/%' ORDER BY path",
    )
    .bind(found.repo_id)
    .bind(&hexes)
    .fetch_all(&state.db)
    .await
    .map_err(db_err)?;
    if artifact_ids.is_empty() {
        // Nothing the download gate could evaluate: the image would be
        // served ungated, so it is not accepted as a pin.
        return Err(McpError::PackageNotFound {
            index,
            detail: format!(
                "image {} has no manifest record in repository '{}' to gate",
                pkg.identifier, repo.key
            ),
        });
    }
    let mut warnings = Vec::new();
    if found.tag_digest_mismatch {
        warnings.push("oci_tag_digest_mismatch".to_string());
    }
    Ok(PackagePin {
        index,
        registry_type: "oci".to_string(),
        submitted: SubmittedRef {
            identifier: pkg.identifier.clone(),
            version: None,
        },
        resolved: ResolvedPin {
            repository: repo.key.clone(),
            repository_id: found.repo_id,
            artifact_ids,
            sha256: None,
            name: Some(found.name),
            tag: r.tag.clone(),
            digest: Some(found.digest),
            media_type: Some(found.media_type),
            children: index_children(&body),
            gate_digest: Some(gate_digest),
            resolved_at: Utc::now(),
            warnings,
        },
        drift: None,
    })
}

async fn repos_location(db: &PgPool, repo_id: Uuid) -> Result<StorageLocation, McpError> {
    let (backend, path): (String, String) =
        sqlx::query_as("SELECT storage_backend, storage_path FROM repositories WHERE id = $1")
            .bind(repo_id)
            .fetch_one(db)
            .await
            .map_err(db_err)?;
    Ok(StorageLocation { backend, path })
}

/// Resolve and pin every package of `server` under the repository's policy.
/// `open` resolves nothing.
pub async fn resolve_packages(
    state: &crate::api::SharedState,
    settings: &McpSettings,
    server: &ServerJson,
    base_url: &str,
) -> Result<Vec<PackagePin>, McpError> {
    if settings.policy == PackagePolicy::Open {
        return Ok(Vec::new());
    }
    let mut pins = Vec::with_capacity(server.packages.len());
    for (index, pkg) in server.packages.iter().enumerate() {
        let Some(repo) = settings.repos.get(&pkg.registry_type) else {
            let mapped: Vec<&str> = settings.repos.keys().map(String::as_str).collect();
            return Err(McpError::ExternalRegistry {
                index,
                detail: format!(
                    "registryType '{}' has no backing repository in this registry (mapped: {}); \
                     publish the package to an AK repository and map it in the repository's \
                     MCP package settings",
                    pkg.registry_type,
                    if mapped.is_empty() {
                        "none".to_string()
                    } else {
                        mapped.join(", ")
                    }
                ),
            });
        };
        let pin = if pkg.registry_type == "oci" {
            resolve_oci_package(state, index, pkg, repo, base_url).await?
        } else {
            resolve_artifact_package(&state.db, index, pkg, repo, base_url).await?
        };
        pins.push(pin);
    }
    Ok(pins)
}

/// The retention hold of an OCI pin in a hosted backing repository.
///
/// * A digest-keyed `oci_tags` row: `storage_gc_service` keeps every manifest
///   an `oci_tags` row names, so a later tag move or tag delete cannot orphan
///   the pinned manifest. Tag listings hide digest-shaped tags.
/// * A digest-path `artifacts` row (`v2/<name>/manifests/<digest>`), copied
///   from the row that carries the digest now (a tag push writes only the
///   tag-path row, and the next push of that tag rewrites it in place). It is
///   the row the download gate and the scanner evaluate for the pinned bytes
///   once the tag has moved, so a single-arch pin stays gateable. The copy
///   keeps the source row's hold. Returns the id of a row it created (the
///   caller scans it after commit), `None` when one already existed.
///
/// A Remote repository already holds both from the pull.
pub async fn hold_oci_pin(
    conn: &mut sqlx::PgConnection,
    repo_id: Uuid,
    name: &str,
    digest: &str,
    media_type: &str,
) -> Result<Option<Uuid>, sqlx::Error> {
    sqlx::query(
        "INSERT INTO oci_tags (repository_id, name, tag, manifest_digest, manifest_content_type) \
         VALUES ($1, $2, $3, $3, $4) ON CONFLICT (repository_id, name, tag) DO NOTHING",
    )
    .bind(repo_id)
    .bind(name)
    .bind(digest)
    .bind(media_type)
    .execute(&mut *conn)
    .await?;
    sqlx::query_scalar(
        "INSERT INTO artifacts (repository_id, path, name, version, size_bytes, checksum_sha256, \
                                content_type, storage_key, uploaded_by, \
                                quarantine_status, quarantine_until, quarantine_source) \
         SELECT a.repository_id, $3, $2 || ':' || $4, $4, a.size_bytes, a.checksum_sha256, \
                a.content_type, a.storage_key, a.uploaded_by, \
                a.quarantine_status, a.quarantine_until, a.quarantine_source \
         FROM artifacts a \
         WHERE a.repository_id = $1 AND a.is_deleted = false AND a.checksum_sha256 = $5 \
           AND a.path LIKE 'v2/%/manifests/%' \
         ORDER BY (a.path = $3) DESC, a.path LIMIT 1 \
         ON CONFLICT (repository_id, path) DO NOTHING \
         RETURNING id",
    )
    .bind(repo_id)
    .bind(name)
    .bind(format!("v2/{name}/manifests/{digest}"))
    .bind(digest)
    .bind(hex_of(digest))
    .fetch_optional(&mut *conn)
    .await
}

/// Write the retention hold of every OCI pin whose resolved repository is
/// hosted. The resolved repository is where the manifest was found: for a
/// Virtual mapping that is the member, which may be Local even though the
/// mapped repository is not. Returns `(repository, artifact)` of each
/// manifest row the holds created.
pub async fn hold_pins(
    conn: &mut sqlx::PgConnection,
    pins: &[PackagePin],
) -> Result<Vec<(Uuid, Uuid)>, sqlx::Error> {
    let mut created = Vec::new();
    for pin in pins.iter().filter(|p| p.registry_type == "oci") {
        let r = &pin.resolved;
        let (Some(name), Some(digest), Some(mt)) = (&r.name, &r.digest, &r.media_type) else {
            continue;
        };
        let repo_type: Option<String> =
            sqlx::query_scalar("SELECT repo_type::text FROM repositories WHERE id = $1")
                .bind(r.repository_id)
                .fetch_optional(&mut *conn)
                .await?;
        if !matches!(repo_type.as_deref(), Some("local" | "staging")) {
            continue;
        }
        if let Some(id) = hold_oci_pin(conn, r.repository_id, name, digest, mt).await? {
            created.push((r.repository_id, id));
        }
    }
    Ok(created)
}

// ---------------------------------------------------------------------------
// Backing gates
// ---------------------------------------------------------------------------

/// Map the download gate's refusal onto a backing-package outcome.
pub fn outcome_for_gate_error(e: &crate::error::AppError) -> GateOutcome {
    use crate::error::AppError;
    match e {
        AppError::Conflict(_) => GateOutcome::Quarantine,
        AppError::Authorization(_) => GateOutcome::ScanPolicy,
        _ => GateOutcome::Unavailable,
    }
}

/// What the backing gates are evaluated with.
#[derive(Clone, Copy)]
pub struct GateCtx<'a> {
    pub db: &'a PgPool,
    /// The age-gate service; `None` fails a gated Remote closed.
    pub age_gate: Option<&'a crate::services::age_gate_service::AgeGateService>,
    /// Whether an age-gate hold records (or bumps) the version's pending
    /// review so an administrator can approve it, as a download of the
    /// package through its Remote would. Exact reads only: listings stay
    /// read-only.
    pub record_reviews: bool,
}

impl<'a> GateCtx<'a> {
    /// The context of a request served from `state`.
    pub fn of(state: &'a crate::api::AppState, record_reviews: bool) -> Self {
        Self {
            db: &state.db,
            age_gate: state.age_gate_service.as_deref(),
            record_reviews,
        }
    }
}

/// A live artifact row a pin's gate evaluates.
#[derive(Debug, Clone)]
struct GateRow {
    id: Uuid,
    repository_id: Uuid,
    checksum: String,
    created_at: DateTime<Utc>,
    quarantine_status: Option<String>,
    quarantine_until: Option<DateTime<Utc>>,
}

type GateRowTuple = (
    Uuid,
    Uuid,
    String,
    DateTime<Utc>,
    Option<String>,
    Option<DateTime<Utc>>,
);

fn gate_row(t: GateRowTuple) -> GateRow {
    GateRow {
        id: t.0,
        repository_id: t.1,
        checksum: t.2,
        created_at: t.3,
        quarantine_status: t.4,
        quarantine_until: t.5,
    }
}

const GATE_ROW_COLUMNS: &str = "id, repository_id, checksum_sha256::text, created_at, \
     quarantine_status, quarantine_until";

/// The artifact rows a pin's gate evaluates: the pinned rows for npm, PyPI,
/// NuGet and Cargo; for OCI the rows carrying the pinned digest (and its
/// gate child) NOW. A tag push rewrites its `v2/<name>/manifests/<tag>` row
/// in place, so the ids recorded at publish may name another image by the
/// time of a read; the digest-path row [`hold_oci_pin`] writes keeps the
/// pinned bytes addressable. A pin with no live row cannot be gated and is
/// unresolvable.
async fn gate_rows(db: &PgPool, pin: &PackagePin) -> Result<Vec<GateRow>, sqlx::Error> {
    let rows: Vec<GateRowTuple> = if pin.registry_type == "oci" {
        let r = &pin.resolved;
        let hexes: Vec<String> = [r.digest.as_deref(), r.gate_digest.as_deref()]
            .into_iter()
            .flatten()
            .map(|d| hex_of(d).to_string())
            .collect();
        sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT {GATE_ROW_COLUMNS} FROM artifacts WHERE repository_id = $1 \
             AND is_deleted = false AND checksum_sha256 = ANY($2) \
             AND path LIKE 'v2/%/manifests/%'"
        )))
        .bind(r.repository_id)
        .bind(&hexes)
        .fetch_all(db)
        .await?
    } else {
        sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT {GATE_ROW_COLUMNS} FROM artifacts WHERE id = ANY($1) AND is_deleted = false"
        )))
        .bind(&pin.resolved.artifact_ids)
        .fetch_all(db)
        .await?
    };
    Ok(rows.into_iter().map(gate_row).collect())
}

/// Whether the pinned OCI manifest still exists in its repository.
async fn oci_pin_present(db: &PgPool, pin: &PackagePin) -> Result<bool, sqlx::Error> {
    let r = &pin.resolved;
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM oci_tags WHERE repository_id = $1 AND manifest_digest = $2) \
             OR EXISTS (SELECT 1 FROM oci_manifests WHERE repository_id = $1 AND digest = $2)",
    )
    .bind(r.repository_id)
    .bind(r.digest.as_deref().unwrap_or_default())
    .fetch_one(db)
    .await
}

/// The policy inputs of one repository a pin's rows live in, read once per
/// evaluation.
#[derive(Debug, Clone)]
struct RepoFacts {
    age: crate::services::age_gate_service::AgeGateRepoParams,
    /// A Remote repository's proxy-scan severity gate, when scan-on-proxy is
    /// on for it.
    scan_gate: Option<crate::services::proxy_scan_service::ProxySeverityGate>,
}

impl RepoFacts {
    fn is_remote(&self) -> bool {
        self.age.repo_type == crate::models::repository::RepositoryType::Remote
    }
}

type FactsCache = HashMap<Uuid, RepoFacts>;

async fn repo_facts<'c>(
    db: &PgPool,
    cache: &'c mut FactsCache,
    repo_id: Uuid,
) -> Result<&'c RepoFacts, ()> {
    if let std::collections::hash_map::Entry::Vacant(slot) = cache.entry(repo_id) {
        let age = crate::services::age_gate_service::resolve_repo_params(db, repo_id)
            .await
            .map_err(|_| ())?;
        let scan_gate = if age.repo_type == crate::models::repository::RepositoryType::Remote {
            crate::api::handlers::proxy_helpers::remote_scan_policy(db, repo_id)
                .await
                .map_err(|_| ())?
                .map(|(_, gate)| gate)
        } else {
            None
        };
        slot.insert(RepoFacts { age, scan_gate });
    }
    Ok(&cache[&repo_id])
}

/// A stored proxy-scan verdict for `hex` refuses under `gate`. Unlike the
/// best-effort helper the NuGet repair path uses, an unreadable verdict is an
/// error here: the MCP gate fails closed.
async fn stored_verdict_blocks(
    db: &PgPool,
    hex: &str,
    gate: crate::services::proxy_scan_service::ProxySeverityGate,
) -> Result<bool, ()> {
    use crate::api::handlers::proxy_helpers::{stored_verdict_blocks_under_gate, PROXY_SCAN_TYPE};
    use crate::services::proxy_scan_service::{verdict_blocks, ProxyScanService};
    if gate.is_record_only() {
        return Ok(false);
    }
    match ProxyScanService::new(db.clone())
        .lookup_verdict(hex, PROXY_SCAN_TYPE)
        .await
    {
        Ok(Some(row)) if verdict_blocks(&row.verdict) => {
            Ok(stored_verdict_blocks_under_gate(Some(&row), gate))
        }
        Ok(_) => Ok(false),
        Err(_) => Err(()),
    }
}

/// The name the backing format's age gate keys a package on.
fn age_gate_package_name(registry_type: &str, identifier: &str) -> String {
    match registry_type {
        "cargo" => identifier.to_ascii_lowercase(),
        other => lookup_name(other, identifier),
    }
}

/// The age gate of one pin in one gated Remote, evaluated without an
/// upstream connection.
///
/// The basis is what this instance knows: under `first_seen` the recorded
/// observation; under `upstream_publish_time` the publish time a review of
/// the version recorded, and otherwise when this instance cached the
/// artifact, which is never before its upstream publish (so the age is never
/// overstated). Review rows are honoured exactly as the download path
/// honours them ([`decide_age_gate_check`]): a rejection holds, a manual
/// approval releases. Under [`GateCtx::record_reviews`] a hold records or
/// bumps the pending review (with the publish time if known, never the cache
/// time), so an administrator can approve it.
///
/// [`decide_age_gate_check`]: crate::services::age_gate_service::decide_age_gate_check
async fn age_gate_outcome(
    ctx: GateCtx<'_>,
    facts: &RepoFacts,
    pin: &PackagePin,
    cached_at: DateTime<Utc>,
) -> Result<Option<GateOutcome>, ()> {
    use crate::services::age_gate_service::{
        decide_age_gate_check, review_identity_match, upstream_fingerprint, AgeGateCheckAction,
        AgeGateDecision, AgeGateMode, AgeGateService, ReviewIdentityMatch, ReviewPolicyView,
    };
    let params = &facts.age;
    if !AgeGateService::gating_requested(params)
        || crate::formats::age_gate_spec(&params.format).is_none()
    {
        // No gate asked for, or a format with no age-gate hook (OCI, NuGet).
        return Ok(None);
    }
    AgeGateService::require_enforceable(params).map_err(|_| ())?;
    let svc = ctx.age_gate.ok_or(())?;
    let Some(version) = pin.submitted.version.as_deref() else {
        return Ok(None);
    };
    let package = age_gate_package_name(&pin.registry_type, &pin.submitted.identifier);
    let review = svc
        .get_review(params.id, &package, version)
        .await
        .map_err(|_| ())?;
    let fingerprint = upstream_fingerprint(params.upstream_url.as_deref());
    let identity = review.as_ref().map(|r| {
        review_identity_match(
            r.basis_mode.as_deref(),
            r.basis_upstream_fingerprint.as_deref(),
            params.age_gate_mode,
            &fingerprint,
        )
    });
    let view = review
        .as_ref()
        .zip(identity)
        .map(|(r, identity)| ReviewPolicyView {
            status: r.status.clone(),
            is_automatic: r.reviewed_by.is_none(),
            identity,
        });
    let reviewed_publish = review
        .as_ref()
        .zip(identity)
        .filter(|(_, id)| *id != ReviewIdentityMatch::Differs)
        .and_then(|(r, _)| r.upstream_published_at);
    let (basis, recorded_basis) = match params.age_gate_mode {
        AgeGateMode::FirstSeen => {
            let seen = svc
                .lookup_first_seen(params, &package, version)
                .await
                .map_err(|_| ())?;
            (seen, seen)
        }
        AgeGateMode::UpstreamPublishTime => (
            Some(reviewed_publish.map_or(cached_at, |p| p.min(cached_at))),
            reviewed_publish,
        ),
    };
    let meets =
        AgeGateService::meets_age_threshold(basis, params.age_gate_min_age_days, Utc::now());
    match decide_age_gate_check(view.as_ref(), meets) {
        AgeGateCheckAction::Allow
        | AgeGateCheckAction::AllowAlreadyApproved
        | AgeGateCheckAction::AllowAndAutoApprovePending => return Ok(None),
        AgeGateCheckAction::BlockRejected
        | AgeGateCheckAction::BlockAndResetReview
        | AgeGateCheckAction::BlockAndRequestReview => {}
    }
    let review_id = if ctx.record_reviews {
        match svc
            .check(params, &package, version, recorded_basis)
            .await
            .map_err(|_| ())?
        {
            AgeGateDecision::Allow => return Ok(None),
            AgeGateDecision::Block { review_id, .. } => Some(review_id),
        }
    } else {
        review.map(|r| r.id)
    };
    Ok(Some(GateOutcome::AgeGate {
        review_id,
        min_age_days: i64::from(params.age_gate_min_age_days),
        requested_age_days: basis.map(|b| AgeGateService::package_age_days(b, Utc::now())),
    }))
}

/// The gates a pin's rows face beyond the download gate, in the Remote
/// repositories they were pulled through: the stored proxy-scan verdict (for
/// OCI keyed by the pinned digest and its gate child, otherwise by each row's
/// sha256), then the age gate. `Err` when a gate cannot be read.
async fn remote_gates(
    ctx: GateCtx<'_>,
    cache: &mut FactsCache,
    pin: &PackagePin,
    rows: &[GateRow],
) -> Result<Option<GateOutcome>, ()> {
    let mut repos: Vec<Uuid> = rows.iter().map(|r| r.repository_id).collect();
    repos.sort();
    repos.dedup();
    for repo_id in repos {
        let facts = repo_facts(ctx.db, cache, repo_id).await?.clone();
        if !facts.is_remote() {
            continue;
        }
        let in_repo = || rows.iter().filter(move |r| r.repository_id == repo_id);
        if let Some(gate) = facts.scan_gate {
            let hexes: Vec<String> = if pin.registry_type == "oci" {
                let r = &pin.resolved;
                [r.digest.as_deref(), r.gate_digest.as_deref()]
                    .into_iter()
                    .flatten()
                    .map(|d| hex_of(d).to_string())
                    .collect()
            } else {
                in_repo().map(|r| r.checksum.trim().to_string()).collect()
            };
            for hex in &hexes {
                if stored_verdict_blocks(ctx.db, hex, gate).await? {
                    return Ok(Some(GateOutcome::ScanPolicy));
                }
            }
        }
        let cached_at = in_repo()
            .map(|r| r.created_at)
            .max()
            .unwrap_or_else(Utc::now);
        if let Some(outcome) = age_gate_outcome(ctx, &facts, pin, cached_at).await? {
            return Ok(Some(outcome));
        }
    }
    Ok(None)
}

/// One pin's gate, as the exact-detail read evaluates it: for OCI the
/// manifest's presence, then the download gate (quarantine, then scan
/// policy) of every row carrying the pinned bytes, then the Remote gates
/// (stored proxy verdict, age gate).
async fn backing_gate(ctx: GateCtx<'_>, cache: &mut FactsCache, pin: &PackagePin) -> GateOutcome {
    if pin.registry_type == "oci" {
        match oci_pin_present(ctx.db, pin).await {
            Ok(true) => {}
            Ok(false) => return GateOutcome::Unresolvable,
            Err(_) => return GateOutcome::Unavailable,
        }
    }
    let rows = match gate_rows(ctx.db, pin).await {
        Ok(rows) => rows,
        Err(_) => return GateOutcome::Unavailable,
    };
    if rows.is_empty() {
        return GateOutcome::Unresolvable;
    }
    for row in &rows {
        if let Err(e) =
            crate::services::quarantine_service::enforce_download_gate(ctx.db, row.id).await
        {
            return outcome_for_gate_error(&e);
        }
    }
    match remote_gates(ctx, cache, pin, &rows).await {
        Ok(Some(outcome)) => outcome,
        Ok(None) => GateOutcome::Allowed,
        Err(()) => GateOutcome::Unavailable,
    }
}

/// [`backing_gate`] for every pin, plus `Unresolvable` for a package the
/// stored document names but no pin covers.
pub async fn backing_gates(
    ctx: GateCtx<'_>,
    stored: &mcp::StoredVersion,
    policy_now: PackagePolicy,
) -> Vec<BackingGate> {
    let mut gates = Vec::new();
    if stored.policy == PackagePolicy::Open && policy_now == PackagePolicy::Open {
        return gates;
    }
    if let Some(package) = stored.unpinned_package() {
        gates.push(BackingGate {
            package,
            outcome: GateOutcome::Unresolvable,
        });
    }
    let mut cache = FactsCache::new();
    for pin in &stored.pins {
        gates.push(BackingGate {
            package: pin.label(),
            outcome: backing_gate(ctx, &mut cache, pin).await,
        });
    }
    gates
}

/// Whether a version's packages are gated: not when it was published under
/// `open` and the repository is still `open`.
fn gated(row: &ListingRow, policy_now: PackagePolicy) -> bool {
    !(row.stored.policy == PackagePolicy::Open && policy_now == PackagePolicy::Open)
}

/// One row a listing is about to advertise.
#[derive(Debug, Clone)]
pub struct ListingRow {
    pub artifact_id: Uuid,
    pub quarantine_status: Option<String>,
    pub quarantine_until: Option<DateTime<Utc>>,
    pub stored: mcp::StoredVersion,
}

/// The rows of a listing batch the reader-only gate refuses, decided in one
/// pass: the quarantine half from the fields in hand, the scan-policy half
/// through `quarantine_service::listing_refusals_fresh` per owning repository
/// (uncached: a listing here serves whole documents, so it must not lag a
/// scan that just completed), each pinned backing artifact the same way,
/// then the Remote gates. Any error refuses the whole batch (the caller omits
/// it), matching `listing_refusals`' fail-closed contract.
pub async fn listing_refusals(
    ctx: GateCtx<'_>,
    mcp_repo_id: Uuid,
    rows: &[ListingRow],
    policy_now: PackagePolicy,
) -> Result<HashSet<Uuid>, GateUnavailable> {
    listing_refusals_inner(ctx, mcp_repo_id, rows, policy_now)
        .await
        .map_err(|()| GateUnavailable)
}

/// A listing gate that could not be evaluated (a database error): the
/// caller omits the batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GateUnavailable;

async fn listing_refusals_inner(
    ctx: GateCtx<'_>,
    mcp_repo_id: Uuid,
    rows: &[ListingRow],
    policy_now: PackagePolicy,
) -> Result<HashSet<Uuid>, ()> {
    use crate::services::quarantine_service::{self as qs, ListingCandidate};
    let db = ctx.db;
    let own: Vec<ListingCandidate<'_>> = rows
        .iter()
        .map(|r| ListingCandidate {
            artifact_id: r.artifact_id,
            quarantine_status: r.quarantine_status.as_deref(),
            quarantine_until: r.quarantine_until,
        })
        .collect();
    let mut refused = qs::listing_refusals_fresh(db, mcp_repo_id, &own)
        .await
        .map_err(|_| ())?;

    // Each gated pin's rows, looked up as the detail read does.
    let mut pin_rows: HashMap<(Uuid, usize), Vec<GateRow>> = HashMap::new();
    for row in rows {
        if refused.contains(&row.artifact_id) || !gated(row, policy_now) {
            continue;
        }
        for pin in &row.stored.pins {
            let found = gate_rows(db, pin).await.map_err(|_| ())?;
            pin_rows.insert((row.artifact_id, pin.index), found);
        }
    }
    let mut by_repo: HashMap<Uuid, Vec<ListingCandidate<'_>>> = HashMap::new();
    for r in pin_rows.values().flatten() {
        by_repo
            .entry(r.repository_id)
            .or_default()
            .push(ListingCandidate {
                artifact_id: r.id,
                quarantine_status: r.quarantine_status.as_deref(),
                quarantine_until: r.quarantine_until,
            });
    }
    let mut backing_refused = HashSet::new();
    for (repo, candidates) in &by_repo {
        backing_refused.extend(
            qs::listing_refusals_fresh(db, *repo, candidates)
                .await
                .map_err(|_| ())?,
        );
    }

    let mut cache = FactsCache::new();
    for row in rows {
        if refused.contains(&row.artifact_id) || !gated(row, policy_now) {
            continue;
        }
        let mut blocked = row.stored.unpinned_package().is_some();
        for pin in &row.stored.pins {
            if blocked {
                break;
            }
            let found = pin_rows
                .get(&(row.artifact_id, pin.index))
                .map(Vec::as_slice)
                .unwrap_or_default();
            blocked = found.is_empty() || found.iter().any(|r| backing_refused.contains(&r.id));
            if !blocked && pin.registry_type == "oci" {
                blocked = !oci_pin_present(db, pin).await.map_err(|_| ())?;
            }
            if !blocked {
                blocked = remote_gates(ctx, &mut cache, pin, found).await?.is_some();
            }
        }
        if blocked {
            refused.insert(row.artifact_id);
        }
    }
    Ok(refused)
}

// ---------------------------------------------------------------------------
// Pin drift
// ---------------------------------------------------------------------------

/// A published server version whose pinned OCI tag moved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinDrift {
    pub artifact_id: Uuid,
    pub server: String,
    pub version: String,
    pub pinned_digest: String,
}

/// Mark every MCP pin of `(repo_id, name, tag)` whose digest is not
/// `observed` with `packages[i].drift`, returning the versions newly marked.
/// A pin already marked with this `observed` digest is left alone (no second
/// audit row), and a pin whose tag moved back to the pinned digest has its
/// mark cleared. The pinned digest (what is served) is never changed.
///
/// One indexed probe (`metadata @> {"packages": [...]}` hits the GIN index on
/// `artifact_metadata.metadata`), skipped outright on an instance without an
/// MCP repository.
pub async fn mark_pin_drift(
    db: &PgPool,
    repo_id: Uuid,
    name: &str,
    tag: &str,
    observed: &str,
) -> Result<Vec<PinDrift>, sqlx::Error> {
    let any_mcp: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM repositories WHERE format = 'mcp')")
            .fetch_one(db)
            .await?;
    if !any_mcp {
        return Ok(Vec::new());
    }
    let probe = serde_json::json!({ "packages": [{ "resolved": {
        "repositoryId": repo_id, "name": name, "tag": tag,
    }}]});
    let rows: Vec<(Uuid, String, String, serde_json::Value)> = sqlx::query_as(
        "SELECT a.id, a.name, a.version, m.metadata->'packages' FROM artifact_metadata m \
         JOIN artifacts a ON a.id = m.artifact_id \
         WHERE m.metadata @> $1::jsonb AND m.format = 'mcp' AND a.is_deleted = false",
    )
    .bind(&probe)
    .fetch_all(db)
    .await?;
    let now = Utc::now();
    let mut out = Vec::new();
    for (artifact_id, server, version, mut packages) in rows {
        let mut changed = false;
        let mut newly = None;
        if let Some(list) = packages.as_array_mut() {
            for p in list.iter_mut() {
                let r = &p["resolved"];
                let matches = r["repositoryId"] == serde_json::json!(repo_id)
                    && r["name"] == name
                    && r["tag"] == tag;
                if !matches {
                    continue;
                }
                let digest = r["digest"].as_str().unwrap_or_default().to_string();
                let marked = p.get("drift").filter(|d| !d.is_null()).cloned();
                if digest == observed {
                    if marked.is_some() {
                        if let Some(o) = p.as_object_mut() {
                            o.remove("drift");
                        }
                        changed = true;
                    }
                } else if marked.as_ref().and_then(|d| d["observedDigest"].as_str())
                    != Some(observed)
                {
                    p["drift"] = serde_json::json!({
                        "observedDigest": observed,
                        "observedAt": now,
                    });
                    changed = true;
                    newly = Some(digest);
                }
            }
        }
        if !changed {
            continue;
        }
        sqlx::query(
            "UPDATE artifact_metadata SET metadata = jsonb_set(metadata, '{packages}', $2) \
             WHERE artifact_id = $1",
        )
        .bind(artifact_id)
        .bind(&packages)
        .execute(db)
        .await?;
        if let Some(pinned_digest) = newly {
            out.push(PinDrift {
                artifact_id,
                server,
                version,
                pinned_digest,
            });
        }
    }
    Ok(out)
}

/// After an OCI tag moved from `previous` to `observed` (`previous` is empty
/// when the tag was created, e.g. re-pushed after a delete): mark the MCP
/// pins on it and audit `MCP_PIN_DRIFT_DETECTED` per version. Best-effort: a
/// failure is logged and never fails the push.
pub async fn record_pin_drift(
    db: &PgPool,
    repo_id: Uuid,
    name: &str,
    tag: &str,
    previous: &str,
    observed: &str,
) {
    if previous == observed {
        return;
    }
    let hits = match mark_pin_drift(db, repo_id, name, tag, observed).await {
        Ok(hits) => hits,
        Err(e) => {
            tracing::warn!(repository_id = %repo_id, name, tag, error = %e, "MCP pin drift check failed");
            return;
        }
    };
    use crate::services::audit_service::{AuditAction, AuditEntry, AuditService, ResourceType};
    for hit in hits {
        let entry = AuditEntry::new(AuditAction::McpPinDriftDetected, ResourceType::Artifact)
            .resource(hit.artifact_id)
            .resource_name(format!("{}@{}", hit.server, hit.version))
            .system_actor("oci-tag-upsert")
            .details(serde_json::json!({
                "backing_repository_id": repo_id,
                "name": name,
                "tag": tag,
                "previous_digest": (!previous.is_empty()).then_some(previous),
                "pinned_digest": hit.pinned_digest,
                "observed_digest": observed,
                "mcp_server": hit.server,
                "mcp_version": hit.version,
            }));
        if let Err(e) = AuditService::new(db.clone()).log(entry).await {
            tracing::warn!(error = %e, "MCP_PIN_DRIFT_DETECTED audit write failed");
        }
    }
}

#[cfg(ak_test_shard = "services-1")]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_backing_rules() {
        assert!(format_backs("npm", "npm"));
        assert!(format_backs("npm", "yarn"));
        assert!(format_backs("pypi", "poetry"));
        assert!(format_backs("oci", "docker"));
        assert!(format_backs("oci", "podman"));
        assert!(format_backs("cargo", "cargo"));
        assert!(format_backs("nuget", "nuget"));
        assert!(!format_backs("npm", "pypi"));
        assert!(!format_backs("mcpb", "generic"));
        assert!(!format_backs("oci", "helm"));
        assert!(!format_backs("npm", "no-such-format"));
    }

    #[test]
    fn every_mcp_repository_type_is_creatable() {
        assert!(creatable(&RepositoryFormat::Mcp, "local").is_ok());
        assert!(creatable(&RepositoryFormat::Mcp, "staging").is_ok());
        assert!(creatable(&RepositoryFormat::Mcp, "remote").is_ok());
        assert!(creatable(&RepositoryFormat::Mcp, "virtual").is_ok());
        assert!(creatable(&RepositoryFormat::Mcp, "bogus").is_err());
        assert!(creatable(&RepositoryFormat::Npm, "remote").is_ok());
    }

    #[test]
    fn setting_parsers() {
        assert_eq!(
            parse_package_repos(r#"{"npm":"npm-local","oci":"oci-local"}"#).unwrap()["oci"],
            "oci-local"
        );
        assert!(parse_package_repos(r#"{"mcpb":"x"}"#).is_err());
        assert!(parse_package_repos(r#"{"npm":" "}"#).is_err());
        assert!(parse_package_repos("[1]").is_err());
        assert_eq!(
            parse_namespace_allow(r#"["com.acme"]"#).unwrap(),
            vec!["com.acme"]
        );
        assert!(parse_namespace_allow(r#"["com/acme"]"#).is_err());
        assert!(parse_namespace_allow(r#"[""]"#).is_err());
        assert!(parse_namespace_allow("{}").is_err());
    }

    #[test]
    fn oci_helpers() {
        assert!(same_registry_host("docker.io", "registry-1.docker.io"));
        assert!(same_registry_host("GHCR.io", "ghcr.io"));
        assert!(!same_registry_host("ghcr.io", "docker.io"));
        assert_eq!(
            oci_name_candidates("docker.io", "library/nginx"),
            vec!["library/nginx", "nginx"]
        );
        assert_eq!(
            oci_name_candidates("ghcr.io", "library/x"),
            vec!["library/x"]
        );
        assert_eq!(hex_of("sha256:abc"), "abc");
        assert_eq!(hex_of("abc"), "abc");
        let repo = |repo_type: &str, upstream: Option<&str>| BackingRepo {
            id: Uuid::nil(),
            key: "oci-r".into(),
            repo_type: repo_type.into(),
            format: "docker".into(),
            upstream_url: upstream.map(Into::into),
            location: StorageLocation {
                backend: "filesystem".into(),
                path: "/tmp".into(),
            },
        };
        let r = mcp::parse_oci_identifier("ghcr.io/acme/mcp:1.2").unwrap();
        assert_eq!(
            oci_backing_path(&r, &repo("local", None), "https://ak.test").unwrap(),
            "acme/mcp"
        );
        assert!(oci_backing_path(
            &r,
            &repo("remote", Some("https://registry-1.docker.io")),
            "https://ak.test"
        )
        .is_err());
        assert_eq!(
            oci_backing_path(
                &r,
                &repo("remote", Some("https://ghcr.io")),
                "https://ak.test"
            )
            .unwrap(),
            "acme/mcp"
        );
        let own = mcp::parse_oci_identifier("ak.test/oci-r/acme/mcp:1.2").unwrap();
        assert_eq!(
            oci_backing_path(
                &own,
                &repo("remote", Some("https://ghcr.io")),
                "https://ak.test"
            )
            .unwrap(),
            "acme/mcp"
        );
        assert_eq!(
            backing_base_url("https://ak.test/", "nuget", "n"),
            "https://ak.test/nuget/n/v3/index.json"
        );
        assert_eq!(
            backing_base_url("https://ak.test", "npm", "n"),
            "https://ak.test/npm/n"
        );
        assert_eq!(not_pulled_hint(&repo("local", None)), "");
        assert!(!not_pulled_hint(&repo("remote", None)).is_empty());
    }

    #[test]
    fn index_children_and_gate_digest() {
        let d = |c: char| format!("sha256:{}", c.to_string().repeat(64));
        let body = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": [
                {"digest": d('a'), "platform": {"os": "linux", "architecture": "amd64"}},
                {"digest": d('b'), "platform": {"os": "linux", "architecture": "arm64", "variant": "v8"}},
                {"digest": d('c'), "platform": {"os": "unknown", "architecture": "unknown"}},
            ],
        });
        let bytes = serde_json::to_vec(&body).unwrap();
        let children = index_children(&bytes);
        assert_eq!(children.len(), 2);
        assert_eq!(children[1].platform, "linux/arm64/v8");
        let gate = gate_digest_for(&bytes, &d('f'));
        assert!(gate == d('a') || gate == d('b'));
        assert_eq!(gate_digest_for(b"{}", "sha256:x"), "sha256:x");
        assert!(index_children(b"not json").is_empty());
        assert!(index_children(b"{}").is_empty());
    }

    #[test]
    fn gate_errors_map_to_outcomes() {
        use crate::error::AppError;
        assert_eq!(
            outcome_for_gate_error(&AppError::Conflict("q".into())),
            GateOutcome::Quarantine
        );
        assert_eq!(
            outcome_for_gate_error(&AppError::Authorization("p".into())),
            GateOutcome::ScanPolicy
        );
        assert_eq!(
            outcome_for_gate_error(&AppError::Database("d".into())),
            GateOutcome::Unavailable
        );
        assert!(name_predicate("pypi").contains("regexp_replace"));
        assert!(name_predicate("nuget").contains("lower(a.version)"));
        assert!(name_predicate("cargo").contains("lower(a.name)"));
        assert_eq!(name_predicate("npm"), "a.name = $2 AND a.version = $3");
        assert_eq!(lookup_name("pypi", "Acme_SDK"), "acme-sdk");
        assert_eq!(lookup_name("npm", "@Acme/x"), "@Acme/x");
    }
}
