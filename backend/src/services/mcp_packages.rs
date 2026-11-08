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
use crate::services::mcp_virtual_serve::{serve_model, shadow_reason, HostedRow, ServeModel};
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
    pub fn is_remote(&self) -> bool {
        self.repo_type == "remote"
    }

    pub fn is_virtual(&self) -> bool {
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
    // MCPB bundles live in an MCP registry (uploaded beside a server
    // version) or as plain files in a Generic repository.
    if registry_type == "mcpb" {
        return matches!(format, "mcp" | "generic");
    }
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
        if !(mcp::ARTIFACT_REGISTRY_TYPES.contains(&ty.as_str()) || ty == "oci" || ty == "mcpb") {
            return Err(format!(
                "`{ty}` is not a registryType AK can back (npm, pypi, nuget, cargo, oci, mcpb)"
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
pub(crate) async fn caller_may_map(
    db: &PgPool,
    caller: &crate::api::middleware::auth::AuthExtension,
    repo_id: Uuid,
) -> crate::error::Result<bool> {
    if !caller.can_access_repo(repo_id) {
        return Ok(false);
    }
    principal_may_read(db, caller, repo_id).await
}

/// Whether the principal behind `caller` may read `repo_id`: an instance
/// administrator, a public repository, or `read` through a grant or a role
/// (an `internal` repository needs the grant, as in [`caller_may_map`]). The
/// token's repository scope is not consulted: a publish token scoped to the
/// MCP registry still publishes packages its principal can read.
pub(crate) async fn principal_may_read(
    db: &PgPool,
    caller: &crate::api::middleware::auth::AuthExtension,
    repo_id: Uuid,
) -> crate::error::Result<bool> {
    use crate::services::repository_service::{RepoAccess, RepositoryService};
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

/// The `422 mcp_package_not_found` detail of a package whose backing
/// repository the publisher cannot read. It names no repository and does not
/// depend on whether the package exists.
pub fn unreadable_package_detail(pkg: &mcp::Package) -> String {
    format!(
        "{} {}@{} is not in a backing repository this account can read; publish it to the \
         mapped repository (or ask for read on it) first",
        pkg.registry_type,
        pkg.identifier,
        pkg.version.as_deref().unwrap_or("")
    )
}

/// Refuse a document naming a package whose mapped backing repository the
/// publisher's principal cannot read ([`principal_may_read`]), before any
/// lookup (#5253). Without it a publisher with MCP write but no read on the
/// backing repository learned whether a package exists there (`422
/// mcp_package_not_found` vs `200`, or `202 resolving` vs `200` through a
/// Remote): the answer is now the same `422` whether the package exists or
/// not. A caller who can read the repository keeps the precise answers.
/// `open` resolves through the same backing repositories (#5452), so it is
/// checked the same way.
pub async fn refuse_unreadable_backing(
    db: &PgPool,
    caller: &crate::api::middleware::auth::AuthExtension,
    settings: &McpSettings,
    server: &ServerJson,
) -> Result<(), McpError> {
    let mut seen: BTreeMap<Uuid, bool> = BTreeMap::new();
    for (index, pkg) in server.packages.iter().enumerate() {
        // A bundle is matched by `fileSha256` (no name to probe), and one
        // uploaded beside the version lives in this registry.
        let Some(repo) = settings
            .repos
            .get(&pkg.registry_type)
            .filter(|_| pkg.registry_type != "mcpb")
        else {
            continue;
        };
        let readable = match seen.get(&repo.id) {
            Some(r) => *r,
            None => {
                let r = principal_may_read(db, caller, repo.id)
                    .await
                    .map_err(|e| McpError::Internal(e.to_string()))?;
                seen.insert(repo.id, r);
                r
            }
        };
        if !readable {
            return Err(McpError::PackageNotFound {
                index,
                detail: unreadable_package_detail(pkg),
            });
        }
    }
    Ok(())
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

/// The repositories whose rows a backing repository serves: for a Virtual
/// its leaf members (nested Virtuals expanded) in the order its download
/// walk tries them, itself otherwise.
pub(crate) async fn content_repo_ids(
    db: &PgPool,
    repo: &BackingRepo,
) -> Result<Vec<Uuid>, McpError> {
    if !repo.is_virtual() {
        return Ok(vec![repo.id]);
    }
    crate::api::handlers::proxy_helpers::fetch_virtual_member_leaf_ids(db, repo.id)
        .await
        .map_err(|_| McpError::Internal("virtual member walk failed".into()))
}

/// The SQL predicate on `artifacts` that matches a package name as each
/// format's publish path stores it (`$2` name, `$3` version).
pub(crate) fn name_predicate(registry_type: &str) -> &'static str {
    match registry_type {
        // PEP 503: compare normalised forms; `$2` arrives normalised.
        "pypi" => "lower(regexp_replace(a.name, '[-_.]+', '-', 'g')) = $2 AND a.version = $3",
        // NuGet: the download routes match `LOWER(name) = <id lowercased>`
        // and the stored version exactly, and a client requests the
        // normalised version (`$3` arrives normalised, [`lookup_version`]):
        // a row stored as `1.0` is never served for `1.0.0`.
        "nuget" => "lower(a.name) = lower($2) AND a.version = $3",
        // Cargo: the download route lowercases the requested name and
        // matches it and the version exactly; `-` and `_` are different
        // crates to it (a Local repository can hold both).
        "cargo" => "a.name = lower($2) AND a.version = $3",
        // npm: exact (scoped names included), after percent-decoding.
        _ => "a.name = $2 AND a.version = $3",
    }
}

/// The name a backing format stores `identifier` under: PEP 503 for PyPI,
/// percent-decoded for npm (`%40acme%2Fx` is `@acme/x`; an npm name never
/// contains `%`).
pub(crate) fn lookup_name(registry_type: &str, identifier: &str) -> String {
    match registry_type {
        "pypi" => crate::formats::pypi::PypiHandler::normalize_name(identifier),
        "npm" if identifier.contains('%') => urlencoding::decode(identifier)
            .map(|d| d.into_owned())
            .unwrap_or_else(|_| identifier.to_string()),
        _ => identifier.to_string(),
    }
}

/// The version text a backing format's download route is asked for, so the
/// pin is looked up as the route looks it up: NuGet clients request the
/// normalised version in lowercase
/// ([`NugetHandler::normalized_version`]); every other
/// format the version as written. `None` for a NuGet version that does not
/// normalise (no client requests it).
///
/// [`NugetHandler::normalized_version`]: crate::formats::nuget::NugetHandler::normalized_version
pub(crate) fn lookup_version(registry_type: &str, submitted: &str) -> Option<String> {
    if registry_type == "nuget" {
        // A V3 client requests the normalised version in lowercase.
        return crate::formats::nuget::NugetHandler::normalized_version(submitted)
            .map(|v| v.to_ascii_lowercase());
    }
    Some(submitted.to_string())
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

/// The pin warning of a package whose submitted coordinates named another
/// registry (a foreign `registryBaseUrl` or OCI image host), accepted under
/// the `open` policy (#5452). The package was resolved in, and is served from,
/// the backing repository; the foreign coordinates are never served.
pub const FOREIGN_COORDINATES_WARNING: &str = "foreign_coordinates_replaced";

/// Whether `pkg` names a `registryBaseUrl` other than `repo`'s on this
/// instance.
pub fn registry_base_url_is_foreign(
    pkg: &mcp::Package,
    repo: &BackingRepo,
    base_url: &str,
) -> bool {
    pkg.registry_base_url.as_deref().is_some_and(|given| {
        let own = backing_base_url(base_url, &pkg.registry_type, &repo.key);
        given.trim_end_matches('/') != own.trim_end_matches('/')
    })
}

/// The host `pkg`'s `registryBaseUrl` names, lowercased.
fn submitted_host(pkg: &mcp::Package) -> Option<String> {
    pkg.registry_base_url
        .as_deref()
        .map(|u| mcp::host_of(u).to_ascii_lowercase())
}

/// Whether content that reached this instance through `remote` (a Remote
/// repository: the backing repository itself or a Virtual's member) may be
/// pinned for `pkg` (#5452). Always, unless `pkg` names a foreign
/// `registryBaseUrl` (accepted only under `open`): then only when that URL
/// is under `remote`'s own upstream ([`url_is_under`]). Otherwise `open` would replace one
/// package identity by another of the same name: `@corp/tool` on
/// `npm.internal.corp` by a same-named (possibly squatted) public package the
/// Remote proxies, with a fill pulling it in on the publisher's behalf.
pub fn remote_may_serve(
    pkg: &mcp::Package,
    mapped: &BackingRepo,
    remote: &BackingRepo,
    base_url: &str,
) -> bool {
    !registry_base_url_is_foreign(pkg, mapped, base_url) || upstream_is_named(pkg, remote)
}

/// Whether `pkg`'s `registryBaseUrl` is under `remote`'s upstream URL.
fn upstream_is_named(pkg: &mcp::Package, remote: &BackingRepo) -> bool {
    match (
        remote.upstream_url.as_deref(),
        pkg.registry_base_url.as_deref(),
    ) {
        (Some(upstream), Some(submitted)) => url_is_under(upstream, submitted),
        _ => false,
    }
}

/// Whether `submitted` names the registry `upstream` is (#5452): the same
/// origin (scheme, host and port, normalised: case, default ports) and a
/// path under the upstream's path, compared by whole segments. A registry is
/// often one path of a shared host (GitLab's
/// `/api/v4/projects/<id>/packages/pypi/simple`, Nexus or Artifactory
/// `/repository/<name>/`), so the host alone does not identify it. A
/// root-path upstream (`https://registry.npmjs.org/`) covers every path of
/// its origin. Anything that does not parse is not under (fail closed).
pub fn url_is_under(upstream: &str, submitted: &str) -> bool {
    let (Ok(up), Ok(sub)) = (url::Url::parse(upstream), url::Url::parse(submitted)) else {
        return false;
    };
    let origin = |u: &url::Url| {
        (
            u.scheme().to_ascii_lowercase(),
            u.host_str().map(str::to_ascii_lowercase),
            u.port_or_known_default(),
        )
    };
    if up.host_str().is_none() || origin(&up) != origin(&sub) {
        return false;
    }
    let segments = |u: &url::Url| -> Vec<String> {
        u.path_segments()
            .map(|s| s.filter(|p| !p.is_empty()).map(str::to_string).collect())
            .unwrap_or_default()
    };
    let (up, sub) = (segments(&up), segments(&sub));
    sub.len() >= up.len() && sub[..up.len()] == up[..]
}

/// The refusal of foreign coordinates that would resolve through a Remote of
/// another upstream ([`remote_may_serve`]).
pub fn foreign_through_remote(index: usize, pkg: &mcp::Package, repo: &BackingRepo) -> McpError {
    McpError::ExternalRegistry {
        index,
        detail: format!(
            "registryBaseUrl names {}, which is not the upstream of the Remote repository \
             '{}' would resolve {} {} through; publish the package to a hosted repository \
             mapped for {}, or name the Remote's upstream",
            submitted_host(pkg).unwrap_or_default(),
            repo.key,
            pkg.registry_type,
            pkg.identifier,
            pkg.registry_type
        ),
    }
}

/// The Remote repositories among those `repo` serves (itself, or a Virtual's
/// members) whose upstream is not the registry `pkg` names
/// ([`remote_may_serve`]).
async fn remotes_not_named_by(
    db: &PgPool,
    repo: &BackingRepo,
    pkg: &mcp::Package,
) -> Result<Vec<BackingRepo>, McpError> {
    let keys: Vec<String> = if repo.is_virtual() {
        sqlx::query_scalar(
            "SELECT r.key FROM virtual_repo_members m JOIN repositories r ON r.id = m.member_repo_id \
             WHERE m.virtual_repo_id = $1 AND r.repo_type = 'remote'",
        )
        .bind(repo.id)
        .fetch_all(db)
        .await
        .map_err(db_err)?
    } else if repo.is_remote() {
        vec![repo.key.clone()]
    } else {
        Vec::new()
    };
    Ok(repos_by_key(db, &keys)
        .await?
        .into_iter()
        .filter(|remote| !upstream_is_named(pkg, remote))
        .collect())
}

/// Record [`FOREIGN_COORDINATES_WARNING`] on a pin found in a Remote's proxy
/// cache rather than by [`resolve_package`] (which records it itself), so
/// every pin of foreign coordinates says so, wherever it was found.
pub fn note_foreign_coordinates(
    pin: &mut PackagePin,
    pkg: &mcp::Package,
    repo: &BackingRepo,
    base_url: &str,
) {
    let warning = FOREIGN_COORDINATES_WARNING.to_string();
    if registry_base_url_is_foreign(pkg, repo, base_url)
        && !pin.resolved.warnings.contains(&warning)
    {
        pin.resolved.warnings.push(warning);
    }
}

async fn resolve_artifact_package(
    db: &PgPool,
    index: usize,
    pkg: &mcp::Package,
    repo: &BackingRepo,
    base_url: &str,
    policy: PackagePolicy,
) -> Result<PackagePin, McpError> {
    let mut warnings = Vec::new();
    let foreign = registry_base_url_is_foreign(pkg, repo, base_url);
    if foreign {
        if policy == PackagePolicy::Open {
            warnings.push(FOREIGN_COORDINATES_WARNING.to_string());
        } else {
            let own = backing_base_url(base_url, &pkg.registry_type, &repo.key);
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
    let rows = pinned_rows(db, index, pkg, repo, version).await?;
    if foreign {
        // Foreign coordinates (`open`) never stand for what a Remote of
        // another upstream holds: the winning row must be hosted, or in a
        // Remote whose upstream is the submitted registry.
        let untrusted = remotes_not_named_by(db, repo, pkg).await?;
        if let Some(first) = rows.first() {
            if untrusted.iter().any(|r| r.id == first.repository_id) {
                return Err(foreign_through_remote(index, pkg, repo));
            }
        }
    }
    let Some(first) = rows.first() else {
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
    let sha256 = first.checksum.clone();
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
            artifact_ids: rows.iter().map(|r| r.id).collect(),
            artifact_sha256s: rows.iter().map(|r| r.checksum.clone()).collect(),
            sha256: Some(sha256),
            name: None,
            tag: None,
            digest: None,
            media_type: None,
            children: Vec::new(),
            gate_digest: None,
            resolved_at: Utc::now(),
            warnings,
            cache_path: None,
            download_path: None,
        },
        drift: None,
    })
}

/// The rows a pin of `pkg` (npm, PyPI, NuGet, Cargo) at `version` covers:
/// for a Virtual, the rows of the member its download walk serves the
/// version from (PyPI: every hosted file of the version), refusing a
/// coordinate a Remote member would serve instead (#5456); for any other
/// repository its own rows (PyPI: every file of the version).
async fn pinned_rows(
    db: &PgPool,
    index: usize,
    pkg: &mcp::Package,
    repo: &BackingRepo,
    version: &str,
) -> Result<Vec<HostedRow>, McpError> {
    use crate::services::mcp_virtual_serve::{serve_model, Winner};
    if !repo.is_virtual() {
        return own_rows(db, repo, &pkg.registry_type, &pkg.identifier, version).await;
    }
    let model = serve_model(db, repo.id, &pkg.registry_type, &pkg.identifier, version).await?;
    let shadowed = |remote: &str| McpError::PackageShadowed {
        index,
        detail: shadowed_detail(pkg, version, repo, remote, model.first_holder.as_deref()),
    };
    if pkg.registry_type == "pypi" {
        if model.files.is_empty() {
            return Ok(Vec::new());
        }
        if let Some((_, remote)) = model.remotes.first() {
            return Err(shadowed(remote));
        }
        return Ok(model.files);
    }
    match model.winner {
        Some(Winner::Hosted { rows, .. }) => Ok(rows),
        // Nothing hosted: a Remote member may still fill it (the resolver).
        Some(Winner::Remote { .. }) | None if model.first_holder.is_none() => Ok(Vec::new()),
        Some(Winner::Remote { key, .. }) => Err(shadowed(&key)),
        None => Ok(Vec::new()),
    }
}

/// The refusal of a coordinate a Remote member of Virtual `repo` would
/// serve in place of the hosted member that holds it: names both members
/// and the fixes.
fn shadowed_detail(
    pkg: &mcp::Package,
    version: &str,
    repo: &BackingRepo,
    remote: &str,
    holder: Option<&str>,
) -> String {
    let coordinate = format!("{} {}@{version}", pkg.registry_type, pkg.identifier);
    let holder = holder.unwrap_or("the hosted member");
    if pkg.registry_type == "pypi" {
        return format!(
            "{coordinate} is in '{holder}', but Remote member '{remote}' of repository '{}' can \
             serve other distributions of it from its upstream; map '{holder}' directly",
            repo.key
        );
    }
    let isolate = if pkg.registry_type == "npm" {
        ", enable isolate mode on the Virtual"
    } else {
        ""
    };
    format!(
        "Remote member '{remote}' outranks '{holder}' for {coordinate} in repository '{}', so a \
         download would come from its upstream; rank '{holder}' above '{remote}'{isolate}, or map \
         '{holder}' directly",
        repo.key
    )
}

/// The rows of a coordinate in a repository that is not a Virtual.
async fn own_rows(
    db: &PgPool,
    repo: &BackingRepo,
    registry_type: &str,
    identifier: &str,
    version: &str,
) -> Result<Vec<HostedRow>, McpError> {
    crate::services::mcp_virtual_serve::repo_rows(
        db,
        &[repo.id],
        registry_type,
        identifier,
        version,
    )
    .await
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

/// Where an OCI identifier is looked up in its backing repository.
#[derive(Debug, Clone, PartialEq, Eq)]
struct OciBackingPath {
    /// The image path inside the backing repository.
    path: String,
    /// The identifier named another registry, accepted under `open`.
    foreign: bool,
}

/// The image path inside `repo` an identifier names, or why it is foreign.
/// Under `open` a foreign host is accepted for a hosted repository and its
/// path looked up there (#5452): the image still has to be there, and is
/// served from there. A Remote's images came from its upstream, so naming
/// another host is refused under either policy ([`remote_may_serve`]).
fn oci_backing_path(
    r: &mcp::OciRef,
    repo: &BackingRepo,
    base_url: &str,
    policy: PackagePolicy,
) -> Result<OciBackingPath, String> {
    // An identifier that already names this instance's repository.
    if same_registry_host(&r.host, &mcp::host_of(base_url)) {
        if let Some(rest) = r.path.strip_prefix(&format!("{}/", repo.key)) {
            return Ok(OciBackingPath {
                path: rest.to_string(),
                foreign: false,
            });
        }
    }
    match oci_host_refusal(r, repo, base_url) {
        None => Ok(OciBackingPath {
            path: r.path.clone(),
            foreign: false,
        }),
        Some(_) if policy == PackagePolicy::Open && !repo.is_remote() => Ok(OciBackingPath {
            path: r.path.clone(),
            foreign: true,
        }),
        Some(why) => Err(why),
    }
}

/// Why an image host is not one `repo` serves under `own-repos`, if it is not.
fn oci_host_refusal(r: &mcp::OciRef, repo: &BackingRepo, base_url: &str) -> Option<String> {
    if repo.is_remote() {
        let upstream = repo
            .upstream_url
            .as_deref()
            .map(mcp::host_of)
            .unwrap_or_default();
        if !same_registry_host(&r.host, &upstream) {
            return Some(format!(
                "image host '{}' is not the upstream of repository '{}' ({upstream})",
                r.host, repo.key
            ));
        }
    } else if !repo.is_virtual() {
        // A Local/Staging repository holds only what was pushed to this
        // instance: an image named on another host is external, whatever
        // its path (#5253 e2e).
        return Some(format!(
            "image host '{}' is not this registry; name the image as {}/{}/<image>:<tag>",
            r.host,
            mcp::host_of(base_url),
            repo.key
        ));
    }
    None
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
    pin_floating: bool,
    policy: PackagePolicy,
) -> Result<PackagePin, McpError> {
    let (r, floating) = match mcp::parse_oci_reference(&pkg.identifier) {
        Ok((_, true)) if !pin_floating => return Err(McpError::OciFloatingTag { index }),
        Ok(parsed) => parsed,
        Err(mcp::OciRefError::Floating) => return Err(McpError::OciFloatingTag { index }),
        Err(mcp::OciRefError::Invalid(m)) => {
            return Err(McpError::invalid(
                format!("packages[{index}].identifier"),
                m,
            ))
        }
    };
    let OciBackingPath { path, foreign } = oci_backing_path(&r, repo, base_url, policy)
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
    if floating {
        warnings.push(FLOATING_TAG_WARNING.to_string());
    }
    if foreign {
        warnings.push(FOREIGN_COORDINATES_WARNING.to_string());
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
            artifact_sha256s: Vec::new(),
            sha256: None,
            name: Some(found.name),
            tag: r.tag.clone(),
            digest: Some(found.digest),
            media_type: Some(found.media_type),
            children: index_children(&body),
            gate_digest: Some(gate_digest),
            resolved_at: Utc::now(),
            warnings,
            cache_path: None,
            download_path: None,
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

/// The pin warning of an OCI `latest`/tagless identifier pinned at sync.
pub const FLOATING_TAG_WARNING: &str = "oci_floating_tag";

/// Resolve and pin every package of `server` under the repository's policy.
/// `open` resolves and pins exactly as `own-repos` does; it only accepts
/// foreign coordinates (#5452).
pub async fn resolve_packages(
    state: &crate::api::SharedState,
    settings: &McpSettings,
    server: &ServerJson,
    base_url: &str,
) -> Result<Vec<PackagePin>, McpError> {
    let mut pins = Vec::with_capacity(server.packages.len());
    for (index, pkg) in server.packages.iter().enumerate() {
        pins.push(resolve_package(state, settings, index, pkg, base_url, false).await?);
    }
    Ok(pins)
}

/// The `422 mcp_external_registry` of a `registryType` with no backing
/// repository.
pub fn unmapped(settings: &McpSettings, index: usize, registry_type: &str) -> McpError {
    let mapped: Vec<&str> = settings.repos.keys().map(String::as_str).collect();
    McpError::ExternalRegistry {
        index,
        detail: format!(
            "registryType '{registry_type}' has no backing repository in this registry \
             (mapped: {}); publish the package to an AK repository and map it in the \
             repository's MCP package settings",
            if mapped.is_empty() {
                "none".to_string()
            } else {
                mapped.join(", ")
            }
        ),
    }
}

/// Resolve and pin one `packages[]` entry against its backing repository
/// (`mcpb` entries are resolved by the bundle path, never here). With
/// `pin_floating`, an OCI `latest`/tagless identifier is resolved through the
/// backing repository's `latest` tag and pinned with the
/// [`FLOATING_TAG_WARNING`] warning instead of refused (Remote ingest).
pub async fn resolve_package(
    state: &crate::api::SharedState,
    settings: &McpSettings,
    index: usize,
    pkg: &mcp::Package,
    base_url: &str,
    pin_floating: bool,
) -> Result<PackagePin, McpError> {
    let Some(repo) = settings
        .repos
        .get(&pkg.registry_type)
        .filter(|_| pkg.registry_type != "mcpb")
    else {
        return Err(unmapped(settings, index, &pkg.registry_type));
    };
    if pkg.registry_type == "oci" {
        resolve_oci_package(
            state,
            index,
            pkg,
            repo,
            base_url,
            pin_floating,
            settings.policy,
        )
        .await
    } else {
        resolve_artifact_package(&state.db, index, pkg, repo, base_url, settings.policy).await
    }
}

/// [`resolve_package`] for a hosted publish or the resolver: floating OCI
/// references are refused.
pub async fn resolve_one(
    state: &crate::api::SharedState,
    settings: &McpSettings,
    index: usize,
    pkg: &mcp::Package,
    base_url: &str,
) -> Result<PackagePin, McpError> {
    resolve_package(state, settings, index, pkg, base_url, false).await
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
    /// A `proxy_cache_artifacts` row (a cache pin), not an `artifacts` row:
    /// its hold is the cache entry's Package Age Policy hold, and `id` is not
    /// an artifact id the download gate knows.
    cached: bool,
}

impl GateRow {
    /// A cache row's quarantine hold: held until `quarantine_until` unless an
    /// administrator released it (`quarantine_status` carries the release
    /// marker for these rows).
    fn cache_held(&self, now: DateTime<Utc>) -> bool {
        self.cached
            && self.quarantine_status.is_none()
            && self.quarantine_until.is_some_and(|until| until > now)
    }
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
        cached: false,
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
async fn gate_rows(
    db: impl sqlx::PgExecutor<'_>,
    pin: &PackagePin,
) -> Result<Vec<GateRow>, sqlx::Error> {
    if let Some(path) = pin.resolved.cache_path.as_deref() {
        // A cache pin is present while the Remote still caches the pinned
        // bytes at its path; a refresh to other bytes (or an eviction) makes
        // it unresolvable rather than gating something else.
        let rows: Vec<GateRowTuple> = sqlx::query_as(
            "SELECT id, repository_id, checksum_sha256, cached_at, \
                    CASE WHEN quarantine_released_at IS NULL THEN NULL ELSE 'released' END, \
                    quarantine_until \
             FROM proxy_cache_artifacts WHERE repository_id = $1 AND path = $2 \
               AND checksum_sha256 = $3",
        )
        .bind(pin.resolved.repository_id)
        .bind(path)
        .bind(pin.resolved.sha256.as_deref().unwrap_or_default())
        .fetch_all(db)
        .await?;
        return Ok(rows
            .into_iter()
            .map(|t| GateRow {
                cached: true,
                ..gate_row(t)
            })
            .collect());
    }
    let rows: Vec<GateRowTuple> = if pin.registry_type == "oci" {
        // #5457: every alias of the pinned digest, the rows the native
        // manifest gate evaluates too.
        let r = &pin.resolved;
        let digests: Vec<&str> = [r.digest.as_deref(), r.gate_digest.as_deref()]
            .into_iter()
            .flatten()
            .collect();
        crate::services::oci_manifests::alias_rows(db, r.repository_id, &digests)
            .await?
            .into_iter()
            .map(|a| {
                (
                    a.id,
                    a.repository_id,
                    a.checksum,
                    a.created_at,
                    a.quarantine_status,
                    a.quarantine_until,
                )
            })
            .collect()
    } else {
        sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT {GATE_ROW_COLUMNS} FROM artifacts WHERE id = ANY($1) AND is_deleted = false"
        )))
        .bind(&pin.resolved.artifact_ids)
        .fetch_all(db)
        .await?
    };
    Ok(rows
        .into_iter()
        .map(gate_row)
        .filter(|row| row_bytes_pinned(pin, row))
        .collect())
}

/// Whether an `artifacts` row still holds the bytes pinned for it: its
/// checksum is the one recorded at publish (`artifact_sha256s`, or the
/// pin's `sha256` for an older single-row pin). A row rewritten in place no
/// longer counts as the pinned row.
fn row_bytes_pinned(pin: &PackagePin, row: &GateRow) -> bool {
    let r = &pin.resolved;
    let expected = match r.artifact_ids.iter().position(|id| *id == row.id) {
        Some(i) if !r.artifact_sha256s.is_empty() => r.artifact_sha256s.get(i),
        Some(_) if r.artifact_ids.len() == 1 => r.sha256.as_ref(),
        _ => None,
    };
    expected.is_none_or(|sha| sha.eq_ignore_ascii_case(&row.checksum))
}

/// Per-evaluation memo of the mapped repositories and Virtual serve models
/// the shadowing check reads (#5456), so a listing batch reads each
/// Virtual's member walk once per coordinate.
#[derive(Default)]
pub(crate) struct ShadowCache {
    repos: HashMap<String, Option<BackingRepo>>,
    models: HashMap<(Uuid, String, String, String), ServeModel>,
}

/// Whether the advertised URL of an npm, PyPI, NuGet or Cargo pin no longer
/// delivers the pinned rows (#5456).
///
/// These pins are served as `registryBaseUrl` = the mapped repository, so a
/// client following the approved document downloads whatever that
/// repository's route serves for the coordinate. For a Virtual that is the
/// member its download walk picks ([`serve_model`]): once that is not the
/// pinned member (a higher-ranked hosted member holds the version, a Remote
/// member the format's guard does not withhold outranks it, the pinned
/// member left), the gate would be evaluating rows the client never gets,
/// so the version is held instead. For PyPI every hosted file of the version
/// is part of the pin, in a Virtual or not: a file that is not pinned (or a
/// pinned one that is gone) holds it, and so does any Remote member with an
/// upstream. The pin never moves; the version serves again once the route
/// serves the pinned rows again, or a new server version pins what it
/// serves now.
///
/// OCI pins are digest-addressed and MCPB bundles are served from their own
/// route, so neither is affected.
async fn pin_shadowed(
    db: &PgPool,
    cache: &mut ShadowCache,
    pin: &PackagePin,
    rows: &[GateRow],
) -> Result<bool, McpError> {
    let r = &pin.resolved;
    let Some(version) = pin.submitted.version.as_deref() else {
        return Ok(false);
    };
    if matches!(pin.registry_type.as_str(), "oci" | "mcpb") {
        return Ok(false);
    }
    // The repository the advertised URL names, looked up as the URL is: by
    // key.
    if !cache.repos.contains_key(&r.repository) {
        let found = repos_by_key(db, std::slice::from_ref(&r.repository))
            .await?
            .into_iter()
            .next();
        cache.repos.insert(r.repository.clone(), found);
    }
    let Some(mapped) = cache.repos[&r.repository].clone() else {
        return Ok(true);
    };
    let cached = rows.iter().any(|row| row.cached);
    // The key now names another repository than the one pinned through. A
    // cache pin records its Remote's id: through a Virtual the serve model
    // decides whether that Remote still serves; any other repository must be
    // the pinned one itself.
    if mapped.id != r.repository_id && (!cached || !mapped.is_virtual()) {
        return Ok(true);
    }
    let live: Vec<HostedRow> = rows
        .iter()
        .filter(|row| !row.cached)
        .map(|row| HostedRow {
            id: row.id,
            repository_id: row.repository_id,
            checksum: row.checksum.clone(),
        })
        .collect();
    let memo = (
        mapped.id,
        pin.registry_type.clone(),
        pin.submitted.identifier.clone(),
        version.to_string(),
    );
    if !cache.models.contains_key(&memo) {
        let model = if mapped.is_virtual() {
            serve_model(
                db,
                mapped.id,
                &pin.registry_type,
                &pin.submitted.identifier,
                version,
            )
            .await?
        } else if pin.registry_type == "pypi" {
            ServeModel {
                files: own_rows(db, &mapped, "pypi", &pin.submitted.identifier, version).await?,
                ..ServeModel::default()
            }
        } else {
            return Ok(false);
        };
        cache.models.insert(memo.clone(), model);
    }
    Ok(shadow_reason(&cache.models[&memo], pin, &live, cached).is_some())
}

/// Refuse a cache pin (a package a Remote member of `repo` has in its proxy
/// cache) that the Virtual `repo` would not serve from that Remote (#5456).
pub(crate) async fn refuse_shadowed_cache_pin(
    db: &PgPool,
    repo: &BackingRepo,
    pin: &PackagePin,
) -> Result<(), McpError> {
    if !repo.is_virtual() {
        return Ok(());
    }
    let version = pin.submitted.version.as_deref().unwrap_or_default();
    let model = serve_model(
        db,
        repo.id,
        &pin.registry_type,
        &pin.submitted.identifier,
        version,
    )
    .await?;
    match shadow_reason(&model, pin, &[], true) {
        None => Ok(()),
        Some(reason) => Err(McpError::PackageShadowed {
            index: pin.index,
            detail: format!(
                "{} is in a Remote member's proxy cache, but {reason} through repository '{}'; \
                 map the member that holds it directly",
                pin.label(),
                repo.key
            ),
        }),
    }
}

/// The first package of `stored` whose pinned bytes are no longer cleared
/// for use, read on `conn` (the transaction that commits an introspection
/// result, #5463): a package with no pin, a pin with no live row, a cache
/// pin under its hold, or a pinned `artifacts` row that is quarantined,
/// rejected or deleted. Those rows are locked `FOR SHARE`, so a quarantine,
/// rejection or deletion of a backing package either is seen here or waits
/// for the caller's commit. This is the quarantine half of
/// [`backing_gate`] only: the scan-policy, Remote and OCI-presence gates
/// stay with the full serve gate, which the caller evaluates beforehand
/// (#5533 tracks evaluating the whole gate on the transaction).
pub async fn held_backing_package(
    conn: &mut sqlx::PgConnection,
    stored: &mcp::StoredVersion,
) -> Result<Option<String>, sqlx::Error> {
    if let Some(package) = stored.unpinned_package() {
        return Ok(Some(package));
    }
    let mut pins = Vec::new();
    for pin in &stored.pins {
        pins.push((pin, gate_rows(&mut *conn, pin).await?));
    }
    // Every pinned row of every pin locked in one statement, in id order, so
    // two completions never take them in opposite orders.
    let mut ids: Vec<Uuid> = pins
        .iter()
        .flat_map(|(_, rows)| rows.iter().filter(|r| !r.cached).map(|r| r.id))
        .collect();
    ids.sort();
    ids.dedup();
    let locked: HashMap<Uuid, (Option<String>, Option<DateTime<Utc>>)> =
        sqlx::query_as::<_, (Uuid, Option<String>, Option<DateTime<Utc>>)>(
            "SELECT id, quarantine_status, quarantine_until FROM artifacts \
         WHERE id = ANY($1) AND is_deleted = false ORDER BY id FOR SHARE",
        )
        .bind(&ids)
        .fetch_all(&mut *conn)
        .await?
        .into_iter()
        .map(|(id, status, until)| (id, (status, until)))
        .collect();
    let now = Utc::now();
    let cleared = |r: &GateRow| {
        if r.cached {
            return !r.cache_held(now);
        }
        locked.get(&r.id).is_some_and(|(status, until)| {
            crate::services::quarantine_service::check_download_allowed(
                status.as_deref(),
                *until,
                now,
            )
            .is_ok()
        })
    };
    Ok(pins
        .iter()
        .find(|(_, rows)| rows.is_empty() || !rows.iter().all(cleared))
        .map(|(pin, _)| pin.label()))
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
    use crate::services::age_gate_service::{AgeGateMode, AgeGateService, ReviewIdentityMatch};
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
    let (review, identity, view) = review_view(svc, params, &package, version).await?;
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
    age_gate_verdict(
        ctx,
        params,
        &package,
        version,
        basis,
        recorded_basis,
        view.as_ref(),
        review.map(|r| r.id),
    )
    .await
}

/// The age-gate review of `(package, version)` in `params`' repository, how
/// its recorded basis relates to the repository's current policy, and the
/// policy view [`age_gate_verdict`] decides with.
async fn review_view(
    svc: &crate::services::age_gate_service::AgeGateService,
    params: &crate::services::age_gate_service::AgeGateRepoParams,
    package: &str,
    version: &str,
) -> Result<
    (
        Option<crate::services::age_gate_service::AgeGateReview>,
        Option<crate::services::age_gate_service::ReviewIdentityMatch>,
        Option<crate::services::age_gate_service::ReviewPolicyView>,
    ),
    (),
> {
    use crate::services::age_gate_service::{
        review_identity_match, upstream_fingerprint, ReviewPolicyView,
    };
    let review = svc
        .get_review(params.id, package, version)
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
    Ok((review, identity, view))
}

/// The `first_seen` age gate of one server version of a Remote MCP registry
/// (`params` is the registry itself): the basis is the first sighting the
/// sync recorded at ingest. `Ok(None)` when no gate is asked for; `Err` when
/// it cannot be evaluated (an unenforceable mode, no age-gate service, a
/// database error), which the caller fails closed.
pub(crate) async fn server_version_age_gate(
    ctx: GateCtx<'_>,
    params: &crate::services::age_gate_service::AgeGateRepoParams,
    name: &str,
    version: &str,
) -> Result<Option<GateOutcome>, ()> {
    use crate::services::age_gate_service::AgeGateService;
    if !AgeGateService::gating_requested(params) {
        return Ok(None);
    }
    AgeGateService::require_enforceable(params).map_err(|_| ())?;
    let svc = ctx.age_gate.ok_or(())?;
    let (review, _, view) = review_view(svc, params, name, version).await?;
    let seen = svc
        .lookup_first_seen(params, name, version)
        .await
        .map_err(|_| ())?;
    age_gate_verdict(
        ctx,
        params,
        name,
        version,
        seen,
        seen,
        view.as_ref(),
        review.map(|r| r.id),
    )
    .await
}

/// The age-gate verdict of one `(package, version)` of `params`' repository
/// given its age `basis` and its review state, as the download path decides
/// it ([`decide_age_gate_check`]). Under [`GateCtx::record_reviews`] a hold
/// records (or bumps) the pending review with `recorded_basis`. Shared by the
/// backing-package gate and the server-version gate of a Remote MCP registry.
///
/// [`decide_age_gate_check`]: crate::services::age_gate_service::decide_age_gate_check
#[allow(clippy::too_many_arguments)]
pub(crate) async fn age_gate_verdict(
    ctx: GateCtx<'_>,
    params: &crate::services::age_gate_service::AgeGateRepoParams,
    package: &str,
    version: &str,
    basis: Option<DateTime<Utc>>,
    recorded_basis: Option<DateTime<Utc>>,
    view: Option<&crate::services::age_gate_service::ReviewPolicyView>,
    existing_review: Option<Uuid>,
) -> Result<Option<GateOutcome>, ()> {
    use crate::services::age_gate_service::{
        decide_age_gate_check, AgeGateCheckAction, AgeGateDecision, AgeGateService,
    };
    let svc = ctx.age_gate.ok_or(())?;
    let meets =
        AgeGateService::meets_age_threshold(basis, params.age_gate_min_age_days, Utc::now());
    match decide_age_gate_check(view, meets) {
        AgeGateCheckAction::Allow
        | AgeGateCheckAction::AllowAlreadyApproved
        | AgeGateCheckAction::AllowAndAutoApprovePending => return Ok(None),
        AgeGateCheckAction::BlockRejected
        | AgeGateCheckAction::BlockAndResetReview
        | AgeGateCheckAction::BlockAndRequestReview => {}
    }
    let review_id = if ctx.record_reviews {
        match svc
            .check(params, package, version, recorded_basis)
            .await
            .map_err(|_| ())?
        {
            AgeGateDecision::Allow => return Ok(None),
            AgeGateDecision::Block { review_id, .. } => Some(review_id),
        }
    } else {
        existing_review
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
async fn backing_gate(
    ctx: GateCtx<'_>,
    cache: &mut FactsCache,
    shadows: &mut ShadowCache,
    pin: &PackagePin,
) -> GateOutcome {
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
    match pin_shadowed(ctx.db, shadows, pin, &rows).await {
        Ok(false) => {}
        Ok(true) => return GateOutcome::Shadowed,
        Err(_) => return GateOutcome::Unavailable,
    }
    let now = Utc::now();
    if rows.iter().any(|row| row.cache_held(now)) {
        return GateOutcome::Quarantine;
    }
    let gate: Vec<_> = rows
        .iter()
        .filter(|row| !row.cached)
        .map(|row| crate::services::quarantine_service::GateRow {
            artifact_id: row.id,
            repository_id: row.repository_id,
            quarantine_status: row.quarantine_status.as_deref(),
            quarantine_until: row.quarantine_until,
        })
        .collect();
    if let Err((_, e)) =
        crate::services::quarantine_service::enforce_download_gate_rows(ctx.db, &gate).await
    {
        return outcome_for_gate_error(&e);
    }
    match remote_gates(ctx, cache, pin, &rows).await {
        Ok(Some(outcome)) => outcome,
        Ok(None) => GateOutcome::Allowed,
        Err(()) => GateOutcome::Unavailable,
    }
}

/// [`backing_gate`] for every pin, plus `Unresolvable` for a package the
/// stored document names but no pin covers. Every version is gated, whatever
/// policy it was published under or the repository has now: an `open`
/// version's packages are pinned and gated like any other (#5452), and one
/// stored unpinned under `open` before that is `unresolvable`.
pub async fn backing_gates(ctx: GateCtx<'_>, stored: &mcp::StoredVersion) -> Vec<BackingGate> {
    let mut gates = Vec::new();
    if let Some(package) = stored.unpinned_package() {
        gates.push(BackingGate {
            package,
            outcome: GateOutcome::Unresolvable,
        });
    }
    let mut cache = FactsCache::new();
    let mut shadows = ShadowCache::default();
    for pin in &stored.pins {
        gates.push(BackingGate {
            package: pin.label(),
            outcome: backing_gate(ctx, &mut cache, &mut shadows, pin).await,
        });
    }
    gates
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
) -> Result<HashSet<Uuid>, GateUnavailable> {
    listing_refusals_inner(ctx, mcp_repo_id, rows)
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
        if refused.contains(&row.artifact_id) {
            continue;
        }
        for pin in &row.stored.pins {
            let found = gate_rows(db, pin).await.map_err(|_| ())?;
            pin_rows.insert((row.artifact_id, pin.index), found);
        }
    }
    let mut by_repo: HashMap<Uuid, Vec<ListingCandidate<'_>>> = HashMap::new();
    let mut backing_refused = HashSet::new();
    let now = Utc::now();
    for r in pin_rows.values().flatten() {
        if r.cached {
            if r.cache_held(now) {
                backing_refused.insert(r.id);
            }
            continue;
        }
        by_repo
            .entry(r.repository_id)
            .or_default()
            .push(ListingCandidate {
                artifact_id: r.id,
                quarantine_status: r.quarantine_status.as_deref(),
                quarantine_until: r.quarantine_until,
            });
    }
    for (repo, candidates) in &by_repo {
        backing_refused.extend(
            qs::listing_refusals_fresh(db, *repo, candidates)
                .await
                .map_err(|_| ())?,
        );
    }

    let mut cache = FactsCache::new();
    let mut shadows = ShadowCache::default();
    for row in rows {
        if refused.contains(&row.artifact_id) {
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
            if !blocked {
                blocked = pin_shadowed(db, &mut shadows, pin, found)
                    .await
                    .map_err(|_| ())?;
            }
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

    fn test_repo(key: &str, repo_type: &str, format: &str, upstream: Option<&str>) -> BackingRepo {
        BackingRepo {
            id: Uuid::nil(),
            key: key.into(),
            repo_type: repo_type.into(),
            format: format.into(),
            upstream_url: upstream.map(Into::into),
            location: StorageLocation {
                backend: "filesystem".into(),
                path: "/tmp".into(),
            },
        }
    }

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
        assert!(format_backs("mcpb", "generic"));
        assert!(format_backs("mcpb", "mcp"));
        assert!(!format_backs("mcpb", "npm"));
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
        assert!(parse_package_repos(r#"{"mcpb":"x"}"#).is_ok());
        assert!(parse_package_repos(r#"{"maven":"x"}"#).is_err());
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
        let repo = |repo_type: &str, upstream: Option<&str>| {
            test_repo("oci-r", repo_type, "docker", upstream)
        };
        let r = mcp::parse_oci_identifier("ghcr.io/acme/mcp:1.2").unwrap();
        let own_repos = |r: &mcp::OciRef, repo: &BackingRepo| {
            oci_backing_path(r, repo, "https://ak.test", PackagePolicy::OwnRepos)
        };
        let local = |path: &str| OciBackingPath {
            path: path.into(),
            foreign: false,
        };
        assert!(own_repos(&r, &repo("local", None))
            .unwrap_err()
            .contains("not this registry"));
        assert_eq!(
            own_repos(&r, &repo("virtual", None)).unwrap(),
            local("acme/mcp")
        );
        assert!(own_repos(&r, &repo("remote", Some("https://registry-1.docker.io"))).is_err());
        assert_eq!(
            own_repos(&r, &repo("remote", Some("https://ghcr.io"))).unwrap(),
            local("acme/mcp")
        );
        let own = mcp::parse_oci_identifier("ak.test/oci-r/acme/mcp:1.2").unwrap();
        assert_eq!(
            own_repos(&own, &repo("remote", Some("https://ghcr.io"))).unwrap(),
            local("acme/mcp")
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

    /// #5452: foreign coordinates stand for what a Remote holds only when
    /// they name its upstream host; coordinates naming this instance (or
    /// none) always may. A Remote with no upstream serves no foreign name.
    #[test]
    fn a_remote_serves_foreign_coordinates_only_for_its_upstream() {
        let mapped = test_repo("npm-v", "virtual", "npm", None);
        let remote = test_repo(
            "npm-r",
            "remote",
            "npm",
            Some("https://Registry.NPMjs.org/"),
        );
        let pkg = |base: Option<&str>| -> mcp::Package {
            serde_json::from_value(serde_json::json!({
                "registryType": "npm", "identifier": "@corp/tool", "version": "1.0.0",
                "registryBaseUrl": base, "transport": {"type": "stdio"},
            }))
            .unwrap()
        };
        let base = "https://ak.test";
        for (submitted, may) in [
            (None, true),
            (Some("https://ak.test/npm/npm-v"), true),
            (Some("https://registry.npmjs.org"), true),
            (Some("https://npm.internal.corp"), false),
            (Some("https://registry.npmjs.org.evil.test"), false),
        ] {
            assert_eq!(
                remote_may_serve(&pkg(submitted), &mapped, &remote, base),
                may,
                "{submitted:?}"
            );
        }
        let bare = test_repo("npm-r", "remote", "npm", None);
        assert!(!remote_may_serve(
            &pkg(Some("https://registry.npmjs.org")),
            &mapped,
            &bare,
            base
        ));
        let e = foreign_through_remote(3, &pkg(Some("https://npm.internal.corp")), &remote);
        assert!(matches!(e, McpError::ExternalRegistry { index: 3, .. }));
        assert!(e.detail().contains("npm.internal.corp") && e.detail().contains("npm-r"));
    }

    /// #5452: a submitted registry URL is a Remote's upstream only with the
    /// same origin and a path under the upstream's, segment by segment: one
    /// project or repository of a shared host is not another. A root-path
    /// upstream covers every path of its origin; nothing unparseable matches.
    #[test]
    fn registry_urls_match_by_origin_and_path_prefix() {
        let gitlab = "https://gitlab.com/api/v4/projects/222/packages/pypi/simple";
        let nexus = "https://nexus.corp/repository/npm-public/";
        for (upstream, submitted, under) in [
            (gitlab, gitlab, true),
            (
                gitlab,
                "https://gitlab.com/api/v4/projects/222/packages/pypi/simple/",
                true,
            ),
            (
                gitlab,
                "https://GitLab.com:443/api/v4/projects/222/packages/pypi/simple/tool",
                true,
            ),
            (
                gitlab,
                "https://gitlab.com/api/v4/projects/111/packages/pypi/simple",
                false,
            ),
            (
                gitlab,
                "https://gitlab.com/api/v4/projects/2222/packages/pypi/simple",
                false,
            ),
            (gitlab, "https://gitlab.com/api/v4/projects/222", false),
            (nexus, "https://nexus.corp/repository/npm-public", true),
            (nexus, "https://nexus.corp/repository/npm-private/", false),
            (nexus, "https://nexus.corp/repository/npm-public-2/", false),
            (
                "https://registry.npmjs.org/",
                "https://registry.npmjs.org",
                true,
            ),
            (
                "https://registry.npmjs.org/",
                "https://registry.npmjs.org/any/path",
                true,
            ),
            (
                "https://registry.npmjs.org",
                "http://registry.npmjs.org",
                false,
            ),
            (
                "https://registry.npmjs.org",
                "https://registry.npmjs.org:8443",
                false,
            ),
            (
                "https://registry.npmjs.org",
                "https://registry.npmjs.org.evil.test",
                false,
            ),
            ("https://registry.npmjs.org", "not a url", false),
            ("not a url", "https://registry.npmjs.org", false),
        ] {
            assert_eq!(
                url_is_under(upstream, submitted),
                under,
                "{upstream} / {submitted}"
            );
        }
        let remote = test_repo("pypi-r", "remote", "pypi", Some(gitlab));
        let mapped = test_repo("pypi-r", "remote", "pypi", Some(gitlab));
        let pkg = |base: &str| -> mcp::Package {
            serde_json::from_value(serde_json::json!({
                "registryType": "pypi", "identifier": "tool", "version": "1.0.0",
                "registryBaseUrl": base, "transport": {"type": "stdio"},
            }))
            .unwrap()
        };
        assert!(remote_may_serve(
            &pkg(gitlab),
            &mapped,
            &remote,
            "https://ak.test"
        ));
        assert!(!remote_may_serve(
            &pkg("https://gitlab.com/api/v4/projects/111/packages/pypi/simple"),
            &mapped,
            &remote,
            "https://ak.test"
        ));
    }

    /// #5452: a pin found in a Remote's proxy cache records the foreign
    /// coordinates it replaced, once, as a direct pin does; this instance's
    /// own `registryBaseUrl` (or none) records nothing.
    #[test]
    fn proxy_cache_pins_note_foreign_coordinates() {
        let repo = test_repo("npm-r", "remote", "npm", Some("https://registry.npmjs.org"));
        let pkg = |base: Option<&str>| -> mcp::Package {
            serde_json::from_value(serde_json::json!({
                "registryType": "npm", "identifier": "@acme/x", "version": "1.0.0",
                "registryBaseUrl": base, "transport": {"type": "stdio"},
            }))
            .unwrap()
        };
        let mut pin = PackagePin {
            index: 0,
            registry_type: "npm".into(),
            submitted: SubmittedRef {
                identifier: "@acme/x".into(),
                version: Some("1.0.0".into()),
            },
            resolved: ResolvedPin {
                repository: repo.key.clone(),
                repository_id: repo.id,
                artifact_ids: Vec::new(),
                artifact_sha256s: Vec::new(),
                sha256: Some("cd".repeat(32)),
                name: None,
                tag: None,
                digest: None,
                media_type: None,
                children: Vec::new(),
                gate_digest: None,
                resolved_at: Utc::now(),
                warnings: Vec::new(),
                cache_path: Some("@acme/x/-/x-1.0.0.tgz".into()),
                download_path: None,
            },
            drift: None,
        };
        let base = "https://ak.test";
        for own in [None, Some("https://ak.test/npm/npm-r/")] {
            assert!(!registry_base_url_is_foreign(&pkg(own), &repo, base));
            note_foreign_coordinates(&mut pin, &pkg(own), &repo, base);
            assert!(pin.resolved.warnings.is_empty(), "{own:?}");
        }
        let evil = pkg(Some("https://npm.evil.test"));
        assert!(registry_base_url_is_foreign(&evil, &repo, base));
        note_foreign_coordinates(&mut pin, &evil, &repo, base);
        note_foreign_coordinates(&mut pin, &evil, &repo, base);
        assert_eq!(pin.resolved.warnings, [FOREIGN_COORDINATES_WARNING]);
    }

    /// #5452: under `open` an image on a foreign host is not refused, but it
    /// is looked up (by path) in the backing repository and flagged foreign,
    /// so the pin records that its served coordinates replaced the submitted
    /// ones. `own-repos` keeps refusing the same identifiers.
    #[test]
    fn open_policy_looks_foreign_images_up_in_the_backing_repository() {
        let repo = |repo_type: &str, upstream: Option<&str>| {
            test_repo("oci-r", repo_type, "docker", upstream)
        };
        let open = |r: &mcp::OciRef, repo: &BackingRepo| {
            oci_backing_path(r, repo, "https://ak.test", PackagePolicy::Open)
        };
        let evil = mcp::parse_oci_identifier("evil.example/acme/mcp:1.2").unwrap();
        // A Remote holds what its upstream served: another host is refused.
        assert!(open(&evil, &repo("remote", Some("https://ghcr.io"))).is_err());
        for backing in [repo("local", None), repo("staging", None)] {
            assert!(
                oci_backing_path(&evil, &backing, "https://ak.test", PackagePolicy::OwnRepos)
                    .is_err(),
                "{}",
                backing.repo_type
            );
            assert_eq!(
                open(&evil, &backing).unwrap(),
                OciBackingPath {
                    path: "acme/mcp".into(),
                    foreign: true
                },
                "{}",
                backing.repo_type
            );
        }
        // Coordinates `own-repos` accepts are not flagged under `open`.
        let upstream = mcp::parse_oci_identifier("ghcr.io/acme/mcp:1.2").unwrap();
        assert!(
            !open(&upstream, &repo("remote", Some("https://ghcr.io")))
                .unwrap()
                .foreign
        );
        let own = mcp::parse_oci_identifier("ak.test/oci-r/acme/mcp:1.2").unwrap();
        assert_eq!(
            open(&own, &repo("local", None)).unwrap(),
            OciBackingPath {
                path: "acme/mcp".into(),
                foreign: false
            }
        );
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
        assert!(name_predicate("nuget").contains("lower(a.name)"));
        // S4: as the download routes look a package up (#5253).
        assert_eq!(
            name_predicate("cargo"),
            "a.name = lower($2) AND a.version = $3"
        );
        assert_eq!(
            name_predicate("nuget"),
            "lower(a.name) = lower($2) AND a.version = $3"
        );
        assert_eq!(lookup_version("nuget", "1.0").as_deref(), Some("1.0.0"));
        assert_eq!(
            lookup_version("nuget", "1.0.0-Beta").as_deref(),
            Some("1.0.0-beta")
        );
        assert_eq!(lookup_version("nuget", "not-a-version"), None);
        assert_eq!(lookup_version("npm", "1.0").as_deref(), Some("1.0"));
        assert_eq!(
            lookup_version("cargo", "1.0.0-RC.1").as_deref(),
            Some("1.0.0-RC.1")
        );
        assert_eq!(lookup_name("npm", "%40acme%2Fx"), "@acme/x");
        assert_eq!(name_predicate("npm"), "a.name = $2 AND a.version = $3");
        assert_eq!(lookup_name("pypi", "Acme_SDK"), "acme-sdk");
        assert_eq!(lookup_name("npm", "@Acme/x"), "@Acme/x");
    }
}
