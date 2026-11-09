//! MCP registry package resolution at publish, and the async resolver
//! (#5253, Phase 2 item 2, Phase 3 item 2).
//!
//! At publish every `packages[]` entry is resolved against this instance:
//!
//! * npm, PyPI, NuGet, Cargo, OCI: [`mcp_packages::resolve_one`], and for a
//!   Remote backing repository (or the first Remote member of a Virtual
//!   one) the Remote's proxy cache, where a package pulled through it lives.
//! * `mcpb`: a bundle uploaded beside the version (or in the repository
//!   `mcp_package_repos.mcpb` maps), matched by `fileSha256`.
//!
//! A package that a Remote backing repository does not hold yet is not
//! refused: the version is stored `resolving` (held, [`HoldKind::Resolving`]
//! on reads), the publish answers `202`, and a job here fills the Remote
//! through its own proxy path (an in-process request to the format's
//! routes, so the Remote's curation, age gate, scan-on-proxy and quarantine
//! apply exactly as for a client pull), then resolves and pins the package.
//! A definitive refusal (upstream 404, curation block, age gate, no read
//! access) marks the version failed (`unresolvable` on reads); a transient
//! one (5xx, 429, timeout) is retried with backoff, at most
//! [`MAX_ATTEMPTS`] times. Jobs are row-claimed (`FOR UPDATE SKIP LOCKED` +
//! claim token), so any number of replicas can run the loop.
//!
//! The backend connects only to the Remote's configured upstream, through
//! the Remote's own proxy code; a URL in a server.json is never fetched.
//!
//! [`HoldKind::Resolving`]: crate::formats::mcp::HoldKind::Resolving

use std::time::Duration;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;
use uuid::Uuid;

use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::formats::mcp::{self as fmt, McpError, PackagePin, ResolvedPin, SubmittedRef};
use crate::services::mcp_packages::{self, BackingRepo, McpSettings};

/// Attempts before a version whose fill keeps failing transiently fails.
pub const MAX_ATTEMPTS: i32 = 8;
/// How long one claim lasts before another replica may take the job.
const CLAIM_SECS: i64 = 600;
/// Jobs one tick claims.
const BATCH: i64 = 8;
/// Largest JSON document read from a format route during a fill.
/// What a finished job does after commit: the pins written, and the
/// `(backing repository, row)` pairs `hold_pins` created (scanned after commit).
type PostCommit = (Vec<PackagePin>, Vec<(Uuid, Uuid)>);

const FILL_JSON_MAX: usize = 8 * 1024 * 1024;
/// One deadline over a whole fill: every format request it makes, response
/// head and body alike (#5395). Shorter than [`CLAIM_SECS`], so a stalled
/// fill gives its job up before another replica may claim it.
pub const FILL_DEADLINE: Duration = Duration::from_secs(300);

// ---------------------------------------------------------------------------
// Resolution at publish
// ---------------------------------------------------------------------------

/// A package a Remote backing repository must be filled with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Pending {
    pub index: usize,
    pub registry_type: String,
    pub identifier: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// The Remote to fill.
    pub fill_repository: String,
    pub fill_repository_id: Uuid,
    pub fill_format: String,
    /// The submitted `registryBaseUrl` (accepted under `open` when foreign,
    /// #5452), so the pin a fill produces records
    /// [`mcp_packages::FOREIGN_COORDINATES_WARNING`] as a direct pin does.
    /// Never fetched.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registry_base_url: Option<String>,
}

impl Pending {
    fn package(&self) -> fmt::Package {
        serde_json::from_value(serde_json::json!({
            "registryType": self.registry_type,
            "identifier": self.identifier,
            "version": self.version,
            "registryBaseUrl": self.registry_base_url,
            "transport": {"type": "stdio"},
        }))
        .expect("a pending package is a valid package")
    }
}

/// The outcome of resolving every package of a document.
#[derive(Debug, Clone, Default)]
pub struct Resolution {
    pub pins: Vec<PackagePin>,
    pub pending: Vec<Pending>,
}

/// The MCP repository and version a publish resolves for (bundles are looked
/// up beside it).
#[derive(Debug, Clone, Copy)]
pub struct Target<'a> {
    pub repo_id: Uuid,
    pub repo_key: &'a str,
    pub name: &'a str,
    pub version: &'a str,
}

/// Resolve every package of `server`. A package missing from a Remote
/// backing repository (directly, or as a Virtual's Remote member) is
/// returned in `pending` instead of refused; the caller stores the version
/// `resolving` and queues it ([`enqueue`]), or, for a dry run, reports it.
pub async fn resolve_document(
    state: &SharedState,
    settings: &McpSettings,
    target: Target<'_>,
    server: &fmt::ServerJson,
    base_url: &str,
) -> Result<Resolution, McpError> {
    // `open` resolves exactly as `own-repos` does (#5452): it only accepts
    // foreign coordinates (`mcp_packages::resolve_package`).
    let mut out = Resolution::default();
    for (index, pkg) in server.packages.iter().enumerate() {
        if pkg.registry_type == "mcpb" {
            out.pins
                .push(resolve_bundle(&state.db, settings, target, index, pkg).await?);
            continue;
        }
        match mcp_packages::resolve_one(state, settings, index, pkg, base_url).await {
            Ok(pin) => out.pins.push(pin),
            Err(McpError::PackageNotFound { index, detail }) => {
                let repo = &settings.repos[&pkg.registry_type];
                let Some(remote) = fill_target(&state.db, repo).await? else {
                    return Err(McpError::PackageNotFound { index, detail });
                };
                // Foreign coordinates (`open`) are neither pinned from nor
                // filled through a Remote of another upstream (#5452).
                if !mcp_packages::remote_may_serve(pkg, repo, &remote, base_url) {
                    return Err(mcp_packages::foreign_through_remote(index, pkg, &remote));
                }
                match cached_pin(&state.db, repo, &remote, index, pkg).await? {
                    Some(mut pin) => {
                        mcp_packages::note_foreign_coordinates(&mut pin, pkg, repo, base_url);
                        out.pins.push(pin)
                    }
                    None => out.pending.push(Pending {
                        index,
                        registry_type: pkg.registry_type.clone(),
                        identifier: pkg.identifier.clone(),
                        version: pkg.version.clone(),
                        fill_repository: remote.key.clone(),
                        fill_repository_id: remote.id,
                        fill_format: remote.format.clone(),
                        registry_base_url: pkg.registry_base_url.clone(),
                    }),
                }
            }
            Err(e) => return Err(e),
        }
    }
    Ok(out)
}

fn db_err(e: impl std::fmt::Display) -> McpError {
    McpError::Internal(e.to_string())
}

/// The Remote a missing package can be filled through: the backing
/// repository itself, or the first Remote member (by priority) of a Virtual
/// one. `None` for a hosted backing repository (nothing to fill from).
pub async fn fill_target(db: &PgPool, repo: &BackingRepo) -> Result<Option<BackingRepo>, McpError> {
    if repo.is_remote() {
        return Ok(Some(repo.clone()));
    }
    if !repo.is_virtual() {
        return Ok(None);
    }
    let key: Option<String> = sqlx::query_scalar(
        "SELECT r.key FROM virtual_repo_members m JOIN repositories r ON r.id = m.member_repo_id \
         WHERE m.virtual_repo_id = $1 AND r.repo_type = 'remote' ORDER BY m.priority LIMIT 1",
    )
    .bind(repo.id)
    .fetch_optional(db)
    .await
    .map_err(db_err)?;
    match key {
        Some(k) => Ok(mcp_packages::repos_by_key(db, &[k])
            .await?
            .into_iter()
            .next()),
        None => Ok(None),
    }
}

// ---------------------------------------------------------------------------
// Proxy-cache pins
// ---------------------------------------------------------------------------

/// Where a Remote's proxy cache keeps a package version, as an exact path or
/// a file-name suffix (PyPI distributions have several files and names).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CacheKey {
    Exact(String),
    /// Paths under `prefix` whose file name passes [`pypi_file_matches`].
    PypiFiles {
        prefix: String,
    },
    /// A NuGet package: the V3 flat-container path
    /// (`v3/flatcontainer/{id}/{version}/{id}.{version}.nupkg`, every segment
    /// lowercase, the version normalised: what a NuGet client requests), or
    /// the key a V2 upstream's `package/{id}/{version}` download is cached
    /// under (`v2_path`).
    Nupkg {
        v3_path: String,
        v2_path: String,
    },
}

/// `@scope/name` -> `name`; `name` -> `name`.
fn npm_base_name(name: &str) -> &str {
    name.rsplit('/').next().unwrap_or(name)
}

/// The cache key of `registry_type` `identifier@version` (pure). OCI is not
/// cached this way (its pulls write manifest rows).
pub fn cache_key(registry_type: &str, identifier: &str, version: &str) -> Option<CacheKey> {
    let name = mcp_packages::lookup_name(registry_type, identifier);
    match registry_type {
        "npm" => Some(CacheKey::Exact(format!(
            "{name}/-/{}-{version}.tgz",
            npm_base_name(&name)
        ))),
        "cargo" => Some(CacheKey::Exact(format!(
            "api/v1/crates/{}/{version}/download",
            name.to_ascii_lowercase()
        ))),
        "nuget" => {
            // A version NuGet cannot normalise is never requested by a
            // client: nothing to pin.
            let id = name.to_ascii_lowercase();
            let v = crate::formats::nuget::NugetHandler::normalized_version(version)?
                .to_ascii_lowercase();
            Some(CacheKey::Nupkg {
                v3_path: format!("v3/flatcontainer/{id}/{v}/{id}.{v}.nupkg"),
                v2_path: format!("v2/package/{id}/{v}/package.nupkg"),
            })
        }
        "pypi" => Some(CacheKey::PypiFiles {
            prefix: format!("simple/{name}/"),
        }),
        _ => None,
    }
}

/// Whether a PyPI distribution file name is `name`'s `version`: a wheel
/// (`{dist}-{version}-...whl`) or an sdist (`{name}-{version}.tar.gz`,
/// `.zip`), names compared PEP 503-normalised.
pub fn pypi_file_matches(file: &str, name: &str, version: &str) -> bool {
    use crate::formats::pypi::PypiHandler;
    let want = PypiHandler::normalize_name(name);
    let (dist, ver) = if let Some(stem) = file.strip_suffix(".whl") {
        let mut parts = stem.splitn(3, '-');
        match (parts.next(), parts.next()) {
            (Some(d), Some(v)) => (d, v),
            _ => return false,
        }
    } else if let Some(stem) = file
        .strip_suffix(".tar.gz")
        .or_else(|| file.strip_suffix(".zip"))
    {
        match stem.rsplit_once('-') {
            Some(pair) => pair,
            None => return false,
        }
    } else {
        return false;
    };
    ver == version && PypiHandler::normalize_name(dist) == want
}

/// The proxy-cache entry of a package in `remote`, as `(path, sha256)`.
async fn find_cached(
    db: &PgPool,
    remote: &BackingRepo,
    pkg: &fmt::Package,
) -> Result<Option<(String, String)>, McpError> {
    let Some(version) = pkg.version.as_deref() else {
        return Ok(None);
    };
    cached_entry(db, remote.id, &pkg.registry_type, &pkg.identifier, version).await
}

/// The proxy-cache entry of `registry_type` `identifier@version` in the
/// Remote `remote_id`, as `(path, sha256)`: [`find_cached`] by its parts.
pub(crate) async fn cached_entry(
    db: &PgPool,
    remote_id: Uuid,
    registry_type: &str,
    identifier: &str,
    version: &str,
) -> Result<Option<(String, String)>, McpError> {
    let Some(key) = cache_key(registry_type, identifier, version) else {
        return Ok(None);
    };
    // Proxy-cache paths are exact, case-sensitive storage keys (the format
    // handlers look an entry up by its exact key), so the match is exact:
    // folding case would pin, say, `1.0.0-RC.1` for a `1.0.0-rc.1` request.
    // PyPI matches the files of the normalised project whose name carries
    // the version (filtered exactly below), so the row cap cannot cut the
    // right file off.
    use crate::api::handlers::escape_like_literal;
    let pattern = match &key {
        CacheKey::Exact(p) => escape_like_literal(p),
        CacheKey::PypiFiles { prefix } => format!(
            "{}%{}%",
            escape_like_literal(prefix),
            escape_like_literal(version)
        ),
        CacheKey::Nupkg { v3_path, .. } => escape_like_literal(v3_path),
    };
    // A NuGet V2 upstream caches the package under its own key.
    let exact = match &key {
        CacheKey::Nupkg { v2_path, .. } => Some(v2_path.as_str()),
        _ => None,
    };
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT path, checksum_sha256 FROM proxy_cache_artifacts \
         WHERE repository_id = $1 AND checksum_sha256 IS NOT NULL \
           AND (path LIKE $2 ESCAPE '\\' OR path = $3) \
         ORDER BY path LIMIT 200",
    )
    .bind(remote_id)
    .bind(&pattern)
    .bind(exact)
    .fetch_all(db)
    .await
    .map_err(db_err)?;
    Ok(rows.into_iter().find(|(path, _)| match &key {
        CacheKey::PypiFiles { .. } => path
            .rsplit('/')
            .next()
            .is_some_and(|f| pypi_file_matches(f, identifier, version)),
        _ => true,
    }))
}

/// A pin on a package the proxy cache of `mapped`'s fill target holds (the
/// mapped Remote itself, or a Virtual's first Remote member); `None` when
/// `mapped` has no Remote to pull through or the package is not cached.
/// Remote MCP ingest uses it after the `artifacts` lookup misses: npm, PyPI,
/// NuGet and Cargo packages pulled through a Remote live only in its proxy
/// cache.
///
/// Foreign coordinates (`open`) naming another registry than the Remote's
/// upstream are refused ([`mcp_packages::remote_may_serve`]); the pin records
/// [`mcp_packages::FOREIGN_COORDINATES_WARNING`] when they name it.
pub async fn cached_pin_through(
    db: &PgPool,
    mapped: &BackingRepo,
    index: usize,
    pkg: &fmt::Package,
    base_url: &str,
) -> Result<Option<PackagePin>, McpError> {
    let Some(remote) = fill_target(db, mapped).await? else {
        return Ok(None);
    };
    if !mcp_packages::remote_may_serve(pkg, mapped, &remote, base_url) {
        return Err(mcp_packages::foreign_through_remote(index, pkg, &remote));
    }
    let mut found = cached_pin(db, mapped, &remote, index, pkg).await?;
    if let Some(pin) = found.as_mut() {
        mcp_packages::note_foreign_coordinates(pin, pkg, mapped, base_url);
    }
    Ok(found)
}

/// A pin on a package `remote` (the mapped repository or its Remote member)
/// has in its proxy cache. Every path that pins a proxy-cache entry (the
/// publish, the asynchronous fill, Remote MCP ingest) comes through here, so
/// each refuses a pin the mapped Virtual would not serve from `remote`
/// (`mcp_package_shadowed`, #5456).
async fn cached_pin(
    db: &PgPool,
    mapped: &BackingRepo,
    remote: &BackingRepo,
    index: usize,
    pkg: &fmt::Package,
) -> Result<Option<PackagePin>, McpError> {
    let Some((path, sha256)) = find_cached(db, remote, pkg).await? else {
        return Ok(None);
    };
    let pin = PackagePin {
        index,
        registry_type: pkg.registry_type.clone(),
        submitted: SubmittedRef {
            identifier: pkg.identifier.clone(),
            version: pkg.version.clone(),
        },
        resolved: ResolvedPin {
            repository: mapped.key.clone(),
            repository_id: remote.id,
            artifact_ids: Vec::new(),
            artifact_sha256s: Vec::new(),
            sha256: Some(sha256),
            name: None,
            tag: None,
            digest: None,
            media_type: None,
            children: Vec::new(),
            gate_digest: None,
            resolved_at: Utc::now(),
            warnings: Vec::new(),
            cache_path: Some(path),
            download_path: None,
        },
        drift: None,
    };
    mcp_packages::refuse_shadowed_cache_pin(db, mapped, &pin).await?;
    Ok(Some(pin))
}

// ---------------------------------------------------------------------------
// MCPB bundles
// ---------------------------------------------------------------------------

/// The route a bundle of `name@version` in `repo_key` is downloaded from,
/// relative to the instance base URL.
///
/// The name keeps its literal `/` (the split route spelling): a download
/// ticket binds the exact request path, and a ticket path may not carry an
/// encoded slash.
pub fn bundle_route(repo_key: &str, name: &str, version: &str, file: &str) -> String {
    format!(
        "mcp/{repo_key}/v0.1/servers/{name}/versions/{}/bundles/{}",
        urlencoding::encode(version),
        urlencoding::encode(file)
    )
}

/// `servers/<name>/<version>/bundles/<file>`: where a bundle is stored.
pub fn bundle_path(name: &str, version: &str, file: &str) -> String {
    format!("servers/{name}/{version}/bundles/{file}")
}

fn bundle_pin(
    index: usize,
    pkg: &fmt::Package,
    repo_key: &str,
    repo_id: Uuid,
    artifact_id: Uuid,
    sha256: &str,
    download_path: String,
) -> PackagePin {
    PackagePin {
        index,
        registry_type: "mcpb".into(),
        submitted: SubmittedRef {
            identifier: pkg.identifier.clone(),
            version: pkg.version.clone(),
        },
        resolved: ResolvedPin {
            repository: repo_key.to_string(),
            repository_id: repo_id,
            artifact_ids: vec![artifact_id],
            artifact_sha256s: Vec::new(),
            sha256: Some(sha256.to_string()),
            name: None,
            tag: None,
            digest: None,
            media_type: None,
            children: Vec::new(),
            gate_digest: None,
            resolved_at: Utc::now(),
            warnings: Vec::new(),
            cache_path: None,
            download_path: Some(download_path),
        },
        drift: None,
    }
}

/// Resolve an `mcpb` entry by its `fileSha256`: a bundle uploaded beside this
/// version, else one in the repository `mcp_package_repos.mcpb` maps (an MCP
/// registry's bundles, or a `.mcpb` file in a Generic repository). The
/// identifier the publisher wrote is kept as `submitted`; the served
/// identifier is the bundle's Artifact Keeper URL.
pub async fn resolve_bundle(
    db: &PgPool,
    settings: &McpSettings,
    target: Target<'_>,
    index: usize,
    pkg: &fmt::Package,
) -> Result<PackagePin, McpError> {
    if pkg.registry_base_url.is_some() {
        return Err(McpError::ExternalRegistry {
            index,
            detail: "an mcpb package carries its download URL in `identifier`; remove \
                     `registryBaseUrl`"
                .into(),
        });
    }
    let sha = pkg.file_sha256.as_deref().unwrap_or_default();
    // The PUBLISHING repository's signature policy applies to every bundle
    // it pins, wherever the bundle lives, judged on the bundle's recorded
    // signature facts against the trusted signer list as it is now. A
    // Generic repository's `.mcpb` has no recorded facts (unsigned).
    let require = require_bundle_signature(db, target.repo_id).await?;
    let check = |facts: Option<&serde_json::Value>| -> Result<(), McpError> {
        if !require {
            return Ok(());
        }
        match crate::services::mcpb::recorded_state(
            facts,
            &crate::services::mcpb::trusted_signers(),
        ) {
            crate::services::mcpb::SignatureState::Valid => Ok(()),
            state => Err(McpError::BundleSignatureRequired {
                index,
                detail: format!(
                    "this registry requires MCPB bundles signed by a trusted signer \
                     (mcp_require_bundle_signature); the bundle with fileSha256 {sha} is {}",
                    match state {
                        crate::services::mcpb::SignatureState::SelfSigned =>
                            "signed by a signer that is not on the trusted signer list",
                        crate::services::mcpb::SignatureState::Invalid => "invalidly signed",
                        _ => "unsigned",
                    }
                ),
            }),
        }
    };
    if let Some((id, name, version, file, facts)) =
        find_bundle(db, target.repo_id, Some((target.name, target.version)), sha).await?
    {
        check(facts.as_ref())?;
        return Ok(bundle_pin(
            index,
            pkg,
            target.repo_key,
            target.repo_id,
            id,
            sha,
            bundle_route(target.repo_key, &name, &version, &file),
        ));
    }
    if let Some(repo) = settings.repos.get("mcpb") {
        let found = if repo.format == "mcp" {
            find_bundle(db, repo.id, None, sha)
                .await?
                .map(|(id, n, v, f, facts)| (id, bundle_route(&repo.key, &n, &v, &f), facts))
        } else {
            sqlx::query_as::<_, (Uuid, String)>(
                "SELECT id, path FROM artifacts WHERE repository_id = $1 AND is_deleted = false \
                 AND checksum_sha256 = $2 AND path LIKE '%.mcpb' ORDER BY path LIMIT 1",
            )
            .bind(repo.id)
            .bind(sha)
            .fetch_optional(db)
            .await
            .map_err(db_err)?
            .map(|(id, path)| (id, format!("general/{}/{}", repo.key, path), None))
        };
        if let Some((id, route, facts)) = found {
            check(facts.as_ref())?;
            return Ok(bundle_pin(index, pkg, &repo.key, repo.id, id, sha, route));
        }
    }
    Err(McpError::PackageNotFound {
        index,
        detail: format!(
            "no MCPB bundle with fileSha256 {sha} was uploaded for {}@{}; upload it with \
             PUT .../versions/{{version}}/bundles/{{file}}.mcpb first",
            target.name, target.version
        ),
    })
}

/// Whether `repo_id` sets `mcp_require_bundle_signature`.
async fn require_bundle_signature(db: &PgPool, repo_id: Uuid) -> Result<bool, McpError> {
    let v: Option<String> = sqlx::query_scalar(
        "SELECT value FROM repository_config WHERE repository_id = $1 AND key = $2",
    )
    .bind(repo_id)
    .bind(crate::services::mcp_settings::REQUIRE_BUNDLE_SIGNATURE_KEY)
    .fetch_optional(db)
    .await
    .map_err(db_err)?;
    Ok(v.as_deref().map(str::trim) == Some("true"))
}

/// A live bundle found by [`find_bundle`]: `(artifact id, name, version,
/// file, recorded signature facts)`.
type FoundBundle = (Uuid, String, String, String, Option<serde_json::Value>);

/// A live bundle of `repo_id` with `sha` (optionally of one `name@version`).
async fn find_bundle(
    db: &PgPool,
    repo_id: Uuid,
    of: Option<(&str, &str)>,
    sha: &str,
) -> Result<Option<FoundBundle>, McpError> {
    let row: Option<FoundBundle> = sqlx::query_as(
        "SELECT a.id, a.name, a.version, a.path, m.metadata->'signature' FROM artifacts a \
         JOIN artifact_metadata m ON m.artifact_id = a.id \
         WHERE a.repository_id = $1 AND a.is_deleted = false AND m.format = 'mcpb' \
           AND a.checksum_sha256 = $2 AND ($3::text IS NULL OR (a.name = $3 AND a.version = $4)) \
         ORDER BY a.created_at LIMIT 1",
    )
    .bind(repo_id)
    .bind(sha)
    .bind(of.map(|o| o.0))
    .bind(of.map(|o| o.1).unwrap_or_default())
    .fetch_optional(db)
    .await
    .map_err(db_err)?;
    Ok(row.map(|(id, name, version, path, facts)| {
        let file = path.rsplit('/').next().unwrap_or_default().to_string();
        (id, name, version, file, facts)
    }))
}

/// `metadata.bundles[]` for the `mcpb` pins of a version: each bundle's facts
/// as recorded at upload (`fileSha256`, `size`, `signature`, `manifest`).
pub async fn bundle_facts(
    db: &PgPool,
    pins: &[PackagePin],
) -> Result<Vec<serde_json::Value>, McpError> {
    let mut out = Vec::new();
    for pin in pins.iter().filter(|p| p.registry_type == "mcpb") {
        let Some(id) = pin.resolved.artifact_ids.first() else {
            continue;
        };
        let facts: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT metadata FROM artifact_metadata WHERE artifact_id = $1 AND format = 'mcpb'",
        )
        .bind(id)
        .fetch_optional(db)
        .await
        .map_err(db_err)?;
        let mut facts = facts.unwrap_or_else(|| {
            // A bundle in a Generic repository: no upload-time facts.
            serde_json::json!({
                "fileSha256": pin.resolved.sha256,
                "signature": {"state": "unsigned"},
                "manifest": null,
            })
        });
        if let Some(o) = facts.as_object_mut() {
            o.insert("artifactId".into(), serde_json::json!(id));
            o.insert("index".into(), pin.index.into());
        }
        out.push(facts);
    }
    Ok(out)
}

/// The credential scope of the publish that queued a fill
/// (`resolution.requestedScope`): the asynchronous fill runs with exactly
/// this scope, never wider than the publishing token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestedScope {
    /// The token's scopes; `None` for an unscoped credential.
    pub scopes: Option<Vec<String>>,
    /// The token's repository allowlist; `None` when unrestricted.
    pub repositories: Option<Vec<Uuid>>,
    #[serde(default)]
    pub api_token: bool,
}

impl RequestedScope {
    pub fn of(ext: &AuthExtension) -> Self {
        Self {
            scopes: ext.scopes.clone(),
            repositories: match &ext.allowed_repo_ids {
                crate::models::access_scope::AccessScope::Admin => None,
                crate::models::access_scope::AccessScope::Restricted(ids) => Some(ids.clone()),
            },
            api_token: ext.is_api_token,
        }
    }

    /// The scope of a job whose recorded scope is missing or unreadable:
    /// nothing (fail closed).
    pub fn none() -> Self {
        Self {
            scopes: Some(Vec::new()),
            repositories: Some(Vec::new()),
            api_token: true,
        }
    }

    /// `auth` narrowed to this scope (pure).
    pub fn apply(&self, mut auth: AuthExtension) -> AuthExtension {
        auth.is_api_token = self.api_token;
        auth.scopes = self.scopes.clone();
        auth.allowed_repo_ids = match &self.repositories {
            None => crate::models::access_scope::AccessScope::Admin,
            Some(ids) => crate::models::access_scope::AccessScope::Restricted(ids.clone()),
        };
        auth
    }

    /// The recorded scope of a stored metadata document.
    pub fn of_metadata(meta: &serde_json::Value) -> Self {
        meta.pointer("/resolution/requestedScope")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_else(Self::none)
    }
}

/// The stored metadata document of a publish: [`fmt::metadata_doc`] plus
/// `bundles` and, when packages are still being filled, `resolution`
/// (including the publishing credential's [`RequestedScope`]).
pub async fn metadata_with_resolution(
    db: &PgPool,
    mut doc: serde_json::Value,
    res: &Resolution,
    requester: &AuthExtension,
    base_url: &str,
) -> Result<serde_json::Value, McpError> {
    let requested_by = requester.user_id;
    let bundles = bundle_facts(db, &res.pins).await?;
    if !bundles.is_empty() {
        doc["bundles"] = bundles.into();
    }
    if !res.pending.is_empty() {
        doc["resolution"] = serde_json::json!({
            "state": "resolving",
            "pending": res.pending,
            "requestedAt": Utc::now(),
            "requestedBy": requested_by,
            "requestedScope": RequestedScope::of(requester),
            "baseUrl": base_url,
            "attempts": 0,
        });
    }
    Ok(doc)
}

/// Queue the fill job of a version stored `resolving`, inside the publish's
/// transaction.
pub async fn enqueue(
    conn: &mut sqlx::PgConnection,
    artifact_id: Uuid,
    repo_id: Uuid,
    requested_by: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO mcp_resolve_jobs (artifact_id, repository_id, requested_by) \
         VALUES ($1, $2, $3) ON CONFLICT (artifact_id) DO UPDATE SET \
           attempts = 0, next_attempt_at = NOW(), claim_token = NULL, claim_expires_at = NULL, \
           last_error = NULL, requested_by = $3, updated_at = NOW()",
    )
    .bind(artifact_id)
    .bind(repo_id)
    .bind(requested_by)
    .execute(conn)
    .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Fill through the Remote's proxy path
// ---------------------------------------------------------------------------

/// What one fill attempt achieved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fill {
    /// The Remote served the package (it is now cached or recorded).
    Served,
    /// Definitively refused: `(error code, detail)`.
    Refused(&'static str, String),
    /// Try again later.
    Retry(String),
}

/// Classify the status a format route answered a fill request with (pure).
pub fn classify_fill_status(status: StatusCode, what: &str) -> Fill {
    match status.as_u16() {
        200..=299 => Fill::Served,
        404 | 410 => Fill::Refused(
            "mcp_package_not_found",
            format!("{what} does not exist upstream"),
        ),
        401 | 403 | 451 => Fill::Refused(
            "mcp_package_refused",
            format!(
                "{what} was refused by the backing repository (HTTP {}: access, curation or \
                 age policy)",
                status.as_u16()
            ),
        ),
        400 | 422 => Fill::Refused(
            "mcp_package_not_found",
            format!("{what} is not a valid package reference for the backing repository"),
        ),
        s => Fill::Retry(format!("{what}: the backing repository answered HTTP {s}")),
    }
}

/// The request path, relative to the format's router, that downloads a
/// package (pure). PyPI needs the file name from the project's JSON first.
pub fn fill_path(p: &Pending, pypi_file: Option<&str>) -> Option<String> {
    let repo = &p.fill_repository;
    let name = mcp_packages::lookup_name(&p.registry_type, &p.identifier);
    let version = p.version.as_deref().unwrap_or_default();
    Some(match p.registry_type.as_str() {
        "npm" => format!("/{repo}/{name}/-/{}-{version}.tgz", npm_base_name(&name)),
        "cargo" => format!("/{repo}/api/v1/crates/{name}/{version}/download"),
        "nuget" => {
            let id = name.to_ascii_lowercase();
            let v = crate::formats::nuget::NugetHandler::normalized_version(version)
                .unwrap_or_else(|| version.to_ascii_lowercase());
            format!("/{repo}/v3/flatcontainer/{id}/{v}/{id}.{v}.nupkg")
        }
        "pypi" => format!("/{repo}/simple/{name}/{}", pypi_file?),
        _ => return None,
    })
}

/// The first distribution file of `version` in a PyPI JSON document
/// (`/pypi/<project>/<version>/json`), wheels first.
pub fn pypi_pick_file(json: &serde_json::Value) -> Option<String> {
    let files: Vec<&str> = json
        .get("urls")?
        .as_array()?
        .iter()
        .filter_map(|u| u.get("filename")?.as_str())
        .filter(|f| !f.contains('/') && !f.contains(".."))
        .collect();
    files
        .iter()
        .find(|f| f.ends_with(".whl"))
        .or_else(|| files.first())
        .map(|f| f.to_string())
}

/// The publisher as the principal of a fill, or `None` when the account is
/// gone or disabled.
async fn publisher(db: &PgPool, user_id: Uuid) -> Option<crate::models::user::User> {
    sqlx::query_as::<_, crate::models::user::User>(
        "SELECT id, username, email, password_hash, display_name, auth_provider, external_id, \
                is_admin, is_active, is_service_account, must_change_password, totp_secret, \
                totp_enabled, totp_backup_codes, totp_verified_at, failed_login_attempts, \
                locked_until, last_failed_login_at, password_changed_at, last_login_at, \
                created_at, updated_at \
         FROM users WHERE id = $1",
    )
    .bind(user_id)
    .fetch_optional(db)
    .await
    .ok()
    .flatten()
    .filter(|u| u.is_active)
}

/// The publisher's credential for a fill, narrowed to the recorded scope.
fn auth_of(user: &crate::models::user::User, scope: &RequestedScope) -> AuthExtension {
    scope.apply(AuthExtension {
        user_id: user.id,
        username: user.username.clone(),
        email: user.email.clone(),
        is_admin: user.is_admin,
        is_api_token: false,
        is_service_account: user.is_service_account,
        scopes: None,
        allowed_repo_ids: crate::models::access_scope::AccessScope::Admin,
        iat_ms: None,
    })
}

/// One in-process GET through a format router, as the publisher, finished
/// (head and body) by `deadline`. Returns the status and (for JSON
/// documents) the body.
async fn route_get(
    state: &SharedState,
    format: &str,
    path: &str,
    auth: &AuthExtension,
    bearer: Option<&str>,
    want_body: bool,
    deadline: tokio::time::Instant,
) -> Result<(StatusCode, Option<bytes::Bytes>), String> {
    let router = match format {
        "npm" => crate::api::handlers::npm::router(),
        "pypi" => crate::api::handlers::pypi::router(),
        "nuget" => crate::api::handlers::nuget::router(),
        "cargo" => crate::api::handlers::cargo::router(),
        "oci" => crate::api::handlers::oci_v2::router(None),
        other => return Err(format!("no fill path for {other}")),
    };
    let _ = &state.config;
    let host = crate::api::extractors::trusted_external_url()
        .and_then(|u| url::Url::parse(u).ok())
        .and_then(|u| u.host_str().map(str::to_string))
        .unwrap_or_else(|| "localhost".to_string());
    let mut req = Request::builder()
        .method("GET")
        .uri(path)
        .header(header::HOST, host)
        .header(header::USER_AGENT, "artifact-keeper-mcp-resolver");
    if format == "oci" {
        req = req.header(
            header::ACCEPT,
            "application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json, \
             application/vnd.docker.distribution.manifest.list.v2+json, \
             application/vnd.docker.distribution.manifest.v2+json",
        );
    }
    if let Some(token) = bearer {
        req = req.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    let mut req = req.body(Body::empty()).map_err(|e| e.to_string())?;
    req.extensions_mut().insert(Some(auth.clone()));
    let app = router
        .with_state(state.clone())
        .layer(axum::Extension::<Option<AuthExtension>>(Some(auth.clone())));
    exchange(app, req, want_body, deadline).await
}

/// Send `req` through `app` and read the response body, all of it by
/// `deadline` (#5395): the head alone is not enough, since a slow upstream
/// can trickle a body and hold the job and its worker slot indefinitely. A
/// miss is an `Err`, which [`fill`] records as a retryable failure.
async fn exchange(
    app: axum::Router,
    req: Request<Body>,
    want_body: bool,
    deadline: tokio::time::Instant,
) -> Result<(StatusCode, Option<bytes::Bytes>), String> {
    let run = async {
        let resp = app.oneshot(req).await.map_err(|e| e.to_string())?;
        let status = resp.status();
        let body = if want_body && status.is_success() {
            #[allow(clippy::disallowed_methods)]
            // STREAMING-EXEMPT: a package metadata document capped at FILL_JSON_MAX
            // (8 MiB), not an artifact body (#1608)
            let bytes = axum::body::to_bytes(resp.into_body(), FILL_JSON_MAX)
                .await
                .map_err(|e| e.to_string())?;
            Some(bytes)
        } else {
            // Drain frame by frame (never buffered) so a streamed body completes
            // and the cache commit runs.
            use http_body_util::BodyExt as _;
            let mut body = resp.into_body();
            while let Some(frame) = body.frame().await {
                if frame.is_err() {
                    break;
                }
            }
            None
        };
        Ok((status, body))
    };
    tokio::time::timeout_at(deadline, run).await.map_err(|_| {
        format!(
            "the backing repository did not finish the fill within its deadline ({} s)",
            FILL_DEADLINE.as_secs()
        )
    })?
}

/// Fill `p` through its Remote as `user`.
pub async fn fill(
    state: &SharedState,
    p: &Pending,
    user: &crate::models::user::User,
    scope: &RequestedScope,
) -> Fill {
    let what = match &p.version {
        Some(v) => format!("{} {}@{}", p.registry_type, p.identifier, v),
        None => format!("{} {}", p.registry_type, p.identifier),
    };
    let auth = auth_of(user, scope);
    // One deadline for every request of this fill, head and body (#5395).
    let deadline = tokio::time::Instant::now() + FILL_DEADLINE;
    // The fill runs as the publisher, who must be able to read the Remote
    // (the format routes run without the visibility middleware here).
    match mcp_packages::caller_may_map(&state.db, &auth, p.fill_repository_id).await {
        Ok(true) => {}
        Ok(false) => {
            return Fill::Refused(
                "mcp_package_refused",
                format!(
                    "the publisher cannot read repository '{}'",
                    p.fill_repository
                ),
            )
        }
        Err(e) => return Fill::Retry(e.to_string()),
    }
    let route_format = if p.registry_type == "oci" {
        "oci"
    } else {
        p.registry_type.as_str()
    };
    let result = if p.registry_type == "oci" {
        fill_oci(state, p, user, &auth, deadline).await
    } else if p.registry_type == "pypi" {
        fill_pypi(state, p, &auth, deadline).await
    } else {
        match fill_path(p, None) {
            Some(path) => route_get(state, route_format, &path, &auth, None, false, deadline)
                .await
                .map(|(s, _)| s),
            None => {
                return Fill::Refused("mcp_package_not_found", format!("{what} cannot be filled"))
            }
        }
    };
    match result {
        Ok(status) => classify_fill_status(status, &what),
        Err(e) => Fill::Retry(format!("{what}: {e}")),
    }
}

async fn fill_pypi(
    state: &SharedState,
    p: &Pending,
    auth: &AuthExtension,
    deadline: tokio::time::Instant,
) -> Result<StatusCode, String> {
    let name = mcp_packages::lookup_name("pypi", &p.identifier);
    let version = p.version.as_deref().unwrap_or_default();
    let json_path = format!("/{}/pypi/{name}/{version}/json", p.fill_repository);
    let (status, body) = route_get(state, "pypi", &json_path, auth, None, true, deadline).await?;
    if !status.is_success() {
        return Ok(status);
    }
    let doc: serde_json::Value =
        serde_json::from_slice(&body.unwrap_or_default()).map_err(|e| e.to_string())?;
    let Some(file) = pypi_pick_file(&doc) else {
        return Ok(StatusCode::NOT_FOUND);
    };
    let path = fill_path(p, Some(&file)).ok_or("no PyPI fill path")?;
    Ok(route_get(state, "pypi", &path, auth, None, false, deadline)
        .await?
        .0)
}

/// OCI: a manifest pull by the submitted tag or digest, authenticated with a
/// short-lived pull token of the publisher pinned to the Remote (the scanner
/// pull-token shape: never wider than the publisher's own access).
async fn fill_oci(
    state: &SharedState,
    p: &Pending,
    user: &crate::models::user::User,
    auth: &AuthExtension,
    deadline: tokio::time::Instant,
) -> Result<StatusCode, String> {
    let r = fmt::parse_oci_identifier(&p.identifier).map_err(|_| "invalid OCI identifier")?;
    let reference = r
        .digest
        .clone()
        .or(r.tag.clone())
        .ok_or("no tag or digest")?;
    let token = crate::services::auth_service::AuthService::new(
        state.db.clone(),
        std::sync::Arc::new(state.config.clone()),
    )
    .generate_scan_token(user, &p.fill_repository, 300)
    .map_err(|e| e.to_string())?;
    let path = format!("/{}/{}/manifests/{reference}", p.fill_repository, r.path);
    Ok(
        route_get(state, "oci", &path, auth, Some(&token), false, deadline)
            .await?
            .0,
    )
}

// ---------------------------------------------------------------------------
// The job loop
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, sqlx::FromRow)]
struct Job {
    artifact_id: Uuid,
    repository_id: Uuid,
    requested_by: Option<Uuid>,
    attempts: i32,
    claim_token: Uuid,
}

/// Backoff before attempt `attempts + 1` (30 s doubling, at most 1 h).
pub fn backoff(attempts: i32) -> chrono::Duration {
    let exp = attempts.clamp(1, 8) - 1;
    chrono::Duration::seconds((30i64 << exp).min(3600))
}

async fn claim(db: &PgPool, limit: i64) -> Result<Vec<Job>, sqlx::Error> {
    sqlx::query_as::<_, Job>(
        "WITH due AS ( \
           SELECT artifact_id FROM mcp_resolve_jobs \
           WHERE next_attempt_at <= NOW() \
             AND (claim_expires_at IS NULL OR claim_expires_at < NOW()) \
           ORDER BY next_attempt_at LIMIT $1 FOR UPDATE SKIP LOCKED) \
         UPDATE mcp_resolve_jobs j SET claim_token = gen_random_uuid(), claimed_by = $2, \
           claim_expires_at = NOW() + make_interval(secs => $3), attempts = j.attempts + 1, \
           updated_at = NOW() \
         FROM due WHERE j.artifact_id = due.artifact_id \
         RETURNING j.artifact_id, j.repository_id, j.requested_by, j.attempts, j.claim_token",
    )
    .bind(limit)
    .bind(crate::services::cluster_work::WorkerIdentity::for_process().as_str())
    .bind(CLAIM_SECS as f64)
    .fetch_all(db)
    .await
}

/// What a job's attempt concluded.
#[derive(Debug)]
enum Step {
    Resolved(Vec<PackagePin>),
    Failed {
        code: &'static str,
        detail: String,
        index: Option<usize>,
    },
    Retry(String),
    /// The version is gone or no longer resolving: drop the job.
    Gone,
}

/// Work the job of `artifact_id` now, whatever else is due (tests: a shared
/// database may hold other repositories' due jobs, which a [`run_due`] batch
/// would take first). Returns whether the job was claimed and worked.
#[cfg(test)]
pub(crate) async fn run_job(state: &SharedState, artifact_id: Uuid) -> bool {
    let job = sqlx::query_as::<_, Job>(
        "UPDATE mcp_resolve_jobs j SET claim_token = gen_random_uuid(), claimed_by = $2, \
           claim_expires_at = NOW() + make_interval(secs => $3), attempts = j.attempts + 1, \
           updated_at = NOW() \
         WHERE j.artifact_id = $1 \
           AND (j.claim_expires_at IS NULL OR j.claim_expires_at < NOW()) \
         RETURNING j.artifact_id, j.repository_id, j.requested_by, j.attempts, j.claim_token",
    )
    .bind(artifact_id)
    .bind(crate::services::cluster_work::WorkerIdentity::for_process().as_str())
    .bind(CLAIM_SECS as f64)
    .fetch_optional(&state.db)
    .await
    .expect("claim the resolve job");
    let Some(job) = job else {
        return false;
    };
    let step = attempt(state, &job).await;
    conclude(state, &job, step)
        .await
        .expect("record the resolve outcome");
    true
}

/// Run one tick: claim due jobs and work them. Returns how many were worked.
pub async fn run_due(state: &SharedState) -> usize {
    let jobs = match claim(&state.db, BATCH).await {
        Ok(j) => j,
        Err(e) => {
            tracing::warn!(error = %e, "MCP resolver: claim failed");
            return 0;
        }
    };
    let n = jobs.len();
    for job in jobs {
        let step = attempt(state, &job).await;
        if let Err(e) = conclude(state, &job, step).await {
            tracing::warn!(artifact_id = %job.artifact_id, error = %e, "MCP resolver: could not record the outcome");
        }
    }
    n
}

/// The stored resolution of a version: its metadata, server document and the
/// pending packages.
async fn load(
    db: &PgPool,
    artifact_id: Uuid,
) -> Result<Option<(serde_json::Value, Vec<Pending>)>, sqlx::Error> {
    let meta: Option<serde_json::Value> = sqlx::query_scalar(
        "SELECT m.metadata FROM artifact_metadata m JOIN artifacts a ON a.id = m.artifact_id \
         WHERE m.artifact_id = $1 AND m.format = 'mcp' AND a.is_deleted = false",
    )
    .bind(artifact_id)
    .fetch_optional(db)
    .await?;
    Ok(meta.and_then(|m| {
        if m.pointer("/resolution/state").and_then(|v| v.as_str()) != Some("resolving") {
            return None;
        }
        let pending: Vec<Pending> =
            serde_json::from_value(m.pointer("/resolution/pending")?.clone()).ok()?;
        Some((m, pending))
    }))
}

async fn attempt(state: &SharedState, job: &Job) -> Step {
    let (meta, pending) = match load(&state.db, job.artifact_id).await {
        Ok(Some(x)) => x,
        Ok(None) => return Step::Gone,
        Err(e) => return Step::Retry(e.to_string()),
    };
    let settings = match mcp_packages::load_settings(&state.db, job.repository_id).await {
        Ok(s) => s,
        Err(e) => return Step::Retry(e.detail()),
    };
    let Some(user) = publisher(&state.db, job.requested_by.unwrap_or_default()).await else {
        return Step::Failed {
            code: "mcp_package_refused",
            detail: "the publishing account no longer exists or is disabled".into(),
            index: None,
        };
    };
    // The base URL of the publish: an OCI identifier naming this instance
    // is recognised against it.
    let base = meta
        .pointer("/resolution/baseUrl")
        .and_then(|v| v.as_str())
        .unwrap_or("http://localhost")
        .to_string();
    // The fill runs with the publishing credential's scope, not the account's
    // full authority.
    let scope = RequestedScope::of_metadata(&meta);
    let mut pins = Vec::new();
    for p in &pending {
        match resolve_pending(state, &settings, p, &user, &scope, &base).await {
            Ok(pin) => pins.push(pin),
            Err(step) => return step,
        }
    }
    Step::Resolved(pins)
}

/// Resolve one pending package: look again (another pull may have filled
/// it), else fill and look once more.
async fn resolve_pending(
    state: &SharedState,
    settings: &McpSettings,
    p: &Pending,
    user: &crate::models::user::User,
    scope: &RequestedScope,
    base: &str,
) -> Result<PackagePin, Step> {
    let pkg = p.package();
    let Some(mapped) = settings.repos.get(&p.registry_type) else {
        return Err(Step::Failed {
            code: "mcp_external_registry",
            detail: format!("registryType '{}' is no longer mapped", p.registry_type),
            index: Some(p.index),
        });
    };
    // The fill target is recomputed from the current mapping and must be the
    // repository recorded at publish: a pin is never assembled from the
    // mapping of one moment and the Remote of another.
    let remote = match fill_target(&state.db, mapped).await {
        Ok(Some(remote)) if remote.id == p.fill_repository_id => remote,
        Ok(_) => {
            return Err(Step::Failed {
                code: "mcp_package_not_found",
                detail: format!(
                    "registryType '{}' no longer fills through repository '{}'; publish again",
                    p.registry_type, p.fill_repository
                ),
                index: Some(p.index),
            })
        }
        Err(McpError::Internal(m)) | Err(McpError::Misconfigured(m)) => return Err(Step::Retry(m)),
        Err(e) => return Err(Step::Retry(e.detail())),
    };
    // Fill through the repository as it is now (its key may have changed).
    let current;
    let p = if remote.key == p.fill_repository {
        p
    } else {
        current = Pending {
            fill_repository: remote.key.clone(),
            ..p.clone()
        };
        &current
    };
    let look = || async {
        if p.registry_type == "oci" {
            match mcp_packages::resolve_one(state, settings, p.index, &pkg, base).await {
                Ok(pin) => Ok(Some(pin)),
                Err(McpError::PackageNotFound { .. }) => Ok(None),
                Err(e) => Err(e),
            }
        } else {
            // No policy re-check here: a pin does not depend on the policy
            // (#5452), only the hostname check does, and that ran at publish.
            // What can change since is the Remote, so the foreign-coordinate
            // rule is checked against the fill target again.
            if !mcp_packages::remote_may_serve(&pkg, mapped, &remote, base) {
                return Err(mcp_packages::foreign_through_remote(p.index, &pkg, &remote));
            }
            let mut found = cached_pin(&state.db, mapped, &remote, p.index, &pkg).await;
            if let Ok(Some(pin)) = found.as_mut() {
                mcp_packages::note_foreign_coordinates(pin, &pkg, mapped, base);
            }
            found
        }
    };
    let to_step = |e: McpError| match e {
        McpError::Internal(m) | McpError::Misconfigured(m) => Step::Retry(m),
        other => Step::Failed {
            code: other.code(),
            detail: other.detail(),
            index: Some(p.index),
        },
    };
    if let Some(pin) = look().await.map_err(to_step)? {
        return Ok(pin);
    }
    match fill(state, p, user, scope).await {
        Fill::Served => {}
        Fill::Refused(code, detail) => {
            return Err(Step::Failed {
                code,
                detail,
                index: Some(p.index),
            })
        }
        Fill::Retry(why) => return Err(Step::Retry(why)),
    }
    match look().await.map_err(to_step)? {
        Some(pin) => Ok(pin),
        // Served but not recorded where the gate finds it (e.g. a stream
        // still committing): look again on the next attempt.
        None => Err(Step::Retry(format!(
            "{} {} was served but is not cached yet",
            p.registry_type, p.identifier
        ))),
    }
}

/// Record a step: pins written and the job removed, a failure recorded, or a
/// retry scheduled. Every write is guarded by the job's claim token.
async fn conclude(state: &SharedState, job: &Job, step: Step) -> Result<(), sqlx::Error> {
    let db = &state.db;
    let step = match step {
        Step::Retry(why) if job.attempts >= MAX_ATTEMPTS => Step::Failed {
            code: "mcp_resolve_exhausted",
            detail: format!("gave up after {} attempts: {why}", job.attempts),
            index: None,
        },
        s => s,
    };
    let mut tx = db.begin().await?;
    let owned: Option<Uuid> = sqlx::query_scalar(
        "SELECT artifact_id FROM mcp_resolve_jobs WHERE artifact_id = $1 AND claim_token = $2 \
         FOR UPDATE",
    )
    .bind(job.artifact_id)
    .bind(job.claim_token)
    .fetch_optional(&mut *tx)
    .await?;
    if owned.is_none() {
        return Ok(()); // The claim lapsed and another replica owns the job.
    }
    let now = Utc::now();
    let mut post: Option<PostCommit> = None;
    match step {
        Step::Gone => {}
        Step::Retry(why) => {
            sqlx::query(
                "UPDATE mcp_resolve_jobs SET next_attempt_at = $2, last_error = $3, \
                 claim_token = NULL, claim_expires_at = NULL, updated_at = NOW() \
                 WHERE artifact_id = $1",
            )
            .bind(job.artifact_id)
            .bind(now + backoff(job.attempts))
            .bind(&why)
            .execute(&mut *tx)
            .await?;
            patch_resolution(
                &mut tx,
                job.artifact_id,
                serde_json::json!({"attempts": job.attempts, "lastError": why}),
            )
            .await?;
            tx.commit().await?;
            return Ok(());
        }
        Step::Failed {
            code,
            detail,
            index,
        } => {
            tracing::warn!(artifact_id = %job.artifact_id, code, %detail, "MCP resolver: version failed to resolve");
            patch_resolution(
                &mut tx,
                job.artifact_id,
                serde_json::json!({
                    "state": "failed", "attempts": job.attempts, "failedAt": now,
                    "error": {"error": code, "detail": detail, "index": index},
                }),
            )
            .await?;
        }
        Step::Resolved(new_pins) => {
            let current: serde_json::Value = sqlx::query_scalar(
                "SELECT metadata->'packages' FROM artifact_metadata WHERE artifact_id = $1 \
                 FOR UPDATE",
            )
            .bind(job.artifact_id)
            .fetch_one(&mut *tx)
            .await?;
            let mut pins: Vec<PackagePin> = serde_json::from_value(current).unwrap_or_default();
            pins.extend(new_pins.iter().cloned());
            pins.sort_by_key(|p| p.index);
            let hold_rows = mcp_packages::hold_pins(&mut tx, &new_pins).await?;
            sqlx::query(
                "UPDATE artifact_metadata SET metadata = jsonb_set(metadata, '{packages}', $2) \
                 WHERE artifact_id = $1",
            )
            .bind(job.artifact_id)
            .bind(serde_json::to_value(&pins).unwrap_or_default())
            .execute(&mut *tx)
            .await?;
            patch_resolution(
                &mut tx,
                job.artifact_id,
                serde_json::json!({"state": "resolved", "attempts": job.attempts, "resolvedAt": now, "pending": []}),
            )
            .await?;
            post = Some((new_pins, hold_rows));
        }
    }
    sqlx::query("DELETE FROM mcp_resolve_jobs WHERE artifact_id = $1 AND claim_token = $2")
        .bind(job.artifact_id)
        .bind(job.claim_token)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    if let Some((pins, hold_rows)) = post {
        after_resolved(state, job, &pins, hold_rows).await;
    }
    Ok(())
}

/// Merge `patch` into `metadata.resolution`.
async fn patch_resolution(
    tx: &mut sqlx::PgConnection,
    artifact_id: Uuid,
    patch: serde_json::Value,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE artifact_metadata SET metadata = jsonb_set(metadata, '{resolution}', \
           COALESCE(metadata->'resolution', '{}'::jsonb) || $2::jsonb) \
         WHERE artifact_id = $1",
    )
    .bind(artifact_id)
    .bind(patch)
    .execute(tx)
    .await?;
    Ok(())
}

/// After a version resolved: scan the manifest rows its retention holds
/// created and audit `MCP_PACKAGE_PINNED` per new pin.
async fn after_resolved(
    state: &SharedState,
    job: &Job,
    pins: &[PackagePin],
    hold_rows: Vec<(Uuid, Uuid)>,
) {
    for (backing, row) in hold_rows {
        crate::services::scanner_service::trigger_scan_on_upload(
            &state.db,
            state.scanner_service.clone(),
            backing,
            row,
        )
        .await;
    }
    let ident: Option<(String, String, String)> = sqlx::query_as(
        "SELECT a.name, a.version, r.key FROM artifacts a JOIN repositories r ON r.id = a.repository_id \
         WHERE a.id = $1",
    )
    .bind(job.artifact_id)
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten();
    let Some((name, version, repo_key)) = ident else {
        return;
    };
    tracing::info!(
        "MCP resolver: {name}@{version} in {repo_key} resolved ({} packages pinned)",
        pins.len()
    );
    for pin in pins {
        crate::services::mcp_write::audit(
            &state.db,
            crate::services::audit_service::AuditAction::McpPackagePinned,
            match job.requested_by {
                Some(u) => crate::services::mcp_write::Actor::User(u),
                None => crate::services::mcp_write::Actor::System("mcp-resolver"),
            },
            &repo_key,
            Some(job.artifact_id),
            &name,
            &version,
            serde_json::json!({
                "index": pin.index,
                "registry_type": pin.registry_type,
                "submitted": pin.submitted,
                "resolved_repository": pin.resolved.repository,
                "digest": pin.resolved.digest,
                "sha256": pin.resolved.sha256,
                "warnings": pin.resolved.warnings,
                "async": true,
            }),
        );
    }
}

/// Spawn the resolver loop (every replica ticks; jobs are row-claimed).
/// `MCP_RESOLVER_INTERVAL_SECS` (default 15) sets the tick.
pub fn spawn(state: SharedState, shutdown: CancellationToken) {
    let secs = std::env::var("MCP_RESOLVER_INTERVAL_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(15);
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(secs));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => return,
                _ = ticker.tick() => {}
            }
            run_due(&state).await;
        }
    });
}

#[cfg(ak_test_shard = "services-1")]
#[cfg(test)]
mod tests {
    use super::*;

    /// #5452: a pending package keeps its submitted `registryBaseUrl` through
    /// the job record, so the filled pin can record the coordinates it
    /// replaced; a record written before the field existed still loads.
    #[test]
    fn pending_keeps_the_submitted_registry_base_url() {
        let p = Pending {
            index: 1,
            registry_type: "npm".into(),
            identifier: "@acme/echo".into(),
            version: Some("2.0.0".into()),
            fill_repository: "npm-remote".into(),
            fill_repository_id: Uuid::nil(),
            fill_format: "npm".into(),
            registry_base_url: Some("https://registry.npmjs.org".into()),
        };
        let v = serde_json::to_value(&p).unwrap();
        assert_eq!(v["registryBaseUrl"], "https://registry.npmjs.org");
        assert_eq!(serde_json::from_value::<Pending>(v).unwrap(), p);
        assert_eq!(
            p.package().registry_base_url.as_deref(),
            Some("https://registry.npmjs.org")
        );
        let legacy = serde_json::json!({
            "index": 0, "registryType": "npm", "identifier": "@acme/echo", "version": "1.0.0",
            "fillRepository": "npm-remote", "fillRepositoryId": Uuid::nil(), "fillFormat": "npm",
        });
        let old: Pending = serde_json::from_value(legacy).unwrap();
        assert_eq!(old.registry_base_url, None);
        assert!(serde_json::to_value(&old)
            .unwrap()
            .get("registryBaseUrl")
            .is_none());
        assert_eq!(old.package().registry_base_url, None);
    }

    /// Review finding 12: the asynchronous fill runs with the publishing
    /// token's scope (repository allowlist, scopes), recorded on the
    /// resolution; a job without a readable record gets nothing.
    #[test]
    fn fills_run_with_the_publishing_scope() {
        let (allowed, other) = (Uuid::new_v4(), Uuid::new_v4());
        let mut token = crate::api::handlers::test_db_helpers::make_auth(Uuid::new_v4(), "ci");
        token.is_api_token = true;
        token.scopes = Some(vec!["write:artifacts".into()]);
        token.allowed_repo_ids =
            crate::models::access_scope::AccessScope::Restricted(vec![allowed]);
        let scope = RequestedScope::of(&token);
        let meta = serde_json::json!({"resolution": {"requestedScope": scope}});
        let recorded = RequestedScope::of_metadata(&meta);
        assert_eq!(recorded, scope);
        let account = crate::api::handlers::test_db_helpers::make_auth(token.user_id, "ci");
        assert!(
            account.can_access_repo(other),
            "the account alone is unrestricted"
        );
        let fill = recorded.apply(account.clone());
        assert!(fill.can_access_repo(allowed));
        assert!(!fill.can_access_repo(other));
        assert!(!fill.has_scope("admin"));
        assert!(fill.is_api_token);
        let none = RequestedScope::of_metadata(&serde_json::json!({"resolution": {}}));
        let blind = none.apply(account);
        assert!(!blind.can_access_repo(allowed));
        assert!(!blind.has_scope("read:artifacts"));
    }

    /// A router whose `/stall` answers `200` at once with one chunk, then a
    /// body that never ends: a slow upstream trickling a fill.
    fn stalling_router() -> axum::Router {
        axum::Router::new().route(
            "/stall",
            axum::routing::get(|| async {
                let chunk = futures::stream::once(async {
                    Ok::<_, std::io::Error>(bytes::Bytes::from_static(b"{"))
                });
                Body::from_stream(futures::StreamExt::chain(chunk, futures::stream::pending()))
            }),
        )
    }

    /// #5395: the fill deadline covers the body, not only the head. A body
    /// that stalls after a prompt `200` ends the exchange with an error (a
    /// retryable fill failure) at the deadline, whether the body is read as
    /// a JSON document or drained.
    #[tokio::test]
    async fn a_body_stalled_after_the_head_ends_at_the_fill_deadline() {
        for want_body in [true, false] {
            let req = Request::builder()
                .uri("/stall")
                .body(Body::empty())
                .unwrap();
            let deadline = tokio::time::Instant::now() + Duration::from_millis(200);
            let out = tokio::time::timeout(
                Duration::from_secs(10),
                exchange(stalling_router(), req, want_body, deadline),
            )
            .await
            .unwrap_or_else(|_| {
                panic!("want_body={want_body}: the stalled body outlived the fill deadline")
            });
            let err = out.expect_err("a stalled body is not a served fill");
            assert!(err.contains("deadline"), "{err}");
        }
    }
}
