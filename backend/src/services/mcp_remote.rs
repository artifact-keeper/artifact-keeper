//! Remote MCP registries (#5253): the upstream sync.
//!
//! A Remote `mcp` repository is an allowlist that happens to be populated
//! from an upstream registry, not a mirror of it. Its `upstream_url` is a
//! registry origin (the official registry, another Artifact Keeper
//! `/mcp/<key>`, any server of the v0.1 API). The sync pages
//! `GET {upstream}/v0.1/servers?updated_since=..&limit=100&cursor=..` through
//! [`proxy_fetch_capped_with_format`](crate::api::handlers::proxy_helpers::proxy_fetch_capped_with_format)
//! (8 MiB per page, SSRF-guarded, the Remote's upstream credentials) and:
//!
//! * records every upstream server name as one `curation_packages` row
//!   (`version = '*'`) whose `metadata` caches the catalog summary the UI
//!   browses (title, description, versions, latest, upstream time, flags),
//!   so browsing never calls upstream;
//! * flags lookalike names at ingest (typosquat, routed to `review`) and
//!   approves names matching `mcp_auto_approve_namespaces`;
//! * ingests the versions of every eligible name (approved names, pending
//!   names under `allow_with_gates`, approved `name@version` pins, and in
//!   `mirror` mode every name) as `artifacts` rows of the Remote, the same
//!   path and metadata shape a hosted publish writes, with every package
//!   pinned now through the Remote's own `mcp_package_repos`;
//! * never overwrites an ingested `name@version`: changed upstream bytes
//!   raise `MCP_SERVER_CONTENT_DRIFT`, revoke that version's approval and
//!   re-queue it (`curation_packages` row of the version in `review`);
//! * mirrors upstream status (`active`/`deprecated`/`deleted`) onto the
//!   stored registry state, which is not content;
//! * records the first sighting of each version for the age gate
//!   (`first_seen`), and audits `MCP_MIRROR_SYNCED` with the run's counts.
//!
//! Serving is decided elsewhere (`services::mcp_curation`, at read time):
//! ingesting a version never makes it visible.

use std::collections::{BTreeMap, HashMap};

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde::Serialize;
use sqlx::PgPool;
use uuid::Uuid;

use crate::api::handlers::proxy_helpers::{self, RepoInfo};
use crate::api::SharedState;
use crate::formats::mcp::{
    self as fmt, McpError, PackagePin, PackagePolicy, RegistryState, ServerJson, ServerStatus,
};
use crate::models::repository::RepositoryFormat;
use crate::services::audit_service::{audit_fire_and_forget, AuditAction, AuditEntry, ResourceType};
use crate::services::mcp_curation::{
    self as cur, CurationRow, Posture, ServePolicy, NAME_ROW_VERSION, STATUS_APPROVED,
    STATUS_PENDING, STATUS_REVIEW,
};
use crate::services::mcp_packages::{self, BackingRepo, McpSettings};
use crate::services::mcp_settings::{self, McpRepoSettings};

/// Advisory-lock class of the per-repository sync lock (`ClusterLock`).
pub const SYNC_LOCK_CLASS: i32 = 0x5253;
/// Upstream page size (the API maximum).
pub const PAGE_LIMIT: usize = 100;
/// Pages one run reads before it stops and records where to resume.
pub const MAX_PAGES_PER_RUN: usize = 200;
/// Versions one catalog summary lists.
pub const MAX_SUMMARY_VERSIONS: usize = 200;
/// Names a run ingests from their per-server version list (newly approved).
pub const MAX_BACKFILL_NAMES: i64 = 50;
/// Ingested versions a run retries package resolution for.
pub const MAX_RERESOLVE: i64 = 100;
/// The watermark never runs closer to the run's start than this, so an
/// upstream entry updated while a pass was paging past it is read again.
pub const WATERMARK_OVERLAP_SECS: i64 = 600;
/// Default interval between two scheduled syncs of one repository.
pub const DEFAULT_SYNC_INTERVAL_SECS: i64 = 3600;
/// How often the scheduler looks for repositories that are due.
pub const SCHEDULER_TICK_SECS: u64 = 300;
const SCHEDULER_LEASE: &str = "mcp_remote_sync";
const SCHEDULER_LEASE_TTL_SECS: f64 = 330.0;

// ---------------------------------------------------------------------------
// Upstream envelope (pure)
// ---------------------------------------------------------------------------

/// One upstream server version, with the upstream registry's own state.
#[derive(Debug, Clone, PartialEq)]
pub struct UpstreamEntry {
    pub name: String,
    pub version: String,
    /// The upstream `server` document as received.
    pub server: serde_json::Value,
    pub status: ServerStatus,
    pub status_message: Option<String>,
    pub status_changed_at: Option<DateTime<Utc>>,
    pub published_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
    pub is_latest: bool,
}

/// One upstream listing page.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct UpstreamPage {
    pub entries: Vec<UpstreamEntry>,
    pub next_cursor: Option<String>,
    /// Entries without a usable `server.name`/`server.version`.
    pub skipped: usize,
}

fn timestamp(v: Option<&serde_json::Value>) -> Option<DateTime<Utc>> {
    v.and_then(|v| v.as_str())
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .map(|t| t.with_timezone(&Utc))
}

/// Parse one `{server, _meta}` entry. The official registry state is read
/// from the entry's `_meta` (and, for older servers, the server's own).
pub fn parse_entry(entry: &serde_json::Value) -> Option<UpstreamEntry> {
    let server = entry.get("server")?;
    let name = server.get("name")?.as_str()?.to_string();
    let version = server.get("version")?.as_str()?.to_string();
    let official = entry
        .pointer("/_meta")
        .and_then(|m| m.get(fmt::OFFICIAL_META_KEY))
        .or_else(|| server.get("_meta").and_then(|m| m.get(fmt::OFFICIAL_META_KEY)));
    let field = |k: &str| official.and_then(|o| o.get(k));
    let status = field("status")
        .and_then(|v| v.as_str())
        .and_then(ServerStatus::parse)
        .unwrap_or(ServerStatus::Active);
    Some(UpstreamEntry {
        name,
        version,
        server: server.clone(),
        status,
        status_message: field("statusMessage")
            .and_then(|v| v.as_str())
            .map(str::to_string),
        status_changed_at: timestamp(field("statusChangedAt")),
        published_at: timestamp(field("publishedAt")),
        updated_at: timestamp(field("updatedAt")),
        is_latest: field("isLatest").and_then(|v| v.as_bool()).unwrap_or(false),
    })
}

/// Parse an upstream list envelope (`{servers: [...], metadata: {nextCursor}}`).
pub fn parse_page(bytes: &[u8]) -> Result<UpstreamPage, String> {
    let doc: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|e| format!("upstream sent invalid JSON: {e}"))?;
    let servers = doc
        .get("servers")
        .and_then(|s| s.as_array())
        .ok_or_else(|| "upstream listing has no `servers` array".to_string())?;
    let mut page = UpstreamPage {
        next_cursor: doc
            .pointer("/metadata/nextCursor")
            .and_then(|c| c.as_str())
            .filter(|c| !c.is_empty())
            .map(str::to_string),
        ..Default::default()
    };
    for entry in servers {
        match parse_entry(entry) {
            Some(e) => page.entries.push(e),
            None => page.skipped += 1,
        }
    }
    Ok(page)
}

/// The upstream listing path of one page.
pub fn listing_path(since: Option<DateTime<Utc>>, cursor: Option<&str>) -> String {
    let mut path = format!("v0.1/servers?limit={PAGE_LIMIT}");
    if let Some(since) = since {
        path.push_str("&updated_since=");
        path.push_str(&urlencoding::encode(
            &since.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        ));
    }
    if let Some(c) = cursor {
        path.push_str("&cursor=");
        path.push_str(&urlencoding::encode(c));
    }
    path
}

/// The upstream path of one server's version list.
pub fn versions_path(name: &str) -> String {
    format!("v0.1/servers/{}/versions", urlencoding::encode(name))
}

/// The upstream path of one server version.
pub fn version_path(name: &str, version: &str) -> String {
    format!(
        "v0.1/servers/{}/versions/{}",
        urlencoding::encode(name),
        urlencoding::encode(version)
    )
}

/// The next `updated_since` watermark: the newest upstream `updatedAt` a
/// completed pass saw, but never closer than [`WATERMARK_OVERLAP_SECS`] to
/// the run's start, and never moving backwards.
pub fn next_watermark(
    old: Option<DateTime<Utc>>,
    max_seen: Option<DateTime<Utc>>,
    started_at: DateTime<Utc>,
) -> Option<DateTime<Utc>> {
    let candidate =
        max_seen.map(|m| m.min(started_at - ChronoDuration::seconds(WATERMARK_OVERLAP_SECS)));
    match (old, candidate) {
        (Some(o), Some(c)) => Some(o.max(c)),
        (o, c) => o.or(c),
    }
}

// ---------------------------------------------------------------------------
// Catalog summary, typosquat, auto-approve (pure)
// ---------------------------------------------------------------------------

/// The catalog-summary members of a name row's `metadata`, from what the
/// row already holds (`existing`) and this page's entries of the name. Other
/// members (`flags`, `approvalRequests`, `needsIngest`) are left alone: the
/// caller merges this into the stored document.
pub fn merge_summary(existing: &serde_json::Value, entries: &[&UpstreamEntry]) -> serde_json::Value {
    let mut versions: Vec<String> = existing
        .get("versions")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    for e in entries {
        if !versions.contains(&e.version) {
            versions.push(e.version.clone());
        }
    }
    versions.sort_by(|a, b| fmt::compare_versions_for_latest(b, a));
    versions.truncate(MAX_SUMMARY_VERSIONS);
    let newest = entries
        .iter()
        .filter(|e| e.status != ServerStatus::Deleted)
        .max_by(|a, b| {
            a.is_latest
                .cmp(&b.is_latest)
                .then_with(|| fmt::compare_versions_for_latest(&a.version, &b.version))
        });
    let mut out = serde_json::json!({ "kind": "mcp_server", "versions": versions });
    let keep = |k: &str| existing.get(k).cloned().unwrap_or(serde_json::Value::Null);
    let replace_latest = newest.is_some_and(|n| {
        existing
            .get("latestVersion")
            .and_then(|v| v.as_str())
            .is_none_or(|old| fmt::compare_versions_for_latest(&n.version, old).is_ge() || n.is_latest)
    });
    match newest.filter(|_| replace_latest) {
        Some(n) => {
            let text = |k: &str| n.server.get(k).cloned().unwrap_or(serde_json::Value::Null);
            out["latestVersion"] = n.version.clone().into();
            out["title"] = text("title");
            out["description"] = text("description");
            out["upstreamStatus"] = n.status.as_str().into();
        }
        None => {
            for k in ["latestVersion", "title", "description", "upstreamStatus"] {
                out[k] = keep(k);
            }
        }
    }
    let seen = entries.iter().filter_map(|e| e.updated_at).max();
    let old = timestamp(existing.get("upstreamUpdatedAt"));
    out["upstreamUpdatedAt"] = match old.max(seen) {
        Some(t) => t.to_rfc3339().into(),
        None => serde_json::Value::Null,
    };
    out
}

/// The comparison key of a lookalike check: lower-cased, the classic
/// visual swaps folded (`rn`->`m`, `vv`->`w`, `0`->`o`, `1`/`i`->`l`,
/// `5`->`s`), separators dropped.
pub fn lookalike_key(s: &str) -> String {
    let lower = s.to_ascii_lowercase().replace("rn", "m").replace("vv", "w");
    lower
        .chars()
        .filter(|c| !matches!(c, '-' | '_' | '.'))
        .map(|c| match c {
            '0' => 'o',
            '1' | 'i' => 'l',
            '5' => 's',
            c => c,
        })
        .collect()
}

fn close(a: &str, b: &str) -> bool {
    a == b
        || lookalike_key(a) == lookalike_key(b)
        || crate::services::curation::typosquat::damerau_levenshtein(
            &a.to_ascii_lowercase(),
            &b.to_ascii_lowercase(),
        ) <= 1
}

/// The protected name `name` looks like, if any: a different namespace that
/// is a lookalike of a protected one (one edit away, or equal after
/// [`lookalike_key`]) with the same or a lookalike server slug. Siblings in
/// one namespace never match each other (the namespace is the identity).
pub fn lookalike_of(name: &str, protected: &[String]) -> Option<String> {
    let (ns, slug) = name.split_once('/')?;
    protected.iter().find_map(|p| {
        let (pns, pslug) = p.split_once('/')?;
        (ns != pns && close(ns, pns) && close(slug, pslug)).then(|| p.clone())
    })
}

/// Whether `name` is approved on sync by `mcp_auto_approve_namespaces`: a
/// glob may name the namespace (`com.acme`, `io.github.acme-*`) or the full
/// name (`io.github.acme/*`).
pub fn auto_approved(globs: &[String], name: &str) -> bool {
    mcp_settings::any_glob_matches(globs, fmt::namespace_of(name))
        || mcp_settings::any_glob_matches(globs, name)
}

/// The status and reason a newly seen name starts with. A lookalike flag
/// overrides auto-approval (flags route to review).
pub fn initial_status(lookalike: Option<&str>, auto: bool) -> (&'static str, String) {
    match lookalike {
        Some(target) => (
            STATUS_REVIEW,
            format!("lookalike of {target}; review before approving"),
        ),
        None if auto => (STATUS_APPROVED, "auto-approved namespace".to_string()),
        None => (STATUS_PENDING, "awaiting approval".to_string()),
    }
}

/// Whether every version of a name is ingested: `mirror` mode ingests all
/// names that are not denied or blocked; `allowlist` ingests the names that
/// may serve (approved, or pending under `allow_with_gates`).
pub fn name_ingestible(mirror: bool, posture: Posture, denied: bool, status: &str) -> bool {
    if denied || status == cur::STATUS_BLOCKED {
        return false;
    }
    mirror
        || status == STATUS_APPROVED
        || (status == STATUS_PENDING && posture == Posture::AllowWithGates)
}

// ---------------------------------------------------------------------------
// Ingest document (pure)
// ---------------------------------------------------------------------------

/// An upstream document accepted for ingest.
#[derive(Debug, Clone)]
pub struct Admitted {
    pub server: ServerJson,
    pub bytes: Vec<u8>,
    pub sha256: String,
}

/// Parse, validate and reduce an upstream server document the way a hosted
/// publish is, except that OCI `latest`/tagless identifiers are admitted (they
/// are pinned or hidden at sync) and reserved namespaces are not refused
/// (they are the upstream registry's own).
pub fn admit_upstream(entry: &UpstreamEntry) -> Result<Admitted, McpError> {
    let raw = serde_json::to_vec(&entry.server).map_err(|e| McpError::Internal(e.to_string()))?;
    let mut server = fmt::parse_server_json(&raw)?;
    fmt::validate_server_json_opts(&server, true)?;
    if server.name != entry.name || server.version != entry.version {
        return Err(McpError::invalid("", "entry name/version mismatch"));
    }
    fmt::reduce_publisher_meta(&mut server)?;
    let bytes = fmt::canonical_bytes(&server);
    let sha256 = fmt::sha256_hex(&bytes);
    Ok(Admitted {
        server,
        bytes,
        sha256,
    })
}

/// The stored registry state of an upstream entry.
pub fn registry_of(entry: &UpstreamEntry, now: DateTime<Utc>) -> RegistryState {
    let updated = entry.updated_at.or(entry.published_at).unwrap_or(now);
    RegistryState {
        status: entry.status,
        status_message: entry.status_message.clone(),
        status_changed_at: entry.status_changed_at.unwrap_or(updated),
        published_at: entry.published_at.unwrap_or(updated),
        updated_at: updated,
        is_latest: false,
    }
}

/// Whether the stored registry state differs from upstream's (status mirror).
pub fn registry_changed(stored: &RegistryState, upstream: &RegistryState) -> bool {
    stored.status != upstream.status
        || stored.status_message != upstream.status_message
        || stored.updated_at != upstream.updated_at
}

/// A package to resolve: an upstream `registryBaseUrl` that names the host of
/// the backing Remote's own upstream is the same registry the Remote proxies,
/// so it is dropped for the lookup (the served form points at the backing
/// repository anyway).
pub fn for_resolution(pkg: &fmt::Package, repo: Option<&BackingRepo>) -> fmt::Package {
    let mut p = pkg.clone();
    if let (Some(given), Some(repo)) = (p.registry_base_url.as_deref(), repo) {
        let upstream = repo.upstream_url.as_deref().map(fmt::host_of);
        if repo.repo_type == "remote" && upstream.as_deref() == Some(fmt::host_of(given).as_str())
        {
            p.registry_base_url = None;
        }
    }
    p
}

/// One `packages[]` entry that could not be pinned at sync. The version is
/// stored but `unresolvable` (hidden) until a later sync pins it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
pub struct Unresolved {
    pub index: usize,
    pub error: String,
    pub detail: String,
}

// ---------------------------------------------------------------------------
// Run context
// ---------------------------------------------------------------------------

/// Counts of one sync run (`last_summary`, the `MCP_MIRROR_SYNCED` details,
/// and the manual trigger's answer).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncSummary {
    pub pages: usize,
    pub entries: usize,
    pub names_new: usize,
    pub auto_approved: usize,
    pub flagged: usize,
    pub ingested: usize,
    pub unchanged: usize,
    pub status_changed: usize,
    pub drifted: usize,
    pub invalid: usize,
    pub unresolved: usize,
    pub re_resolved: usize,
    pub backfilled_names: usize,
    /// The pass reached the last upstream page.
    pub complete: bool,
    pub errors: Vec<String>,
}

/// Why a sync did not run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncError {
    /// Another replica (or a manual trigger) is syncing this repository.
    Busy,
    /// Not a Remote MCP repository, or no upstream URL.
    NotRemote,
    /// This instance has no proxy service (no outbound fetch path).
    NoProxy,
    /// The first upstream page could not be read.
    Upstream(String),
    Database(String),
}

impl std::fmt::Display for SyncError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SyncError::Busy => write!(f, "a sync of this repository is already running"),
            SyncError::NotRemote => write!(f, "not a Remote MCP repository with an upstream"),
            SyncError::NoProxy => write!(f, "outbound fetches are not available"),
            SyncError::Upstream(e) => write!(f, "upstream: {e}"),
            SyncError::Database(e) => write!(f, "database: {e}"),
        }
    }
}

fn db_err(e: impl std::fmt::Display) -> String {
    format!("database: {e}")
}

/// Everything one run (or one approval-triggered ingest) reads once.
pub struct RunCtx<'a> {
    pub state: &'a SharedState,
    pub repo: &'a RepoInfo,
    pub upstream: String,
    pub settings: McpRepoSettings,
    pub policy: ServePolicy,
    /// `Err` when the Remote's package settings are inconsistent: every
    /// package of an ingested version is then unresolved.
    pub packages: Result<McpSettings, String>,
    pub protected: Vec<String>,
}

impl<'a> RunCtx<'a> {
    pub async fn load(state: &'a SharedState, repo: &'a RepoInfo) -> Result<Self, SyncError> {
        if repo.repo_type != "remote" || repo.format != "mcp" {
            return Err(SyncError::NotRemote);
        }
        let upstream = repo
            .upstream_url
            .clone()
            .filter(|u| !u.trim().is_empty())
            .ok_or(SyncError::NotRemote)?;
        let settings = mcp_settings::load(&state.db, repo.id, "remote")
            .await
            .map_err(|e| SyncError::Database(e.to_string()))?;
        let policy = cur::load_serve_policy(&state.db, repo.id)
            .await
            .map_err(|()| SyncError::Database("serve policy".into()))?;
        let packages = mcp_packages::load_settings(&state.db, repo.id)
            .await
            .map_err(|e| e.detail());
        let protected = protected_names(&state.db, repo.id)
            .await
            .map_err(SyncError::Database)?;
        Ok(Self {
            state,
            repo,
            upstream,
            settings,
            policy,
            packages,
            protected,
        })
    }

    fn mirror(&self) -> bool {
        self.settings.mcp_remote_mode.as_deref() == Some("mirror")
    }

    fn denied(&self, name: &str) -> bool {
        cur::is_denied(&self.policy.deny, name)
    }

    fn floating_policy_hides(&self) -> bool {
        self.settings.mcp_oci_floating_tag_policy.as_deref() == Some("hide")
    }

    /// Fetch one upstream document.
    async fn fetch(&self, path: &str) -> Result<Vec<u8>, String> {
        let proxy = self
            .state
            .proxy_service
            .as_ref()
            .ok_or_else(|| SyncError::NoProxy.to_string())?;
        match proxy_helpers::proxy_fetch_capped_with_format(
            proxy,
            self.repo.id,
            &self.repo.key,
            &self.upstream,
            path,
            proxy_helpers::DEFAULT_METADATA_MAX_BYTES,
            RepositoryFormat::Mcp,
        )
        .await
        {
            Ok((bytes, _)) => Ok(bytes.to_vec()),
            Err(resp) => Err(format!("GET {path}: upstream answered {}", resp.status())),
        }
    }
}

/// Names a lookalike is compared with: approved names and names with
/// ingested versions in this repository.
async fn protected_names(db: &PgPool, repo_id: Uuid) -> Result<Vec<String>, String> {
    sqlx::query_scalar(
        "SELECT package_name FROM curation_packages \
         WHERE staging_repo_id = $1 AND format = 'mcp' AND version = '*' AND status = 'approved' \
         UNION SELECT name FROM artifacts WHERE repository_id = $1 AND is_deleted = false",
    )
    .bind(repo_id)
    .fetch_all(db)
    .await
    .map_err(db_err)
}

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

/// One MCP curation audit row (`MCP_SERVER_*`, `MCP_MIRROR_SYNCED`).
pub fn audit(
    db: &PgPool,
    action: AuditAction,
    repo: &RepoInfo,
    server: Option<&str>,
    version: Option<&str>,
    actor: Option<Uuid>,
    details: serde_json::Value,
) {
    let mut d = serde_json::json!({
        "repository": repo.key,
        "repository_id": repo.id,
        "server": server,
        "version": version,
    });
    if let (Some(o), serde_json::Value::Object(more)) = (d.as_object_mut(), details) {
        o.extend(more);
    }
    let mut entry = AuditEntry::new(action, ResourceType::Repository)
        .resource(repo.id)
        .resource_name(match (server, version) {
            (Some(s), Some(v)) => format!("{s}@{v}"),
            (Some(s), None) => s.to_string(),
            _ => repo.key.clone(),
        })
        .details(d);
    if let Some(u) = actor {
        entry = entry.user(u);
    }
    tokio::spawn(audit_fire_and_forget(db.clone(), entry));
}

// ---------------------------------------------------------------------------
// Curation rows
// ---------------------------------------------------------------------------

/// One stored MCP curation row with its metadata.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct StoredRow {
    pub id: Uuid,
    pub package_name: String,
    pub version: String,
    pub status: String,
    pub metadata: serde_json::Value,
}

impl StoredRow {
    fn view(&self) -> CurationRow {
        CurationRow {
            id: self.id,
            version: self.version.clone(),
            status: self.status.clone(),
            drift: self.metadata.get(cur::DRIFT_KEY).is_some(),
        }
    }
}

/// Every MCP curation row of `names` in `repo_id`.
pub async fn rows_of(
    db: &PgPool,
    repo_id: Uuid,
    names: &[String],
) -> Result<HashMap<String, Vec<StoredRow>>, String> {
    let rows: Vec<StoredRow> = sqlx::query_as(
        "SELECT id, package_name, version, status, metadata FROM curation_packages \
         WHERE staging_repo_id = $1 AND format = 'mcp' AND package_name = ANY($2)",
    )
    .bind(repo_id)
    .bind(names)
    .fetch_all(db)
    .await
    .map_err(db_err)?;
    let mut out: HashMap<String, Vec<StoredRow>> = HashMap::new();
    for r in rows {
        out.entry(r.package_name.clone()).or_default().push(r);
    }
    Ok(out)
}

/// Insert or update one MCP curation row. `metadata` is merged into the
/// stored document (top-level members replaced); the status is written only
/// when the row is created or `set_status` is given. Returns the row.
#[allow(clippy::too_many_arguments)]
pub async fn upsert_row(
    db: &PgPool,
    repo_id: Uuid,
    name: &str,
    version: &str,
    status: &str,
    set_status: bool,
    reason: &str,
    metadata: &serde_json::Value,
    checksum: Option<&str>,
) -> Result<StoredRow, String> {
    let upstream_path = if version == NAME_ROW_VERSION {
        versions_path(name)
    } else {
        version_path(name, version)
    };
    sqlx::query_as(
        "INSERT INTO curation_packages \
           (staging_repo_id, remote_repo_id, format, package_name, version, upstream_path, \
            status, evaluation_reason, metadata, checksum_sha256, upstream_updated_at, evaluated_at) \
         VALUES ($1, $1, 'mcp', $2, $3, $4, $5, $6, $7, $8, now(), now()) \
         ON CONFLICT (staging_repo_id, format, package_name, version, \
                      COALESCE(release, ''), COALESCE(architecture, '')) \
         DO UPDATE SET metadata = curation_packages.metadata || EXCLUDED.metadata, \
             checksum_sha256 = COALESCE(EXCLUDED.checksum_sha256, curation_packages.checksum_sha256), \
             upstream_updated_at = now(), \
             status = CASE WHEN $9 THEN EXCLUDED.status ELSE curation_packages.status END, \
             evaluation_reason = CASE WHEN $9 THEN EXCLUDED.evaluation_reason \
                                      ELSE curation_packages.evaluation_reason END, \
             evaluated_by = CASE WHEN $9 THEN NULL ELSE curation_packages.evaluated_by END, \
             evaluated_at = CASE WHEN $9 THEN now() ELSE curation_packages.evaluated_at END \
         RETURNING id, package_name, version, status, metadata",
    )
    .bind(repo_id)
    .bind(name)
    .bind(version)
    .bind(upstream_path)
    .bind(status)
    .bind(reason)
    .bind(metadata)
    .bind(checksum)
    .bind(set_status)
    .fetch_one(db)
    .await
    .map_err(db_err)
}

/// Clear `metadata.needsIngest` on a row once its versions are in.
async fn clear_needs_ingest(db: &PgPool, id: Uuid) -> Result<(), String> {
    sqlx::query("UPDATE curation_packages SET metadata = metadata - 'needsIngest' WHERE id = $1")
        .bind(id)
        .execute(db)
        .await
        .map_err(db_err)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Ingest
// ---------------------------------------------------------------------------

/// What happened to one upstream entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngestOutcome {
    Ingested { unresolved: bool },
    Unchanged,
    StatusChanged,
    Drifted,
    Invalid,
    /// A version deleted through the artifact API: write-once, not reused.
    Tombstoned,
}

impl SyncSummary {
    fn count(&mut self, outcome: IngestOutcome) {
        match outcome {
            IngestOutcome::Ingested { unresolved } => {
                self.ingested += 1;
                if unresolved {
                    self.unresolved += 1;
                }
            }
            IngestOutcome::Unchanged | IngestOutcome::Tombstoned => self.unchanged += 1,
            IngestOutcome::StatusChanged => self.status_changed += 1,
            IngestOutcome::Drifted => self.drifted += 1,
            IngestOutcome::Invalid => self.invalid += 1,
        }
    }
}

type ExistingRow = (Uuid, String, bool, Option<serde_json::Value>);

async fn existing_version(
    db: &PgPool,
    repo_id: Uuid,
    path: &str,
) -> Result<Option<ExistingRow>, String> {
    sqlx::query_as(
        "SELECT a.id, a.checksum_sha256, a.is_deleted, m.metadata->'registry' FROM artifacts a \
         LEFT JOIN artifact_metadata m ON m.artifact_id = a.id \
         WHERE a.repository_id = $1 AND a.path = $2 ORDER BY a.is_deleted LIMIT 1",
    )
    .bind(repo_id)
    .bind(path)
    .fetch_optional(db)
    .await
    .map_err(db_err)
}

/// Pin every package of `server` now, under the Remote's own package
/// settings. A package that cannot be pinned is reported, not refused.
async fn pin_packages(
    run: &RunCtx<'_>,
    server: &ServerJson,
    only: Option<&[usize]>,
) -> (Vec<PackagePin>, Vec<Unresolved>) {
    let mut pins = Vec::new();
    let mut unresolved = Vec::new();
    let settings = match &run.packages {
        Ok(s) if s.policy == PackagePolicy::Open => return (pins, unresolved),
        Ok(s) => s,
        Err(detail) => {
            let all = server.packages.iter().enumerate().map(|(index, _)| Unresolved {
                index,
                error: "mcp_repository_misconfigured".into(),
                detail: detail.clone(),
            });
            return (pins, all.collect());
        }
    };
    for (index, pkg) in server.packages.iter().enumerate() {
        if only.is_some_and(|o| !o.contains(&index)) {
            continue;
        }
        if pkg.registry_type == "oci"
            && run.floating_policy_hides()
            && matches!(fmt::parse_oci_identifier(&pkg.identifier), Err(fmt::OciRefError::Floating))
        {
            unresolved.push(Unresolved {
                index,
                error: McpError::OciFloatingTag { index }.code().into(),
                detail: "the repository hides upstream `latest`/tagless images".into(),
            });
            continue;
        }
        let candidate = for_resolution(pkg, settings.repos.get(&pkg.registry_type));
        match mcp_packages::resolve_package(run.state, settings, index, &candidate, "", true).await
        {
            Ok(mut pin) => {
                pin.submitted.identifier = pkg.identifier.clone();
                pins.push(pin);
            }
            Err(e) => unresolved.push(Unresolved {
                index,
                error: e.code().into(),
                detail: e.detail(),
            }),
        }
    }
    (pins, unresolved)
}

/// The metadata document of an ingested version.
pub fn ingest_metadata(
    admitted: &Admitted,
    registry: &RegistryState,
    policy: PackagePolicy,
    pins: &[PackagePin],
    unresolved: &[Unresolved],
    origin: &str,
    entry: &UpstreamEntry,
) -> serde_json::Value {
    let mut doc = fmt::metadata_doc(&admitted.server, registry, policy, pins);
    doc["upstream"] = serde_json::json!({
        "origin": origin,
        "sha256": admitted.sha256,
        "publishedAt": entry.published_at,
        "updatedAt": entry.updated_at,
    });
    doc["ingest"] = serde_json::json!({
        "source": "upstream",
        "ingestedAt": Utc::now(),
        "unresolved": unresolved,
    });
    doc
}

/// Insert the rows of a new ingested version (quota-admitted, `isLatest`
/// recomputed in the same transaction).
async fn insert_version(
    run: &RunCtx<'_>,
    admitted: &Admitted,
    metadata: &serde_json::Value,
    pins: &[PackagePin],
) -> Result<Uuid, String> {
    let db = &run.state.db;
    let repo = run.repo;
    let name = &admitted.server.name;
    let version = &admitted.server.version;
    let path = fmt::storage_path(name, version);
    let key = fmt::storage_key(name, version, &admitted.sha256);
    let size = admitted.bytes.len() as i64;
    proxy_helpers::put_artifact_bytes(
        run.state,
        repo,
        &key,
        axum::body::Bytes::from(admitted.bytes.clone()),
    )
    .await
    .map_err(|r| format!("storage: {}", r.status()))?;
    let mut tx = crate::api::handlers::publish_quota::begin_admitted_publish(db, repo.id, &path, size)
        .await
        .map_err(|r| format!("quota: {}", r.status()))?;
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO artifacts (repository_id, path, name, version, size_bytes, checksum_sha256, \
                                content_type, storage_key, uploaded_by) \
         VALUES ($1, $2, $3, $4, $5, $6, 'application/json', $7, NULL) RETURNING id",
    )
    .bind(repo.id)
    .bind(&path)
    .bind(name)
    .bind(version)
    .bind(size)
    .bind(&admitted.sha256)
    .bind(&key)
    .fetch_one(&mut *tx)
    .await
    .map_err(db_err)?;
    sqlx::query(
        "INSERT INTO artifact_metadata (artifact_id, format, metadata) VALUES ($1, 'mcp', $2)",
    )
    .bind(id)
    .bind(metadata)
    .execute(&mut *tx)
    .await
    .map_err(db_err)?;
    mcp_packages::hold_pins(&mut tx, pins).await.map_err(db_err)?;
    crate::api::handlers::mcp::recompute_latest_in(&mut tx, repo.id, name)
        .await
        .map_err(db_err)?;
    tx.commit().await.map_err(db_err)?;
    Ok(id)
}

/// After a new version is stored: first sighting (age gate), scan, search.
async fn after_insert(run: &RunCtx<'_>, id: Uuid, admitted: &Admitted) {
    let state = run.state;
    let (name, version) = (&admitted.server.name, &admitted.server.version);
    if let Some(svc) = state.age_gate_service.as_deref() {
        let params = proxy_helpers::age_gate_params(run.repo);
        if let Err(e) = svc.observe_first_seen(&params, name, version).await {
            tracing::warn!(error = %e, server = %name, "MCP sync: first-seen observation failed");
        }
    }
    crate::services::scanner_service::trigger_scan_on_upload(
        &state.db,
        state.scanner_service.clone(),
        run.repo.id,
        id,
    )
    .await;
    crate::services::package_service::PackageService::new(state.db.clone())
        .try_create_or_update_from_artifact(
            run.repo.id,
            name,
            version,
            admitted.bytes.len() as i64,
            &admitted.sha256,
            Some(&admitted.server.description),
            Some(serde_json::json!({"format": "mcp", "source": "upstream"})),
        )
        .await;
    if let Some(search) = &state.search_service {
        let doc = crate::services::opensearch_service::ArtifactDocument {
            id: id.to_string(),
            name: name.clone(),
            path: fmt::storage_path(name, version),
            version: Some(version.clone()),
            format: "mcp".into(),
            repository_id: run.repo.id.to_string(),
            repository_key: run.repo.key.clone(),
            repository_name: run.repo.key.clone(),
            content_type: "application/json".into(),
            size_bytes: admitted.bytes.len() as i64,
            download_count: 0,
            is_public: false,
            created_at: Utc::now().timestamp(),
        };
        if let Err(e) = search.index_artifact(&doc).await {
            tracing::warn!(error = %e, "MCP sync: search indexing failed");
        }
    }
}

/// Mirror the upstream registry state onto a stored version.
async fn mirror_status(
    run: &RunCtx<'_>,
    id: Uuid,
    name: &str,
    registry: &RegistryState,
) -> Result<(), String> {
    let mut tx = run.state.db.begin().await.map_err(db_err)?;
    sqlx::query(
        "UPDATE artifact_metadata SET metadata = jsonb_set(metadata, '{registry}', $2) \
         WHERE artifact_id = $1",
    )
    .bind(id)
    .bind(serde_json::to_value(registry).unwrap_or_default())
    .execute(&mut *tx)
    .await
    .map_err(db_err)?;
    crate::api::handlers::mcp::recompute_latest_in(&mut tx, run.repo.id, name)
        .await
        .map_err(db_err)?;
    tx.commit().await.map_err(db_err)
}

/// Changed bytes under an ingested `name@version`: keep the stored document,
/// re-queue the version (`review` with `contentDrift`), audit. Returns
/// whether this drift is new (a drift to the same upstream bytes is recorded
/// once).
async fn record_drift(
    run: &RunCtx<'_>,
    name: &str,
    version: &str,
    stored_sha: &str,
    upstream_sha: &str,
) -> Result<bool, String> {
    let db = &run.state.db;
    let rows = rows_of(db, run.repo.id, &[name.to_string()])
        .await?
        .remove(name)
        .unwrap_or_default();
    if rows.iter().any(|r| {
        r.version == version
            && r.metadata
                .pointer("/contentDrift/upstreamSha256")
                .and_then(|v| v.as_str())
                == Some(upstream_sha)
    }) {
        return Ok(false);
    }
    let views: Vec<CurationRow> = rows.iter().map(StoredRow::view).collect();
    let was_served = cur::curation_hold(&run.policy, name, version, &views).is_none();
    let meta = serde_json::json!({
        "kind": "mcp_version",
        cur::DRIFT_KEY: {
            "storedSha256": stored_sha,
            "upstreamSha256": upstream_sha,
            "detectedAt": Utc::now(),
        },
    });
    let row = upsert_row(
        db,
        run.repo.id,
        name,
        version,
        STATUS_REVIEW,
        true,
        "content drift: the upstream document changed under this version",
        &meta,
        Some(stored_sha),
    )
    .await?;
    let details = serde_json::json!({
        "review_id": row.id,
        "stored_sha256": stored_sha,
        "upstream_sha256": upstream_sha,
        "was_approved": was_served,
    });
    audit(
        db,
        AuditAction::McpServerContentDrift,
        run.repo,
        Some(name),
        Some(version),
        None,
        details.clone(),
    );
    if was_served {
        audit(
            db,
            AuditAction::McpServerReopened,
            run.repo,
            Some(name),
            Some(version),
            None,
            serde_json::json!({"reason": "content_drift", "review_id": row.id}),
        );
    }
    Ok(true)
}

/// Ingest one upstream entry (write-once; status mirrored; drift detected).
pub async fn ingest_entry(run: &RunCtx<'_>, entry: &UpstreamEntry) -> Result<IngestOutcome, String> {
    let admitted = match admit_upstream(entry) {
        Ok(a) => a,
        Err(e) => {
            tracing::debug!(server = %entry.name, version = %entry.version, error = %e.detail(), "MCP sync: upstream entry refused");
            return Ok(IngestOutcome::Invalid);
        }
    };
    let now = Utc::now();
    let registry = registry_of(entry, now);
    let path = fmt::storage_path(&entry.name, &entry.version);
    match existing_version(&run.state.db, run.repo.id, &path).await? {
        Some((_, _, true, _)) => Ok(IngestOutcome::Tombstoned),
        Some((id, stored_sha, false, stored_registry)) => {
            let stored: Option<RegistryState> =
                stored_registry.and_then(|r| serde_json::from_value(r).ok());
            let status_moved = stored
                .as_ref()
                .is_none_or(|s| registry_changed(s, &registry));
            if status_moved {
                mirror_status(run, id, &entry.name, &registry).await?;
            }
            if stored_sha.trim() != admitted.sha256 {
                let new = record_drift(
                    run,
                    &entry.name,
                    &entry.version,
                    stored_sha.trim(),
                    &admitted.sha256,
                )
                .await?;
                return Ok(if new {
                    IngestOutcome::Drifted
                } else {
                    IngestOutcome::Unchanged
                });
            }
            Ok(if status_moved {
                IngestOutcome::StatusChanged
            } else {
                IngestOutcome::Unchanged
            })
        }
        None => {
            let (pins, unresolved) = pin_packages(run, &admitted.server, None).await;
            let policy = run
                .packages
                .as_ref()
                .map(|s| s.policy)
                .unwrap_or(PackagePolicy::OwnRepos);
            let metadata =
                ingest_metadata(&admitted, &registry, policy, &pins, &unresolved, &run.upstream, entry);
            let id = insert_version(run, &admitted, &metadata, &pins).await?;
            after_insert(run, id, &admitted).await;
            Ok(IngestOutcome::Ingested {
                unresolved: !unresolved.is_empty(),
            })
        }
    }
}

/// Fetch and ingest every upstream version of `name`.
pub async fn ingest_name(run: &RunCtx<'_>, name: &str) -> Result<SyncSummary, String> {
    let page = parse_page(&run.fetch(&versions_path(name)).await?)?;
    let mut summary = SyncSummary::default();
    for entry in page.entries.iter().filter(|e| e.name == name) {
        summary.count(ingest_entry(run, entry).await?);
    }
    Ok(summary)
}

/// Fetch and ingest one upstream version.
pub async fn ingest_version(
    run: &RunCtx<'_>,
    name: &str,
    version: &str,
) -> Result<IngestOutcome, String> {
    let bytes = run.fetch(&version_path(name, version)).await?;
    let doc: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|e| format!("upstream sent invalid JSON: {e}"))?;
    let entry = parse_entry(&doc)
        .filter(|e| e.name == name && e.version == version)
        .ok_or_else(|| "upstream answered another server version".to_string())?;
    ingest_entry(run, &entry).await
}

// ---------------------------------------------------------------------------
// One page of the catalog
// ---------------------------------------------------------------------------

async fn apply_page(
    run: &mut RunCtx<'_>,
    page: &UpstreamPage,
    summary: &mut SyncSummary,
) -> Result<(), String> {
    let mut by_name: BTreeMap<&str, Vec<&UpstreamEntry>> = BTreeMap::new();
    for e in &page.entries {
        by_name.entry(e.name.as_str()).or_default().push(e);
    }
    let names: Vec<String> = by_name.keys().map(|n| n.to_string()).collect();
    let existing = rows_of(&run.state.db, run.repo.id, &names).await?;
    let auto = run.settings.mcp_auto_approve_namespaces.clone().unwrap_or_default();
    for (name, entries) in by_name {
        let rows = existing.get(name).map(Vec::as_slice).unwrap_or_default();
        let name_row = rows.iter().find(|r| r.version == NAME_ROW_VERSION);
        let summary_doc = merge_summary(
            name_row.map(|r| &r.metadata).unwrap_or(&serde_json::Value::Null),
            &entries,
        );
        let denied = run.denied(name);
        let row = match name_row {
            None => {
                let lookalike = lookalike_of(name, &run.protected);
                let (status, reason) =
                    initial_status(lookalike.as_deref(), !denied && auto_approved(&auto, name));
                let mut meta = summary_doc;
                if let Some(target) = &lookalike {
                    meta["flags"] = serde_json::json!({"typosquat": {"similarTo": target}});
                    summary.flagged += 1;
                }
                summary.names_new += 1;
                let row =
                    upsert_row(&run.state.db, run.repo.id, name, NAME_ROW_VERSION, status, true, &reason, &meta, None)
                        .await?;
                if status == STATUS_APPROVED {
                    summary.auto_approved += 1;
                    run.protected.push(name.to_string());
                    audit(
                        &run.state.db,
                        AuditAction::McpServerApproved,
                        run.repo,
                        Some(name),
                        None,
                        None,
                        serde_json::json!({"review_id": row.id, "reason": "auto_approve_namespace"}),
                    );
                }
                row
            }
            Some(r) => {
                let promote = r.status == STATUS_PENDING && !denied && auto_approved(&auto, name);
                let row = upsert_row(
                    &run.state.db,
                    run.repo.id,
                    name,
                    NAME_ROW_VERSION,
                    STATUS_APPROVED,
                    promote,
                    "auto-approved namespace",
                    &summary_doc,
                    None,
                )
                .await?;
                if promote {
                    summary.auto_approved += 1;
                    audit(
                        &run.state.db,
                        AuditAction::McpServerApproved,
                        run.repo,
                        Some(name),
                        None,
                        None,
                        serde_json::json!({"review_id": row.id, "reason": "auto_approve_namespace"}),
                    );
                }
                row
            }
        };
        let whole = name_ingestible(run.mirror(), run.policy.posture, denied, &row.status);
        for entry in entries {
            let pinned = !denied
                && rows
                    .iter()
                    .any(|r| r.version == entry.version && r.status == STATUS_APPROVED);
            // An ingested version is kept current (status, drift) whatever
            // the name's state now.
            let ingest = whole
                || pinned
                || existing_version(
                    &run.state.db,
                    run.repo.id,
                    &fmt::storage_path(&entry.name, &entry.version),
                )
                .await?
                .is_some();
            if ingest {
                summary.count(ingest_entry(run, entry).await?);
            }
        }
        if whole && row.metadata.get("needsIngest").is_some() {
            // The page carried only the recently updated versions.
            match ingest_name(run, name).await {
                Ok(s) => {
                    absorb(summary, &s);
                    clear_needs_ingest(&run.state.db, row.id).await?;
                }
                Err(e) => summary.errors.push(e),
            }
        }
    }
    Ok(())
}

fn absorb(into: &mut SyncSummary, from: &SyncSummary) {
    into.ingested += from.ingested;
    into.unchanged += from.unchanged;
    into.status_changed += from.status_changed;
    into.drifted += from.drifted;
    into.invalid += from.invalid;
    into.unresolved += from.unresolved;
}

/// Names (and pins) an approval flagged `needsIngest` that no page carried:
/// ingest them from their per-server version list.
async fn backfill(run: &RunCtx<'_>, summary: &mut SyncSummary) -> Result<(), String> {
    let pending: Vec<StoredRow> = sqlx::query_as(
        "SELECT id, package_name, version, status, metadata FROM curation_packages \
         WHERE staging_repo_id = $1 AND format = 'mcp' AND status = 'approved' \
           AND metadata ? 'needsIngest' ORDER BY package_name, version LIMIT $2",
    )
    .bind(run.repo.id)
    .bind(MAX_BACKFILL_NAMES)
    .fetch_all(&run.state.db)
    .await
    .map_err(db_err)?;
    for row in pending {
        if run.denied(&row.package_name) {
            continue;
        }
        let result = if row.version == NAME_ROW_VERSION {
            ingest_name(run, &row.package_name).await
        } else {
            ingest_version(run, &row.package_name, &row.version)
                .await
                .map(|o| {
                    let mut s = SyncSummary::default();
                    s.count(o);
                    s
                })
        };
        match result {
            Ok(s) => {
                absorb(summary, &s);
                summary.backfilled_names += 1;
                clear_needs_ingest(&run.state.db, row.id).await?;
            }
            Err(e) => summary.errors.push(e),
        }
    }
    Ok(())
}

/// Retry package resolution for ingested versions that still have
/// unresolved packages (a package pulled through the backing Remote since,
/// a mapping added since).
async fn re_resolve(run: &RunCtx<'_>, summary: &mut SyncSummary) -> Result<(), String> {
    let rows: Vec<(Uuid, serde_json::Value)> = sqlx::query_as(
        "SELECT a.id, m.metadata FROM artifacts a JOIN artifact_metadata m ON m.artifact_id = a.id \
         WHERE a.repository_id = $1 AND a.is_deleted = false AND m.format = 'mcp' \
           AND jsonb_array_length(COALESCE(m.metadata->'ingest'->'unresolved', '[]'::jsonb)) > 0 \
         ORDER BY a.name, a.version LIMIT $2",
    )
    .bind(run.repo.id)
    .bind(MAX_RERESOLVE)
    .fetch_all(&run.state.db)
    .await
    .map_err(db_err)?;
    for (id, meta) in rows {
        let Some(stored) = fmt::StoredVersion::from_metadata(&meta) else {
            continue;
        };
        let Ok(server) = serde_json::from_value::<ServerJson>(stored.server.clone()) else {
            continue;
        };
        let before: Vec<Unresolved> = meta
            .pointer("/ingest/unresolved")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();
        let indexes: Vec<usize> = before.iter().map(|u| u.index).collect();
        let (new_pins, still) = pin_packages(run, &server, Some(&indexes)).await;
        if new_pins.is_empty() {
            continue;
        }
        let mut pins = stored.pins.clone();
        pins.extend(new_pins);
        pins.sort_by_key(|p| p.index);
        let mut tx = run.state.db.begin().await.map_err(db_err)?;
        sqlx::query(
            "UPDATE artifact_metadata SET metadata = \
             jsonb_set(jsonb_set(metadata, '{packages}', $2), '{ingest,unresolved}', $3) \
             WHERE artifact_id = $1",
        )
        .bind(id)
        .bind(serde_json::to_value(&pins).unwrap_or_default())
        .bind(serde_json::to_value(&still).unwrap_or_default())
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
        mcp_packages::hold_pins(&mut tx, &pins).await.map_err(db_err)?;
        tx.commit().await.map_err(db_err)?;
        summary.re_resolved += 1;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Sync state and the run
// ---------------------------------------------------------------------------

/// The stored sync state of one repository (`mcp_remote_sync_state`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct SyncState {
    pub updated_since: Option<DateTime<Utc>>,
    pub resume_cursor: Option<String>,
    pub resume_since: Option<DateTime<Utc>>,
    pub last_started_at: Option<DateTime<Utc>>,
    pub last_finished_at: Option<DateTime<Utc>>,
    pub last_succeeded_at: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
    pub last_summary: serde_json::Value,
}

pub async fn load_state(db: &PgPool, repo_id: Uuid) -> Result<SyncState, String> {
    let row: Option<SyncState> = sqlx::query_as(
        "SELECT updated_since, resume_cursor, resume_since, last_started_at, last_finished_at, \
                last_succeeded_at, last_error, last_summary \
         FROM mcp_remote_sync_state WHERE repository_id = $1",
    )
    .bind(repo_id)
    .fetch_optional(db)
    .await
    .map_err(db_err)?;
    Ok(row.unwrap_or_else(|| SyncState {
        last_summary: serde_json::json!({}),
        ..Default::default()
    }))
}

async fn mark_started(db: &PgPool, repo_id: Uuid) -> Result<(), String> {
    sqlx::query(
        "INSERT INTO mcp_remote_sync_state (repository_id, last_started_at) VALUES ($1, now()) \
         ON CONFLICT (repository_id) DO UPDATE SET last_started_at = now()",
    )
    .bind(repo_id)
    .execute(db)
    .await
    .map_err(db_err)?;
    Ok(())
}

async fn save_state(db: &PgPool, repo_id: Uuid, s: &SyncState, ok: bool) -> Result<(), String> {
    sqlx::query(
        "UPDATE mcp_remote_sync_state SET updated_since = $2, resume_cursor = $3, \
             resume_since = $4, last_finished_at = now(), \
             last_succeeded_at = CASE WHEN $5 THEN now() ELSE last_succeeded_at END, \
             last_error = $6, last_summary = $7 \
         WHERE repository_id = $1",
    )
    .bind(repo_id)
    .bind(s.updated_since)
    .bind(&s.resume_cursor)
    .bind(s.resume_since)
    .bind(ok)
    .bind(&s.last_error)
    .bind(&s.last_summary)
    .execute(db)
    .await
    .map_err(db_err)?;
    Ok(())
}

/// Hold the per-repository sync lock (cluster-wide) for the rest of the run.
async fn lock_repo(
    db: &PgPool,
    repo_id: Uuid,
) -> Result<crate::services::cluster_lock::ClusterLease, SyncError> {
    use crate::services::cluster_lock::{lease_object_id, ClusterLock, PgAdvisoryLock};
    PgAdvisoryLock::new(db.clone())
        .try_acquire(
            SYNC_LOCK_CLASS,
            lease_object_id(&format!("mcp-remote-sync/{repo_id}")),
        )
        .await
        .map_err(|e| SyncError::Database(e.to_string()))?
        .ok_or(SyncError::Busy)
}

/// Run one sync of `repo` (manual trigger or scheduler). Holds the
/// repository's cluster-wide sync lock; [`SyncError::Busy`] when another run
/// holds it.
pub async fn sync_repo(state: &SharedState, repo: &RepoInfo) -> Result<SyncSummary, SyncError> {
    if state.proxy_service.is_none() {
        return Err(SyncError::NoProxy);
    }
    let mut run = RunCtx::load(state, repo).await?;
    let lease = lock_repo(&state.db, repo.id).await?;
    let result = run_locked(&mut run).await;
    lease.release().await;
    result
}

async fn run_locked(run: &mut RunCtx<'_>) -> Result<SyncSummary, SyncError> {
    let db = run.state.db.clone();
    let repo = run.repo;
    let started = Utc::now();
    let mut st = load_state(&db, repo.id).await.map_err(SyncError::Database)?;
    mark_started(&db, repo.id).await.map_err(SyncError::Database)?;
    let since = if st.resume_cursor.is_some() {
        st.resume_since
    } else {
        st.updated_since
    };
    let mut cursor = st.resume_cursor.clone();
    let mut summary = SyncSummary::default();
    let mut max_seen: Option<DateTime<Utc>> = None;
    let mut stopped_at: Option<String> = None;
    loop {
        if summary.pages >= MAX_PAGES_PER_RUN {
            stopped_at = cursor.clone();
            break;
        }
        let bytes = match run.fetch(&listing_path(since, cursor.as_deref())).await {
            Ok(b) => b,
            Err(e) if summary.pages == 0 => {
                st.last_error = Some(e.clone());
                st.last_summary = serde_json::to_value(&summary).unwrap_or_default();
                let _ = save_state(&db, repo.id, &st, false).await;
                return Err(SyncError::Upstream(e));
            }
            Err(e) => {
                summary.errors.push(e);
                stopped_at = cursor.clone();
                break;
            }
        };
        let page = match parse_page(&bytes) {
            Ok(p) => p,
            Err(e) => {
                summary.errors.push(e);
                stopped_at = cursor.clone();
                break;
            }
        };
        summary.pages += 1;
        summary.entries += page.entries.len();
        max_seen = max_seen.max(page.entries.iter().filter_map(|e| e.updated_at).max());
        if let Err(e) = apply_page(run, &page, &mut summary).await {
            summary.errors.push(e);
            stopped_at = cursor.clone();
            break;
        }
        match page.next_cursor {
            Some(next) if Some(&next) != cursor.as_ref() => cursor = Some(next),
            _ => break,
        }
    }
    summary.complete = stopped_at.is_none() && summary.errors.is_empty();
    for step in [backfill(run, &mut summary).await, re_resolve(run, &mut summary).await] {
        if let Err(e) = step {
            summary.errors.push(e);
        }
    }
    if summary.complete {
        st.updated_since = next_watermark(st.updated_since, max_seen, started);
        st.resume_cursor = None;
        st.resume_since = None;
    } else {
        st.resume_cursor = stopped_at.or(cursor);
        st.resume_since = since;
    }
    st.last_error = summary.errors.first().cloned();
    st.last_summary = serde_json::to_value(&summary).unwrap_or_default();
    save_state(&db, repo.id, &st, summary.errors.is_empty())
        .await
        .map_err(SyncError::Database)?;
    audit(
        &db,
        AuditAction::McpMirrorSynced,
        repo,
        None,
        None,
        None,
        serde_json::json!({
            "mode": run.settings.mcp_remote_mode,
            "upstream": run.upstream,
            "updated_since": since,
            "summary": summary,
        }),
    );
    Ok(summary)
}

/// Ingest a name (or one `name@version` pin) right after its approval, so it
/// serves without waiting for the next sync. A failure leaves
/// `metadata.needsIngest` set on the row; the next sync retries it.
pub async fn ingest_after_approval(
    state: &SharedState,
    repo: &RepoInfo,
    name: &str,
    version: &str,
) -> Result<SyncSummary, String> {
    let run = RunCtx::load(state, repo).await.map_err(|e| e.to_string())?;
    if run.denied(name) {
        return Ok(SyncSummary::default());
    }
    let mut summary = SyncSummary::default();
    if version == NAME_ROW_VERSION {
        absorb(&mut summary, &ingest_name(&run, name).await?);
    } else {
        summary.count(ingest_version(&run, name, version).await?);
    }
    Ok(summary)
}

// ---------------------------------------------------------------------------
// Scheduler
// ---------------------------------------------------------------------------

/// The sync interval (`MCP_REMOTE_SYNC_INTERVAL_SECS`, default one hour).
pub fn sync_interval_secs(raw: Option<&str>) -> i64 {
    raw.and_then(|v| v.trim().parse::<i64>().ok())
        .filter(|v| *v >= 60)
        .unwrap_or(DEFAULT_SYNC_INTERVAL_SECS)
}

/// Remote MCP repositories due for a sync: never synced, past the
/// interval, or with an unfinished pass to resume.
pub async fn due_repositories(db: &PgPool, interval_secs: i64) -> Result<Vec<String>, String> {
    sqlx::query_scalar(
        "SELECT r.key FROM repositories r \
         LEFT JOIN mcp_remote_sync_state s ON s.repository_id = r.id \
         WHERE r.format = 'mcp' AND r.repo_type = 'remote' AND r.upstream_url IS NOT NULL \
           AND r.key NOT LIKE '~deleting~%' \
           AND (s.last_started_at IS NULL \
                OR s.last_started_at < now() - make_interval(secs => $1) \
                OR (s.resume_cursor IS NOT NULL \
                    AND s.last_started_at < now() - make_interval(secs => 300))) \
         ORDER BY s.last_started_at NULLS FIRST",
    )
    .bind(interval_secs as f64)
    .fetch_all(db)
    .await
    .map_err(db_err)
}

/// Sync every due repository, stopping between repositories when the
/// scheduler lease is lost.
pub async fn run_due(state: &SharedState, interval_secs: i64, lost: &tokio_util::sync::CancellationToken) {
    let keys = match due_repositories(&state.db, interval_secs).await {
        Ok(k) => k,
        Err(e) => {
            tracing::warn!(error = %e, "MCP remote sync: due repositories unreadable");
            return;
        }
    };
    for key in keys {
        if lost.is_cancelled() {
            return;
        }
        let repo = match proxy_helpers::resolve_repo_by_key(&state.db, &key, &["mcp"], "an MCP registry").await {
            Ok(r) => r,
            Err(_) => continue,
        };
        match sync_repo(state, &repo).await {
            Ok(s) => tracing::info!(repository = %key, ingested = s.ingested, drifted = s.drifted, "MCP remote sync finished"),
            Err(SyncError::Busy) => {}
            Err(e) => tracing::warn!(repository = %key, error = %e, "MCP remote sync failed"),
        }
    }
}

/// Start the hourly sync of Remote MCP registries: every replica ticks, one
/// holds the scheduler lease per tick, and each repository's run holds that
/// repository's cluster lock (so a manual trigger never overlaps it).
pub fn spawn(state: SharedState, shutdown: tokio_util::sync::CancellationToken) {
    let interval_secs = sync_interval_secs(std::env::var("MCP_REMOTE_SYNC_INTERVAL_SECS").ok().as_deref());
    tokio::spawn(async move {
        tokio::select! {
            _ = shutdown.cancelled() => return,
            _ = tokio::time::sleep(std::time::Duration::from_secs(90)) => {}
        }
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(SCHEDULER_TICK_SECS));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => return,
                _ = ticker.tick() => {}
            }
            let Some(lease) = crate::services::cluster_work::try_acquire_scheduler_lease_quiet(
                &state.db,
                SCHEDULER_LEASE,
                SCHEDULER_LEASE_TTL_SECS,
            )
            .await
            else {
                continue;
            };
            let (renewal, lost) =
                lease.spawn_renewal_with_cancellation(state.db.clone(), SCHEDULER_LEASE_TTL_SECS);
            run_due(&state, interval_secs, &lost).await;
            drop(renewal);
            lease.release(&state.db).await;
        }
    });
}

#[cfg(ak_test_shard = "services-1")]
#[cfg(test)]
mod tests {
    use super::*;

    fn ts(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    fn doc(name: &str, version: &str) -> serde_json::Value {
        serde_json::json!({
            "name": name, "description": "Weather", "version": version,
            "remotes": [{"type": "streamable-http", "url": "https://mcp.example.test/mcp"}],
        })
    }

    fn up(name: &str, version: &str, latest: bool, updated: &str) -> UpstreamEntry {
        UpstreamEntry {
            name: name.into(),
            version: version.into(),
            server: doc(name, version),
            status: ServerStatus::Active,
            status_message: None,
            status_changed_at: None,
            published_at: Some(ts(updated)),
            updated_at: Some(ts(updated)),
            is_latest: latest,
        }
    }

    #[test]
    fn pages_parse_with_both_meta_placements() {
        let body = serde_json::json!({
            "servers": [
                {"server": doc("a/b", "1.0.0"), "_meta": {fmt::OFFICIAL_META_KEY: {
                    "status": "deprecated", "statusMessage": "old", "isLatest": true,
                    "publishedAt": "2026-01-01T00:00:00Z", "updatedAt": "2026-01-02T00:00:00Z"}}},
                {"server": {"name": "a/c", "version": "2", "description": "x",
                            "_meta": {fmt::OFFICIAL_META_KEY: {"status": "deleted"}}}},
                {"server": {"version": "1"}},
                {"nothing": true},
            ],
            "metadata": {"nextCursor": "a/c:2", "count": 4},
        });
        let page = parse_page(&serde_json::to_vec(&body).unwrap()).unwrap();
        assert_eq!(page.entries.len(), 2);
        assert_eq!(page.skipped, 2);
        assert_eq!(page.next_cursor.as_deref(), Some("a/c:2"));
        let a = &page.entries[0];
        assert_eq!((a.status, a.status_message.as_deref(), a.is_latest), (ServerStatus::Deprecated, Some("old"), true));
        assert_eq!(a.updated_at, Some(ts("2026-01-02T00:00:00Z")));
        assert_eq!(page.entries[1].status, ServerStatus::Deleted);
        assert!(parse_page(b"nope").is_err());
        assert!(parse_page(b"{}").is_err());
        let empty = parse_page(br#"{"servers": [], "metadata": {"nextCursor": ""}}"#).unwrap();
        assert_eq!(empty.next_cursor, None);
    }

    #[test]
    fn upstream_paths_encode_their_parameters() {
        assert_eq!(listing_path(None, None), "v0.1/servers?limit=100");
        assert_eq!(
            listing_path(Some(ts("2026-10-01T00:00:00Z")), Some("io.github.a/b:1.0.0")),
            "v0.1/servers?limit=100&updated_since=2026-10-01T00%3A00%3A00Z&cursor=io.github.a%2Fb%3A1.0.0"
        );
        assert_eq!(versions_path("a/b"), "v0.1/servers/a%2Fb/versions");
        assert_eq!(version_path("a/b", "1.0 x"), "v0.1/servers/a%2Fb/versions/1.0%20x");
        for p in [listing_path(Some(Utc::now()), Some("x/y")), versions_path("a/b")] {
            assert!(
                crate::services::proxy_service::check_upstream_fetch_path(&p).is_ok(),
                "{p}"
            );
        }
    }

    #[test]
    fn watermark_moves_forward_with_an_overlap() {
        let start = ts("2026-10-10T00:00:00Z");
        let old = Some(ts("2026-10-01T00:00:00Z"));
        assert_eq!(next_watermark(None, None, start), None);
        assert_eq!(next_watermark(old, None, start), old);
        assert_eq!(
            next_watermark(old, Some(ts("2026-10-05T00:00:00Z")), start),
            Some(ts("2026-10-05T00:00:00Z"))
        );
        // Never newer than start minus the overlap, never backwards.
        assert_eq!(
            next_watermark(None, Some(ts("2026-10-10T00:00:00Z")), start),
            Some(start - ChronoDuration::seconds(WATERMARK_OVERLAP_SECS))
        );
        assert_eq!(next_watermark(old, Some(ts("2026-09-01T00:00:00Z")), start), old);
    }

    #[test]
    fn summaries_merge_versions_and_follow_the_latest() {
        let e1 = up("a/b", "1.0.0", false, "2026-01-01T00:00:00Z");
        let mut e2 = up("a/b", "2.0.0", true, "2026-02-01T00:00:00Z");
        e2.server["title"] = "Bee".into();
        let s = merge_summary(&serde_json::Value::Null, &[&e1, &e2]);
        assert_eq!(s["versions"], serde_json::json!(["2.0.0", "1.0.0"]));
        assert_eq!(s["latestVersion"], "2.0.0");
        assert_eq!(s["title"], "Bee");
        assert_eq!(s["upstreamStatus"], "active");
        assert_eq!(s["upstreamUpdatedAt"], ts("2026-02-01T00:00:00Z").to_rfc3339());
        // An older version updated later does not replace the latest.
        let mut stored = s.clone();
        stored["flags"] = serde_json::json!({"x": 1});
        let old = up("a/b", "1.5.0", false, "2026-03-01T00:00:00Z");
        let s2 = merge_summary(&stored, &[&old]);
        assert_eq!(s2["latestVersion"], "2.0.0");
        assert_eq!(s2["title"], "Bee");
        assert_eq!(s2["versions"], serde_json::json!(["2.0.0", "1.5.0", "1.0.0"]));
        assert!(s2.get("flags").is_none(), "other members are merged by the caller");
        // A deleted-only update keeps the stored summary.
        let mut gone = up("a/b", "3.0.0", true, "2026-04-01T00:00:00Z");
        gone.status = ServerStatus::Deleted;
        assert_eq!(merge_summary(&s, &[&gone])["latestVersion"], "2.0.0");
        // Bounded.
        let many: Vec<UpstreamEntry> = (0..250)
            .map(|i| up("a/b", &format!("0.0.{i}"), false, "2026-01-01T00:00:00Z"))
            .collect();
        let refs: Vec<&UpstreamEntry> = many.iter().collect();
        assert_eq!(
            merge_summary(&serde_json::Value::Null, &refs)["versions"]
                .as_array()
                .unwrap()
                .len(),
            MAX_SUMMARY_VERSIONS
        );
    }

    #[test]
    fn lookalikes_are_namespace_squats_of_protected_names() {
        let protected = vec![
            "io.github.acme/filesystem".to_string(),
            "com.stripe/payments".to_string(),
        ];
        assert_eq!(lookalike_key("io.github.Acrne/File-System"), "loglthubacme/fllesystem");
        for squat in [
            "io.github.acrne/filesystem",
            "io.github.acme-/filesystem",
            "io.github.acmee/file-system",
            "com.str1pe/payments",
            "com.stripe0/payment",
        ] {
            assert!(lookalike_of(squat, &protected).is_some(), "{squat}");
        }
        for fine in [
            "io.github.acme/filesystem",  // itself
            "io.github.acme/fileserver",  // a sibling in the same namespace
            "io.github.zzz/filesystem",   // an unrelated namespace
            "com.stripe-labs/other",      // unrelated slug
            "noslash",
        ] {
            assert_eq!(lookalike_of(fine, &protected), None, "{fine}");
        }
    }

    #[test]
    fn auto_approval_and_initial_status() {
        let globs = vec!["com.acme".to_string(), "io.github.acme-*".to_string(), "org.x/y".to_string()];
        assert!(auto_approved(&globs, "com.acme/a"));
        assert!(!auto_approved(&globs, "com.acme.team/a"));
        assert!(auto_approved(&globs, "io.github.acme-labs/a"));
        assert!(auto_approved(&globs, "org.x/y"));
        assert!(!auto_approved(&[], "com.acme/a"));
        assert_eq!(initial_status(None, false).0, STATUS_PENDING);
        assert_eq!(initial_status(None, true).0, STATUS_APPROVED);
        let (s, why) = initial_status(Some("a/b"), true);
        assert_eq!(s, STATUS_REVIEW);
        assert!(why.contains("a/b"));
    }

    #[test]
    fn ingest_eligibility() {
        use Posture::*;
        assert!(name_ingestible(false, ApprovalRequired, false, STATUS_APPROVED));
        assert!(!name_ingestible(false, ApprovalRequired, false, STATUS_PENDING));
        assert!(name_ingestible(false, AllowWithGates, false, STATUS_PENDING));
        assert!(!name_ingestible(false, AllowWithGates, false, STATUS_REVIEW));
        assert!(name_ingestible(true, ApprovalRequired, false, STATUS_REVIEW));
        assert!(!name_ingestible(true, ApprovalRequired, true, STATUS_APPROVED));
        assert!(!name_ingestible(true, AllowWithGates, false, cur::STATUS_BLOCKED));
    }

    #[test]
    fn upstream_documents_are_admitted_like_publishes() {
        let e = up("io.modelcontextprotocol/ref", "1.0.0", true, "2026-01-01T00:00:00Z");
        let a = admit_upstream(&e).expect("reserved upstream namespace is the upstream's own");
        assert_eq!(a.sha256, fmt::sha256_hex(&a.bytes));
        let mut floating = e.clone();
        floating.server = serde_json::json!({
            "name": e.name, "description": "d", "version": "1.0.0",
            "packages": [{"registryType": "oci", "identifier": "ghcr.io/a/b",
                          "transport": {"type": "stdio"}}],
        });
        assert!(admit_upstream(&floating).is_ok(), "tagless OCI admitted for pinning");
        let mut wrong = e.clone();
        wrong.version = "2.0.0".into();
        assert!(admit_upstream(&wrong).is_err());
        let mut bad = e.clone();
        bad.server["description"] = "".into();
        assert!(admit_upstream(&bad).is_err());
    }

    #[test]
    fn registry_state_is_mirrored_from_upstream() {
        let now = Utc::now();
        let mut e = up("a/b", "1", true, "2026-01-01T00:00:00Z");
        let r = registry_of(&e, now);
        assert_eq!(r.updated_at, ts("2026-01-01T00:00:00Z"));
        assert!(!r.is_latest);
        assert!(!registry_changed(&r, &registry_of(&e, now)));
        e.status = ServerStatus::Deprecated;
        assert!(registry_changed(&r, &registry_of(&e, now)));
        e.updated_at = None;
        e.published_at = None;
        assert_eq!(registry_of(&e, now).published_at, now);
    }

    #[test]
    fn upstream_registry_base_url_of_the_backing_remote_is_accepted() {
        let pkg: fmt::Package = serde_json::from_value(serde_json::json!({
            "registryType": "npm", "identifier": "@a/b", "version": "1.0.0",
            "registryBaseUrl": "https://registry.npmjs.org", "transport": {"type": "stdio"},
        }))
        .unwrap();
        let backing = |repo_type: &str, upstream: &str| BackingRepo {
            id: Uuid::new_v4(),
            key: "npm-remote".into(),
            repo_type: repo_type.into(),
            format: "npm".into(),
            upstream_url: Some(upstream.into()),
            location: crate::storage::StorageLocation {
                backend: "filesystem".into(),
                path: "/tmp".into(),
            },
        };
        let remote = backing("remote", "https://registry.npmjs.org/");
        assert_eq!(for_resolution(&pkg, Some(&remote)).registry_base_url, None);
        let other = backing("remote", "https://npm.example.test");
        assert!(for_resolution(&pkg, Some(&other)).registry_base_url.is_some());
        let local = backing("local", "https://registry.npmjs.org");
        assert!(for_resolution(&pkg, Some(&local)).registry_base_url.is_some());
        assert!(for_resolution(&pkg, None).registry_base_url.is_some());
    }

    #[test]
    fn summary_counts_and_intervals() {
        let mut s = SyncSummary::default();
        for o in [
            IngestOutcome::Ingested { unresolved: true },
            IngestOutcome::Ingested { unresolved: false },
            IngestOutcome::Unchanged,
            IngestOutcome::Tombstoned,
            IngestOutcome::StatusChanged,
            IngestOutcome::Drifted,
            IngestOutcome::Invalid,
        ] {
            s.count(o);
        }
        assert_eq!(
            (s.ingested, s.unresolved, s.unchanged, s.status_changed, s.drifted, s.invalid),
            (2, 1, 2, 1, 1, 1)
        );
        let mut total = SyncSummary::default();
        absorb(&mut total, &s);
        absorb(&mut total, &s);
        assert_eq!(total.ingested, 4);
        assert_eq!(sync_interval_secs(None), DEFAULT_SYNC_INTERVAL_SECS);
        assert_eq!(sync_interval_secs(Some(" 600 ")), 600);
        assert_eq!(sync_interval_secs(Some("5")), DEFAULT_SYNC_INTERVAL_SECS);
        assert_eq!(sync_interval_secs(Some("x")), DEFAULT_SYNC_INTERVAL_SECS);
        for (e, needle) in [
            (SyncError::Busy, "already running"),
            (SyncError::NotRemote, "Remote"),
            (SyncError::NoProxy, "outbound"),
            (SyncError::Upstream("x".into()), "upstream"),
            (SyncError::Database("x".into()), "database"),
        ] {
            assert!(e.to_string().contains(needle));
        }
    }
}
