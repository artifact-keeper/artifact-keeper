//! The upstream catalog and approval queue of Remote MCP registries (#5253).
//!
//! Every read here is a database read of what the sync recorded
//! (`services::mcp_remote`): browsing never calls upstream, and nothing here
//! makes an entry visible on `/v0.1` (that is `services::mcp_curation` at
//! read time). Decisions (approve, block, reopen, `name@version` pins,
//! namespace-glob bulk approval) write `curation_packages`, audit
//! `MCP_SERVER_APPROVED` / `MCP_SERVER_REJECTED` / `MCP_SERVER_REOPENED`, and
//! an approval ingests the name's versions right away (falling back to the
//! next sync, through `metadata.needsIngest`, when upstream is unreachable).

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::api::handlers::proxy_helpers::RepoInfo;
use crate::api::SharedState;
use crate::error::{AppError, Result};
use crate::services::audit_service::AuditAction;
use crate::services::mcp_curation::{
    self as cur, ServePolicy, NAME_ROW_VERSION, STATUS_APPROVED, STATUS_BLOCKED, STATUS_PENDING,
    STATUS_REVIEW,
};
use crate::services::mcp_remote::{self, StoredRow};

pub const DEFAULT_LIMIT: i64 = 50;
pub const MAX_LIMIT: i64 = 200;
/// Names one bulk approval touches.
pub const MAX_BULK: usize = 5000;
/// Names a bulk answer lists.
pub const BULK_NAMES_SHOWN: usize = 100;

fn db(e: sqlx::Error) -> AppError {
    AppError::Database(e.to_string())
}

// ---------------------------------------------------------------------------
// Query (pure)
// ---------------------------------------------------------------------------

/// `GET .../mcp/catalog` query.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, ToSchema, utoipa::IntoParams)]
pub struct CatalogQuery {
    /// Case-insensitive substring of the server name.
    pub search: Option<String>,
    /// Name-level status: `pending`, `approved`, `blocked`, `review`.
    pub status: Option<String>,
    /// Exact namespace (the part before `/`).
    pub namespace: Option<String>,
    /// Only names someone requested approval for.
    pub requested: Option<bool>,
    /// The approval queue: names awaiting a decision, or with a version
    /// awaiting one (a content drift).
    pub queue: Option<bool>,
    pub cursor: Option<String>,
    pub limit: Option<i64>,
}

/// A validated catalog query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogFilter {
    pub like: Option<String>,
    pub status: Option<String>,
    pub namespace: Option<String>,
    pub requested: bool,
    pub queue: bool,
    pub after: Option<String>,
    pub limit: i64,
}

pub const STATUSES: &[&str] = &[
    STATUS_PENDING,
    STATUS_APPROVED,
    STATUS_BLOCKED,
    STATUS_REVIEW,
];

pub fn encode_cursor(name: &str) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(name)
}

pub fn decode_cursor(c: &str) -> Option<String> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(c)
        .ok()
        .and_then(|b| String::from_utf8(b).ok())
}

/// Validate a catalog query (400 on a bad value).
pub fn parse_query(q: &CatalogQuery) -> Result<CatalogFilter> {
    let bad = |m: &str| AppError::Validation(m.to_string());
    let limit = match q.limit {
        None => DEFAULT_LIMIT,
        Some(n) if n >= 1 => n.min(MAX_LIMIT),
        Some(_) => return Err(bad("limit must be a positive integer")),
    };
    let status = match q.status.as_deref().filter(|s| !s.is_empty()) {
        Some(s) if STATUSES.contains(&s) => Some(s.to_string()),
        Some(_) => {
            return Err(bad(
                "status must be one of pending, approved, blocked, review",
            ))
        }
        None => None,
    };
    let search = q.search.as_deref().map(str::trim).filter(|s| !s.is_empty());
    if search.is_some_and(|s| s.chars().count() > 200) {
        return Err(bad("search must be at most 200 characters"));
    }
    let after = match q.cursor.as_deref().filter(|c| !c.is_empty()) {
        Some(c) => Some(decode_cursor(c).ok_or_else(|| bad("cursor is not valid"))?),
        None => None,
    };
    Ok(CatalogFilter {
        like: search.map(|s| format!("%{}%", crate::api::handlers::escape_like_literal(s))),
        status,
        namespace: q
            .namespace
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string),
        requested: q.requested.unwrap_or(false),
        queue: q.queue.unwrap_or(false),
        after,
        limit,
    })
}

// ---------------------------------------------------------------------------
// Items
// ---------------------------------------------------------------------------

/// A `name@version` row of a server (an administrator's pin, or a version
/// re-queued by content drift).
#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CatalogPin {
    pub id: Uuid,
    pub version: String,
    pub status: String,
    /// `{storedSha256, upstreamSha256, detectedAt}` when the upstream
    /// document changed under this ingested version.
    #[schema(value_type = Option<Object>)]
    pub content_drift: Option<serde_json::Value>,
    pub evaluation_reason: Option<String>,
}

/// One ingested version (an `artifacts` row of the Remote).
#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CatalogVersion {
    pub version: String,
    pub artifact_id: Uuid,
    /// Upstream registry status mirrored onto the version.
    pub upstream_status: String,
    /// Packages the sync could not pin (the version is hidden until it can).
    #[schema(value_type = Vec<Object>)]
    pub unresolved: Vec<serde_json::Value>,
}

/// One upstream server name of the catalog.
#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CatalogItem {
    /// The `curation_packages` id of the name-level row (also accepted by
    /// `/api/v1/curation/packages/{id}/approve|block`).
    pub id: Uuid,
    pub name: String,
    pub namespace: String,
    /// `pending` | `approved` | `blocked` | `review`.
    pub status: String,
    /// The name matches `mcp_server_deny`: never served, whatever `status`.
    pub denied: bool,
    pub title: Option<String>,
    pub description: Option<String>,
    pub latest_version: Option<String>,
    pub versions: Vec<String>,
    pub upstream_status: Option<String>,
    pub upstream_updated_at: Option<String>,
    /// `{"typosquat": {"similarTo": "<name>"}}` and similar ingest flags.
    #[schema(value_type = Object)]
    pub flags: serde_json::Value,
    /// `{count, lastRequestedAt, lastRequestedBy, lastNote}`.
    #[schema(value_type = Object)]
    pub approval_requests: serde_json::Value,
    pub evaluation_reason: Option<String>,
    pub evaluated_at: Option<DateTime<Utc>>,
    pub evaluated_by: Option<Uuid>,
    pub first_seen_at: DateTime<Utc>,
    pub pins: Vec<CatalogPin>,
    pub ingested: Vec<CatalogVersion>,
}

/// One catalog page.
#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CatalogPage {
    pub items: Vec<CatalogItem>,
    pub next_cursor: Option<String>,
    /// Name rows per status in the whole repository.
    pub counts: HashMap<String, i64>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct NameRow {
    id: Uuid,
    package_name: String,
    status: String,
    metadata: serde_json::Value,
    evaluation_reason: Option<String>,
    evaluated_at: Option<DateTime<Utc>>,
    evaluated_by: Option<Uuid>,
    first_seen_at: DateTime<Utc>,
}

const NAME_COLUMNS: &str = "id, package_name, status, metadata, evaluation_reason, \
     evaluated_at, evaluated_by, first_seen_at";

fn text(v: &serde_json::Value, k: &str) -> Option<String> {
    v.get(k).and_then(|x| x.as_str()).map(str::to_string)
}

fn object(v: &serde_json::Value, k: &str) -> serde_json::Value {
    v.get(k)
        .filter(|x| x.is_object())
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}))
}

/// The item of one name row (pure).
fn item_of(
    row: NameRow,
    policy: &ServePolicy,
    versions: Vec<(
        String,
        Uuid,
        String,
        Option<serde_json::Value>,
        serde_json::Value,
    )>,
    ingested: Vec<CatalogVersion>,
) -> CatalogItem {
    let m = &row.metadata;
    CatalogItem {
        id: row.id,
        namespace: crate::formats::mcp::namespace_of(&row.package_name).to_string(),
        denied: cur::is_denied(&policy.deny, &row.package_name),
        status: row.status,
        title: text(m, "title"),
        description: text(m, "description"),
        latest_version: text(m, "latestVersion"),
        versions: m
            .get("versions")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default(),
        upstream_status: text(m, "upstreamStatus"),
        upstream_updated_at: text(m, "upstreamUpdatedAt"),
        flags: object(m, "flags"),
        approval_requests: object(m, "approvalRequests"),
        evaluation_reason: row.evaluation_reason,
        evaluated_at: row.evaluated_at,
        evaluated_by: row.evaluated_by,
        first_seen_at: row.first_seen_at,
        pins: versions
            .into_iter()
            .map(|(version, id, status, reason, meta)| CatalogPin {
                id,
                version,
                status,
                content_drift: meta.get(cur::DRIFT_KEY).cloned(),
                evaluation_reason: reason.and_then(|r| r.as_str().map(str::to_string)),
            })
            .collect(),
        ingested,
        name: row.package_name,
    }
}

type VersionTuple = (
    String,
    String,
    Uuid,
    String,
    Option<serde_json::Value>,
    serde_json::Value,
);

type IngestedTuple = (
    String,
    String,
    Uuid,
    Option<String>,
    Option<serde_json::Value>,
);

/// Build the items of `rows`: their version rows and ingested versions.
async fn items_of(
    db_pool: &PgPool,
    repo_id: Uuid,
    policy: &ServePolicy,
    rows: Vec<NameRow>,
) -> Result<Vec<CatalogItem>> {
    let names: Vec<String> = rows.iter().map(|r| r.package_name.clone()).collect();
    let pins: Vec<VersionTuple> = sqlx::query_as(
        "SELECT package_name, version, id, status, to_jsonb(evaluation_reason), metadata \
         FROM curation_packages WHERE staging_repo_id = $1 AND format = 'mcp' \
           AND version <> '*' AND package_name = ANY($2) ORDER BY package_name, version",
    )
    .bind(repo_id)
    .bind(&names)
    .fetch_all(db_pool)
    .await
    .map_err(db)?;
    let ingested: Vec<IngestedTuple> = sqlx::query_as(
        "SELECT a.name, a.version, a.id, m.metadata->'registry'->>'status', \
                    m.metadata->'ingest'->'unresolved' \
             FROM artifacts a JOIN artifact_metadata m ON m.artifact_id = a.id \
             WHERE a.repository_id = $1 AND a.is_deleted = false AND a.name = ANY($2) \
             ORDER BY a.name, a.version",
    )
    .bind(repo_id)
    .bind(&names)
    .fetch_all(db_pool)
    .await
    .map_err(db)?;
    let mut pins_by: HashMap<String, Vec<_>> = HashMap::new();
    for (name, version, id, status, reason, meta) in pins {
        pins_by
            .entry(name)
            .or_default()
            .push((version, id, status, reason, meta));
    }
    let mut ingested_by: HashMap<String, Vec<CatalogVersion>> = HashMap::new();
    for (name, version, artifact_id, status, unresolved) in ingested {
        ingested_by.entry(name).or_default().push(CatalogVersion {
            version,
            artifact_id,
            upstream_status: status.unwrap_or_else(|| "active".into()),
            unresolved: unresolved
                .and_then(|u| serde_json::from_value(u).ok())
                .unwrap_or_default(),
        });
    }
    Ok(rows
        .into_iter()
        .map(|r| {
            let p = pins_by.remove(&r.package_name).unwrap_or_default();
            let i = ingested_by.remove(&r.package_name).unwrap_or_default();
            item_of(r, policy, p, i)
        })
        .collect())
}

fn policy_err(_: ()) -> AppError {
    AppError::Internal("the repository's MCP settings could not be read".into())
}

/// Refuse anything but a Remote MCP repository (404, as for an unknown key).
pub fn require_remote_mcp(repo: &RepoInfo) -> Result<()> {
    if repo.format == "mcp" && repo.repo_type == "remote" {
        Ok(())
    } else {
        Err(AppError::NotFound(
            "Not a Remote MCP repository".to_string(),
        ))
    }
}

/// One page of the catalog.
pub async fn list(db_pool: &PgPool, repo: &RepoInfo, f: &CatalogFilter) -> Result<CatalogPage> {
    let policy = cur::load_serve_policy(db_pool, repo.id)
        .await
        .map_err(policy_err)?;
    let sql = format!(
        "SELECT {NAME_COLUMNS} FROM curation_packages c \
         WHERE c.staging_repo_id = $1 AND c.format = 'mcp' AND c.version = '*' \
           AND ($2::text IS NULL OR c.package_name ILIKE $2 ESCAPE '\\') \
           AND ($3::text IS NULL OR c.status = $3) \
           AND ($4::text IS NULL OR split_part(c.package_name, '/', 1) = $4) \
           AND (NOT $5 OR c.metadata ? 'approvalRequests') \
           AND (NOT $6 OR c.status IN ('pending', 'review') OR EXISTS ( \
                 SELECT 1 FROM curation_packages v WHERE v.staging_repo_id = c.staging_repo_id \
                   AND v.format = 'mcp' AND v.package_name = c.package_name \
                   AND v.version <> '*' AND v.status IN ('pending', 'review'))) \
           AND ($7::text IS NULL OR c.package_name > $7) \
         ORDER BY c.package_name LIMIT $8"
    );
    let mut rows: Vec<NameRow> = sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .bind(repo.id)
        .bind(&f.like)
        .bind(&f.status)
        .bind(&f.namespace)
        .bind(f.requested)
        .bind(f.queue)
        .bind(&f.after)
        .bind(f.limit + 1)
        .fetch_all(db_pool)
        .await
        .map_err(db)?;
    let next_cursor = if rows.len() as i64 > f.limit {
        rows.truncate(f.limit as usize);
        rows.last().map(|r| encode_cursor(&r.package_name))
    } else {
        None
    };
    let counts: Vec<(String, i64)> = sqlx::query_as(
        "SELECT status, count(*) FROM curation_packages \
         WHERE staging_repo_id = $1 AND format = 'mcp' AND version = '*' GROUP BY status",
    )
    .bind(repo.id)
    .fetch_all(db_pool)
    .await
    .map_err(db)?;
    Ok(CatalogPage {
        items: items_of(db_pool, repo.id, &policy, rows).await?,
        next_cursor,
        counts: counts.into_iter().collect(),
    })
}

async fn name_row_by_name(db_pool: &PgPool, repo_id: Uuid, name: &str) -> Result<NameRow> {
    sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT {NAME_COLUMNS} FROM curation_packages \
         WHERE staging_repo_id = $1 AND format = 'mcp' AND version = '*' AND package_name = $2"
    )))
    .bind(repo_id)
    .bind(name)
    .fetch_optional(db_pool)
    .await
    .map_err(db)?
    .ok_or_else(|| AppError::NotFound("MCP server not found in this catalog".into()))
}

/// The catalog item of server `name`.
pub async fn item_by_name(db_pool: &PgPool, repo: &RepoInfo, name: &str) -> Result<CatalogItem> {
    let policy = cur::load_serve_policy(db_pool, repo.id)
        .await
        .map_err(policy_err)?;
    let row = name_row_by_name(db_pool, repo.id, name).await?;
    Ok(items_of(db_pool, repo.id, &policy, vec![row])
        .await?
        .remove(0))
}

/// One MCP curation row of `repo` by id (404 for any other row).
async fn row_by_id(db_pool: &PgPool, repo_id: Uuid, id: Uuid) -> Result<StoredRow> {
    sqlx::query_as(
        "SELECT id, package_name, version, status, metadata FROM curation_packages \
         WHERE id = $1 AND staging_repo_id = $2 AND format = 'mcp'",
    )
    .bind(id)
    .bind(repo_id)
    .fetch_optional(db_pool)
    .await
    .map_err(db)?
    .ok_or_else(|| AppError::NotFound("MCP catalog entry not found".into()))
}

// ---------------------------------------------------------------------------
// Decisions
// ---------------------------------------------------------------------------

/// A decision on one name or `name@version` row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    Approve,
    Block,
    Reopen,
}

impl Decision {
    pub fn status(self) -> &'static str {
        match self {
            Decision::Approve => STATUS_APPROVED,
            Decision::Block => STATUS_BLOCKED,
            Decision::Reopen => STATUS_REVIEW,
        }
    }

    pub fn audit_action(self) -> AuditAction {
        match self {
            Decision::Approve => AuditAction::McpServerApproved,
            Decision::Block => AuditAction::McpServerRejected,
            Decision::Reopen => AuditAction::McpServerReopened,
        }
    }

    /// The decision a generic curation status write amounts to.
    pub fn of_status(status: &str) -> Option<Self> {
        match status {
            STATUS_APPROVED => Some(Decision::Approve),
            STATUS_BLOCKED => Some(Decision::Block),
            STATUS_REVIEW | STATUS_PENDING => Some(Decision::Reopen),
            _ => None,
        }
    }
}

/// The version of a row as an audit field (`None` for a name row).
fn audit_version(row_version: &str) -> Option<&str> {
    (row_version != NAME_ROW_VERSION).then_some(row_version)
}

/// What follows a status write on an MCP row, wherever it was made (the
/// repository routes here, or `/api/v1/curation/packages/...`): the audit
/// and, for an approval, the ingest. Returns the ingest error, if any (the
/// approval stands; the next sync retries).
#[allow(clippy::too_many_arguments)]
pub async fn after_status_change(
    state: &SharedState,
    repo: &RepoInfo,
    row_id: Uuid,
    name: &str,
    version: &str,
    decision: Decision,
    actor: Option<Uuid>,
    reason: Option<&str>,
) -> Option<String> {
    mcp_remote::audit(
        &state.db,
        decision.audit_action(),
        repo,
        Some(name),
        audit_version(version),
        actor,
        serde_json::json!({"review_id": row_id, "reason": reason}),
    );
    if decision != Decision::Approve {
        return None;
    }
    if let Err(e) = mark_needs_ingest(&state.db, &[row_id]).await {
        return Some(e.to_string());
    }
    match mcp_remote::ingest_after_approval(state, repo, name, version).await {
        Ok(_) => {
            let _ = sqlx::query(
                "UPDATE curation_packages SET metadata = metadata - 'needsIngest' WHERE id = $1",
            )
            .bind(row_id)
            .execute(&state.db)
            .await;
            None
        }
        Err(e) => {
            tracing::warn!(server = %name, error = %e, "MCP approval: ingest deferred to the next sync");
            Some(e)
        }
    }
}

async fn mark_needs_ingest(db_pool: &PgPool, ids: &[Uuid]) -> Result<()> {
    sqlx::query(
        "UPDATE curation_packages SET metadata = metadata || '{\"needsIngest\": true}' \
         WHERE id = ANY($1)",
    )
    .bind(ids)
    .execute(db_pool)
    .await
    .map_err(db)?;
    Ok(())
}

/// The answer of a decision: the item it changed and whether the approval's
/// ingest is deferred to the next sync.
#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DecisionResult {
    pub item: CatalogItem,
    /// Set when the approval could not ingest right away (upstream
    /// unreachable); the next sync ingests it.
    pub ingest_error: Option<String>,
}

/// Approve, block or reopen one row of the catalog (a name, or a
/// `name@version` pin).
pub async fn decide(
    state: &SharedState,
    repo: &RepoInfo,
    id: Uuid,
    decision: Decision,
    actor: Uuid,
    reason: Option<&str>,
) -> Result<DecisionResult> {
    let row = row_by_id(&state.db, repo.id, id).await?;
    let default_reason = match decision {
        Decision::Approve => "approved",
        Decision::Block => "blocked",
        Decision::Reopen => "reopened for review",
    };
    sqlx::query(
        "UPDATE curation_packages SET status = $2, evaluation_reason = $3, evaluated_by = $4, \
                evaluated_at = now() WHERE id = $1",
    )
    .bind(id)
    .bind(decision.status())
    .bind(reason.unwrap_or(default_reason))
    .bind(actor)
    .execute(&state.db)
    .await
    .map_err(db)?;
    let ingest_error = after_status_change(
        state,
        repo,
        id,
        &row.package_name,
        &row.version,
        decision,
        Some(actor),
        reason,
    )
    .await;
    Ok(DecisionResult {
        item: item_by_name(&state.db, repo, &row.package_name).await?,
        ingest_error,
    })
}

/// Pin `name@version`: approve that one version (the name's other versions
/// keep the name's decision).
pub async fn pin(
    state: &SharedState,
    repo: &RepoInfo,
    name: &str,
    version: &str,
    actor: Uuid,
    reason: Option<&str>,
) -> Result<DecisionResult> {
    crate::formats::mcp::check_version("version", version)
        .map_err(|e| AppError::Validation(e.detail()))?;
    if version == NAME_ROW_VERSION {
        return Err(AppError::Validation(
            "version must be a concrete version".into(),
        ));
    }
    // The name must be in the catalog: a pin is a decision on an upstream
    // entry, never a way to create one.
    name_row_by_name(&state.db, repo.id, name).await?;
    let row = mcp_remote::upsert_row(
        &state.db,
        repo.id,
        name,
        version,
        STATUS_APPROVED,
        true,
        reason.unwrap_or("pinned version approved"),
        &serde_json::json!({"kind": "mcp_version"}),
        None,
    )
    .await
    .map_err(AppError::Database)?;
    sqlx::query("UPDATE curation_packages SET evaluated_by = $2 WHERE id = $1")
        .bind(row.id)
        .bind(actor)
        .execute(&state.db)
        .await
        .map_err(db)?;
    let ingest_error = after_status_change(
        state,
        repo,
        row.id,
        name,
        version,
        Decision::Approve,
        Some(actor),
        reason,
    )
    .await;
    Ok(DecisionResult {
        item: item_by_name(&state.db, repo, name).await?,
        ingest_error,
    })
}

/// The answer of a namespace-glob bulk approval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct BulkResult {
    pub approved: usize,
    /// At most the first 100 approved names.
    pub names: Vec<String>,
    /// Matching names left alone because they match `mcp_server_deny`.
    pub skipped_denied: usize,
    /// Matching names left alone because they are flagged (`review`);
    /// approve them one by one, or pass `include_review`.
    pub skipped_review: usize,
}

/// Which matching rows a bulk approval takes (pure): `pending` ones, plus
/// flagged (`review`) ones only when asked; never a denied name.
pub fn bulk_selection(
    rows: &[(Uuid, String, String)],
    pattern: &str,
    deny: &[String],
    include_review: bool,
) -> (Vec<(Uuid, String)>, usize, usize) {
    let mut take = Vec::new();
    let (mut denied, mut review) = (0, 0);
    for (id, name, status) in rows {
        if !(crate::services::mcp_settings::glob_matches(pattern, name)
            || crate::services::mcp_settings::glob_matches(
                pattern,
                crate::formats::mcp::namespace_of(name),
            ))
        {
            continue;
        }
        if cur::is_denied(deny, name) {
            denied += 1;
        } else if status == STATUS_REVIEW && !include_review {
            review += 1;
        } else {
            take.push((*id, name.clone()));
        }
    }
    (take, denied, review)
}

/// Approve every `pending` name matching the glob `pattern` (on the full
/// name or the namespace), as one decision. The names' versions are ingested
/// in the background (and by the next sync, whichever comes first).
pub async fn approve_pattern(
    state: &SharedState,
    repo: &RepoInfo,
    pattern: &str,
    include_review: bool,
    actor: Uuid,
    reason: Option<&str>,
) -> Result<BulkResult> {
    let pattern =
        crate::services::mcp_settings::validate_globs("pattern", &[pattern.to_string()])?.remove(0);
    let policy = cur::load_serve_policy(&state.db, repo.id)
        .await
        .map_err(policy_err)?;
    let rows: Vec<(Uuid, String, String)> = sqlx::query_as(
        "SELECT id, package_name, status FROM curation_packages \
         WHERE staging_repo_id = $1 AND format = 'mcp' AND version = '*' \
           AND status IN ('pending', 'review') ORDER BY package_name",
    )
    .bind(repo.id)
    .fetch_all(&state.db)
    .await
    .map_err(db)?;
    let (mut take, skipped_denied, skipped_review) =
        bulk_selection(&rows, &pattern, &policy.deny, include_review);
    take.truncate(MAX_BULK);
    let ids: Vec<Uuid> = take.iter().map(|t| t.0).collect();
    let reason = reason
        .map(str::to_string)
        .unwrap_or_else(|| format!("bulk-approved by pattern {pattern}"));
    sqlx::query(
        "UPDATE curation_packages SET status = 'approved', evaluation_reason = $2, \
                evaluated_by = $3, evaluated_at = now(), \
                metadata = metadata || '{\"needsIngest\": true}' \
         WHERE id = ANY($1)",
    )
    .bind(&ids)
    .bind(&reason)
    .bind(actor)
    .execute(&state.db)
    .await
    .map_err(db)?;
    for (id, name) in &take {
        mcp_remote::audit(
            &state.db,
            AuditAction::McpServerApproved,
            repo,
            Some(name),
            None,
            Some(actor),
            serde_json::json!({"review_id": id, "reason": reason, "pattern": pattern}),
        );
    }
    spawn_ingest(
        state,
        repo,
        take.iter()
            .map(|t| (t.1.clone(), NAME_ROW_VERSION.to_string()))
            .collect(),
    );
    Ok(BulkResult {
        approved: take.len(),
        names: take
            .iter()
            .take(BULK_NAMES_SHOWN)
            .map(|t| t.1.clone())
            .collect(),
        skipped_denied,
        skipped_review,
    })
}

/// Ingest approved names in the background (a bulk approval), clearing each
/// name's `needsIngest` as it lands.
pub fn spawn_ingest(state: &SharedState, repo: &RepoInfo, names: Vec<(String, String)>) {
    if names.is_empty() {
        return;
    }
    let state = state.clone();
    let repo = repo.clone();
    tokio::spawn(async move {
        for (name, version) in names {
            match mcp_remote::ingest_after_approval(&state, &repo, &name, &version).await {
                Ok(_) => {
                    let _ = sqlx::query(
                        "UPDATE curation_packages SET metadata = metadata - 'needsIngest' \
                         WHERE staging_repo_id = $1 AND format = 'mcp' AND package_name = $2 \
                           AND version = $3",
                    )
                    .bind(repo.id)
                    .bind(&name)
                    .bind(&version)
                    .execute(&state.db)
                    .await;
                }
                Err(e) => {
                    tracing::warn!(server = %name, error = %e, "MCP bulk approval: ingest deferred to the next sync");
                }
            }
        }
    });
}

/// Record a reader's request for approval of a name (the UI's "Request
/// approval"): counted on the row, which stays in the queue.
pub async fn request_approval(
    db_pool: &PgPool,
    repo: &RepoInfo,
    id: Uuid,
    user: Uuid,
    note: Option<&str>,
) -> Result<CatalogItem> {
    let row = row_by_id(db_pool, repo.id, id).await?;
    if row.version != NAME_ROW_VERSION {
        return Err(AppError::Validation(
            "request approval of a server name".into(),
        ));
    }
    let note = note.map(|n| n.chars().take(500).collect::<String>());
    sqlx::query(
        "UPDATE curation_packages SET metadata = jsonb_set(metadata, '{approvalRequests}', \
             jsonb_build_object( \
               'count', COALESCE((metadata->'approvalRequests'->>'count')::int, 0) + 1, \
               'lastRequestedAt', now(), 'lastRequestedBy', $2::text, 'lastNote', $3::text)) \
         WHERE id = $1",
    )
    .bind(id)
    .bind(user.to_string())
    .bind(note)
    .execute(db_pool)
    .await
    .map_err(db)?;
    item_by_name(db_pool, repo, &row.package_name).await
}

/// What follows a status write on curation rows through the generic
/// `/api/v1/curation/packages/...` routes, for the rows that are MCP rows of
/// a Remote MCP registry: the audit, and for an approval the ingest (in the
/// background for a bulk write, so the request does not wait on upstream).
pub async fn after_generic_status(
    state: &SharedState,
    ids: &[Uuid],
    status: &str,
    actor: Uuid,
    background: bool,
) {
    let Some(decision) = Decision::of_status(status) else {
        return;
    };
    let rows: Vec<(Uuid, String, String)> = match sqlx::query_as(
        "SELECT id, package_name, version FROM curation_packages          WHERE id = ANY($1) AND format = 'mcp'",
    )
    .bind(ids)
    .fetch_all(&state.db)
    .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "MCP curation hook: rows unreadable");
            return;
        }
    };
    for (id, name, version) in rows {
        let Some(repo) = repo_of_row(&state.db, id).await else {
            continue;
        };
        if background && decision == Decision::Approve {
            mcp_remote::audit(
                &state.db,
                decision.audit_action(),
                &repo,
                Some(&name),
                audit_version(&version),
                Some(actor),
                serde_json::json!({"review_id": id}),
            );
            let _ = mark_needs_ingest(&state.db, &[id]).await;
            spawn_ingest(state, &repo, vec![(name, version)]);
        } else {
            after_status_change(
                state,
                &repo,
                id,
                &name,
                &version,
                decision,
                Some(actor),
                None,
            )
            .await;
        }
    }
}

/// The Remote MCP repository a curation row belongs to, when it is an MCP
/// row (for the generic `/api/v1/curation/packages` routes).
pub async fn repo_of_row(db_pool: &PgPool, row_id: Uuid) -> Option<RepoInfo> {
    let key: Option<String> = sqlx::query_scalar(
        "SELECT r.key FROM curation_packages c JOIN repositories r ON r.id = c.staging_repo_id \
         WHERE c.id = $1 AND c.format = 'mcp' AND r.format = 'mcp' AND r.repo_type = 'remote'",
    )
    .bind(row_id)
    .fetch_optional(db_pool)
    .await
    .ok()
    .flatten();
    crate::api::handlers::proxy_helpers::resolve_repo_by_key(
        db_pool,
        &key?,
        &["mcp"],
        "an MCP registry",
    )
    .await
    .ok()
}

#[cfg(ak_test_shard = "services-1")]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_rules() {
        let f = parse_query(&CatalogQuery::default()).unwrap();
        assert_eq!((f.limit, f.like.as_deref()), (DEFAULT_LIMIT, None));
        let f = parse_query(&CatalogQuery {
            search: Some(" a_b ".into()),
            limit: Some(1000),
            status: Some("review".into()),
            namespace: Some(" com.acme ".into()),
            cursor: Some(encode_cursor("com.acme/x")),
            requested: Some(true),
            queue: Some(true),
        })
        .unwrap();
        assert_eq!(f.limit, MAX_LIMIT);
        assert_eq!(f.like.as_deref(), Some("%a\\_b%"));
        assert_eq!(f.namespace.as_deref(), Some("com.acme"));
        assert_eq!(f.after.as_deref(), Some("com.acme/x"));
        assert!(f.requested && f.queue);
        for bad in [
            CatalogQuery {
                limit: Some(0),
                ..Default::default()
            },
            CatalogQuery {
                status: Some("open".into()),
                ..Default::default()
            },
            CatalogQuery {
                cursor: Some("!!".into()),
                ..Default::default()
            },
            CatalogQuery {
                search: Some("x".repeat(201)),
                ..Default::default()
            },
        ] {
            assert!(parse_query(&bad).is_err(), "{bad:?}");
        }
        assert_eq!(decode_cursor(&encode_cursor("a/b")).as_deref(), Some("a/b"));
    }

    #[test]
    fn decisions_map_to_statuses_and_audits() {
        assert_eq!(Decision::Approve.status(), STATUS_APPROVED);
        assert_eq!(Decision::Block.status(), STATUS_BLOCKED);
        assert_eq!(Decision::Reopen.status(), STATUS_REVIEW);
        assert!(matches!(
            Decision::Approve.audit_action(),
            AuditAction::McpServerApproved
        ));
        assert!(matches!(
            Decision::Block.audit_action(),
            AuditAction::McpServerRejected
        ));
        assert!(matches!(
            Decision::Reopen.audit_action(),
            AuditAction::McpServerReopened
        ));
        assert_eq!(Decision::of_status("approved"), Some(Decision::Approve));
        assert_eq!(Decision::of_status("blocked"), Some(Decision::Block));
        assert_eq!(Decision::of_status("pending"), Some(Decision::Reopen));
        assert_eq!(Decision::of_status("x"), None);
        assert_eq!(audit_version("*"), None);
        assert_eq!(audit_version("1.0"), Some("1.0"));
        let remote = RepoInfo {
            format: "mcp".into(),
            repo_type: "remote".into(),
            ..crate::api::handlers::test_db_helpers::make_repo_info(
                Uuid::new_v4(),
                "k",
                std::path::Path::new("/tmp"),
                "remote",
                None,
            )
        };
        assert!(require_remote_mcp(&remote).is_ok());
        let local = RepoInfo {
            repo_type: "local".into(),
            ..remote.clone()
        };
        assert!(require_remote_mcp(&local).is_err());
    }

    #[test]
    fn bulk_selection_skips_denied_and_flagged() {
        let id = Uuid::new_v4;
        let rows = vec![
            (id(), "io.github.acme/a".to_string(), "pending".to_string()),
            (id(), "io.github.acme/b".to_string(), "review".to_string()),
            (
                id(),
                "io.github.acme/evil".to_string(),
                "pending".to_string(),
            ),
            (id(), "com.other/c".to_string(), "pending".to_string()),
        ];
        let deny = vec!["*/evil".to_string()];
        let (take, denied, review) = bulk_selection(&rows, "io.github.acme/*", &deny, false);
        assert_eq!(
            take.iter().map(|t| t.1.as_str()).collect::<Vec<_>>(),
            ["io.github.acme/a"]
        );
        assert_eq!((denied, review), (1, 1));
        let (take, _, review) = bulk_selection(&rows, "io.github.acme", &deny, true);
        assert_eq!(take.len(), 2);
        assert_eq!(review, 0);
    }

    #[test]
    fn item_of_reads_the_cached_summary() {
        let row = NameRow {
            id: Uuid::new_v4(),
            package_name: "com.acme/w".into(),
            status: "pending".into(),
            metadata: serde_json::json!({
                "title": "W", "description": "Weather", "latestVersion": "2.0.0",
                "versions": ["2.0.0", "1.0.0"], "upstreamStatus": "active",
                "flags": {"typosquat": {"similarTo": "com.acrne/w"}},
            }),
            evaluation_reason: None,
            evaluated_at: None,
            evaluated_by: None,
            first_seen_at: Utc::now(),
        };
        let policy = ServePolicy::hosted(vec!["com.acme/*".into()]);
        let pin_id = Uuid::new_v4();
        let item = item_of(
            row,
            &policy,
            vec![(
                "1.0.0".into(),
                pin_id,
                "review".into(),
                Some(serde_json::json!("content drift")),
                serde_json::json!({"contentDrift": {"upstreamSha256": "x"}}),
            )],
            Vec::new(),
        );
        assert!(item.denied);
        assert_eq!(item.namespace, "com.acme");
        assert_eq!(item.latest_version.as_deref(), Some("2.0.0"));
        assert_eq!(item.versions, ["2.0.0", "1.0.0"]);
        assert_eq!(item.flags["typosquat"]["similarTo"], "com.acrne/w");
        assert_eq!(item.approval_requests, serde_json::json!({}));
        assert_eq!(item.pins[0].id, pin_id);
        assert!(item.pins[0].content_drift.is_some());
        assert_eq!(
            item.pins[0].evaluation_reason.as_deref(),
            Some("content drift")
        );
    }
}
