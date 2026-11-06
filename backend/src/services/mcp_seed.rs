//! Seed a Remote MCP registry with named server versions, without a full
//! catalog sync (#5408).
//!
//! `POST /api/v1/repositories/{key}/mcp/seed` takes a list of
//! `name@version`, records a `mcp_remote_seed_jobs` row and answers `202`;
//! a background task then seeds each item in order:
//!
//! 1. A version already pinned and ingested is `already_pinned`, with no
//!    upstream contact.
//! 2. The name's version list is fetched from the upstream and recorded in
//!    the catalog exactly as a sync page would record it
//!    ([`mcp_remote::record_name_from_upstream`]): the sync's outbound path
//!    (SSRF guard, credentials, egress proxy, upstream gate, cache-only
//!    refusal, `UPSTREAM_FETCHED`), `mcp_server_deny`, the lookalike check and
//!    `mcp_auto_approve_namespaces`.
//! 3. The version is pinned as `POST .../catalog/pins` pins it
//!    ([`catalog::pin`]): approved, audited `MCP_SERVER_APPROVED` and
//!    ingested through the Remote's own package settings.
//!
//! An item ends `pinned`, `already_pinned`, `refused` (a denied, blocked or
//! review-flagged name, or a version the upstream does not list; nothing is
//! approved) or `failed` (the upstream or the ingest failed).
//!
//! `GET .../mcp/seed/{job_id}` reads the job.

use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::api::handlers::proxy_helpers::RepoInfo;
use crate::api::SharedState;
use crate::error::{AppError, Result};
use crate::services::mcp_catalog as catalog;
use crate::services::mcp_curation::{NAME_ROW_VERSION, STATUS_APPROVED, STATUS_BLOCKED};
use crate::services::mcp_remote::{self, NameFetch};
use crate::services::{upstream_mode, upstream_pause};

/// Most items one seed request may list (after duplicates are dropped).
pub const MAX_ITEMS: usize = 500;

/// One requested server version.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
pub struct SeedServer {
    /// Full server name (`io.github.acme/weather`).
    pub name: String,
    /// A concrete version (not `latest`).
    pub version: String,
}

/// Body of `POST .../mcp/seed`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct SeedRequest {
    /// 1 to 500 server versions; a repeated one is seeded once.
    pub servers: Vec<SeedServer>,
    /// Recorded as the approval reason of every pin.
    #[serde(default)]
    pub reason: Option<String>,
}

/// One item of a seed job.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SeedItem {
    pub name: String,
    pub version: String,
    /// `pending`, `pinned`, `already_pinned`, `refused` or `failed`.
    pub state: String,
    /// Why the item was refused or failed.
    #[serde(default)]
    pub reason: Option<String>,
    /// The catalog id of the name, once the name is in the catalog.
    #[serde(default)]
    pub catalog_id: Option<Uuid>,
}

/// `202` answer of a seed request.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SeedAccepted {
    pub job_id: Uuid,
    pub repository: String,
    pub status: String,
    /// Items recorded, after duplicates were dropped.
    pub total: usize,
    /// Where to poll the job.
    pub status_url: String,
}

/// A seed job and its items, in request order.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SeedJob {
    pub job_id: Uuid,
    pub repository: String,
    /// `pending`, `running`, `completed` or `failed`.
    pub status: String,
    pub error: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub started_at: Option<chrono::DateTime<chrono::Utc>>,
    pub finished_at: Option<chrono::DateTime<chrono::Utc>>,
    pub items: Vec<SeedItem>,
}

fn db_err(e: sqlx::Error) -> AppError {
    AppError::Database(e.to_string())
}

fn status_url(repo_key: &str, job_id: Uuid) -> String {
    format!("/api/v1/repositories/{repo_key}/mcp/seed/{job_id}")
}

/// Validate the requested list: bounded, concrete versions, duplicates
/// dropped (input order kept). Pure.
#[allow(clippy::result_large_err)]
pub fn validate(servers: &[SeedServer]) -> Result<Vec<SeedServer>> {
    let mut out: Vec<SeedServer> = Vec::new();
    for s in servers {
        let s = SeedServer {
            name: s.name.trim().to_string(),
            version: s.version.trim().to_string(),
        };
        crate::formats::mcp::check_name(&s.name).map_err(|e| AppError::Validation(e.detail()))?;
        crate::formats::mcp::check_version("version", &s.version)
            .map_err(|e| AppError::Validation(e.detail()))?;
        if s.version == NAME_ROW_VERSION || s.version.eq_ignore_ascii_case("latest") {
            return Err(AppError::Validation(format!(
                "{}: version must be a concrete version",
                s.name
            )));
        }
        if !out.contains(&s) {
            out.push(s);
        }
    }
    if out.is_empty() {
        return Err(AppError::Validation(
            "servers must list at least one {name, version}".into(),
        ));
    }
    if out.len() > MAX_ITEMS {
        return Err(AppError::Validation(format!(
            "servers accepts at most {MAX_ITEMS} entries"
        )));
    }
    Ok(out)
}

/// Record a seed job for `repo` and start it in the background. Refused
/// before anything is recorded when the instance has no outbound fetch path
/// (`502`), when scheduled upstream jobs are paused or the Remote is
/// cache-only (`409`: no upstream contact is allowed).
pub async fn start(
    state: &SharedState,
    repo: RepoInfo,
    servers: &[SeedServer],
    reason: Option<String>,
    actor: Uuid,
) -> Result<SeedAccepted> {
    let items = validate(servers)?;
    if state.proxy_service.is_none() {
        return Err(AppError::BadGateway(
            "outbound fetches are not available".into(),
        ));
    }
    if upstream_pause::upstream_jobs_paused(&state.db).await {
        return Err(AppError::Conflict(
            "scheduled upstream jobs are paused on this instance (upstream_jobs_paused); \
             a seed contacts the upstream and waits for the switch too"
                .into(),
        ));
    }
    if upstream_mode::effective_upstream_mode(&state.db, repo.id)
        .await?
        .is_cache_only()
    {
        return Err(AppError::Conflict(format!(
            "repository '{}' is cache-only; a seed needs upstream contact",
            repo.key
        )));
    }
    let items: Vec<SeedItem> = items
        .into_iter()
        .map(|s| SeedItem {
            name: s.name,
            version: s.version,
            state: "pending".into(),
            reason: None,
            catalog_id: None,
        })
        .collect();
    let total = items.len();
    let job_id: Uuid = sqlx::query_scalar(
        "INSERT INTO mcp_remote_seed_jobs (repository_id, items, reason, created_by) \
         VALUES ($1, $2, $3, $4) RETURNING id",
    )
    .bind(repo.id)
    .bind(serde_json::to_value(&items).unwrap_or_default())
    .bind(&reason)
    .bind(actor)
    .fetch_one(&state.db)
    .await
    .map_err(db_err)?;
    let accepted = SeedAccepted {
        job_id,
        status_url: status_url(&repo.key, job_id),
        repository: repo.key.clone(),
        status: "pending".into(),
        total,
    };
    let state = state.clone();
    tokio::spawn(async move {
        if let Err(e) = run(&state, &repo, job_id, items, reason, actor).await {
            tracing::warn!(job_id = %job_id, error = %e, "MCP seed job failed");
            let _ = sqlx::query(
                "UPDATE mcp_remote_seed_jobs SET status = 'failed', error = $2, \
                     finished_at = NOW() WHERE id = $1",
            )
            .bind(job_id)
            .bind(e.to_string())
            .execute(&state.db)
            .await;
        }
    });
    Ok(accepted)
}

async fn save_items(db: &PgPool, job_id: Uuid, items: &[SeedItem]) -> Result<()> {
    sqlx::query("UPDATE mcp_remote_seed_jobs SET items = $2 WHERE id = $1")
        .bind(job_id)
        .bind(serde_json::to_value(items).unwrap_or_default())
        .execute(db)
        .await
        .map_err(db_err)?;
    Ok(())
}

async fn run(
    state: &SharedState,
    repo: &RepoInfo,
    job_id: Uuid,
    mut items: Vec<SeedItem>,
    reason: Option<String>,
    actor: Uuid,
) -> Result<()> {
    sqlx::query(
        "UPDATE mcp_remote_seed_jobs SET status = 'running', started_at = NOW() WHERE id = $1",
    )
    .bind(job_id)
    .execute(&state.db)
    .await
    .map_err(db_err)?;
    for i in 0..items.len() {
        let (name, version) = (items[i].name.clone(), items[i].version.clone());
        let (outcome, catalog_id) =
            seed_one(state, repo, &name, &version, reason.as_deref(), actor).await;
        let item = &mut items[i];
        item.catalog_id = catalog_id;
        match outcome {
            Outcome::Pinned => item.state = "pinned".into(),
            Outcome::AlreadyPinned => item.state = "already_pinned".into(),
            Outcome::Refused(r) => {
                item.state = "refused".into();
                item.reason = Some(r);
            }
            Outcome::Failed(r) => {
                item.state = "failed".into();
                item.reason = Some(r);
            }
        }
        save_items(&state.db, job_id, &items).await?;
    }
    sqlx::query(
        "UPDATE mcp_remote_seed_jobs SET status = 'completed', finished_at = NOW() WHERE id = $1",
    )
    .bind(job_id)
    .execute(&state.db)
    .await
    .map_err(db_err)?;
    tracing::info!(job_id = %job_id, repository = %repo.key, items = items.len(), "MCP seed job completed");
    Ok(())
}

/// How one item ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Pinned,
    AlreadyPinned,
    Refused(String),
    Failed(String),
}

/// Whether `item` has `version` approved and ingested.
fn pinned_and_ingested(item: &catalog::CatalogItem, version: &str) -> bool {
    item.pins
        .iter()
        .any(|p| p.version == version && p.status == STATUS_APPROVED)
        && item.ingested.iter().any(|v| v.version == version)
}

/// Seed one `name@version`, and the catalog id of the name once known.
pub async fn seed_one(
    state: &SharedState,
    repo: &RepoInfo,
    name: &str,
    version: &str,
    reason: Option<&str>,
    actor: Uuid,
) -> (Outcome, Option<Uuid>) {
    if let Ok(item) = catalog::item_by_name(&state.db, repo, name).await {
        if pinned_and_ingested(&item, version) {
            return (Outcome::AlreadyPinned, Some(item.id));
        }
    }
    let versions = match mcp_remote::record_name_from_upstream(state, repo, name).await {
        Err(e) => return (Outcome::Failed(e), None),
        Ok(NameFetch::Denied) => {
            return (
                Outcome::Refused("the name is denied by mcp_server_deny".into()),
                None,
            )
        }
        Ok(NameFetch::Recorded(v)) => v,
    };
    if versions.is_empty() {
        return (
            Outcome::Refused("the upstream registry lists no version of this name".into()),
            None,
        );
    }
    let item = match catalog::item_by_name(&state.db, repo, name).await {
        Ok(item) => item,
        Err(e) => return (Outcome::Failed(e.to_string()), None),
    };
    let id = Some(item.id);
    if !versions.iter().any(|v| v == version) {
        let listed: Vec<&str> = versions.iter().take(10).map(String::as_str).collect();
        return (
            Outcome::Refused(format!(
                "the upstream registry does not list version {version} (it lists {})",
                listed.join(", ")
            )),
            id,
        );
    }
    if item.status == STATUS_BLOCKED {
        return (
            Outcome::Refused("the name is blocked in the catalog".into()),
            id,
        );
    }
    if item.status == crate::services::mcp_curation::STATUS_REVIEW {
        return (
            Outcome::Refused(format!(
                "the name is flagged for review ({}); decide it in the catalog first",
                item.evaluation_reason.as_deref().unwrap_or("review")
            )),
            id,
        );
    }
    if pinned_and_ingested(&item, version) {
        // Auto-approved and ingested by the recording itself.
        return (Outcome::Pinned, id);
    }
    match catalog::pin(
        state,
        repo,
        name,
        version,
        actor,
        reason.or(Some("seeded version approved")),
    )
    .await
    {
        Ok(r) => match r.ingest_error {
            None => (Outcome::Pinned, id),
            Some(e) => (
                Outcome::Failed(format!(
                    "approved, but not ingested yet ({e}); the next sync retries it"
                )),
                id,
            ),
        },
        Err(e) => (Outcome::Failed(e.to_string()), id),
    }
}

/// Read a seed job of `repo`.
pub async fn load(db: &PgPool, repo: &RepoInfo, job_id: Uuid) -> Result<SeedJob> {
    type Row = (
        String,
        serde_json::Value,
        Option<String>,
        chrono::DateTime<chrono::Utc>,
        Option<chrono::DateTime<chrono::Utc>>,
        Option<chrono::DateTime<chrono::Utc>>,
    );
    let row: Option<Row> = sqlx::query_as(
        "SELECT status, items, error, created_at, started_at, finished_at \
           FROM mcp_remote_seed_jobs WHERE id = $1 AND repository_id = $2",
    )
    .bind(job_id)
    .bind(repo.id)
    .fetch_optional(db)
    .await
    .map_err(db_err)?;
    let (status, items, error, created_at, started_at, finished_at) =
        row.ok_or_else(|| AppError::NotFound("MCP seed job not found".into()))?;
    Ok(SeedJob {
        job_id,
        repository: repo.key.clone(),
        status,
        error,
        created_at,
        started_at,
        finished_at,
        items: serde_json::from_value(items).unwrap_or_default(),
    })
}

#[cfg(ak_test_shard = "services-1")]
#[cfg(test)]
mod tests {
    use super::*;

    fn s(name: &str, version: &str) -> SeedServer {
        SeedServer {
            name: name.into(),
            version: version.into(),
        }
    }

    #[test]
    fn the_list_is_bounded_concrete_and_deduplicated() {
        let out = validate(&[s("io.github.a/x", "1.0.0"), s(" io.github.a/x ", "1.0.0")]).unwrap();
        assert_eq!(out, vec![s("io.github.a/x", "1.0.0")]);
        assert!(validate(&[]).is_err());
        assert!(validate(&[s("io.github.a/x", "latest")]).is_err());
        assert!(validate(&[s("io.github.a/x", "*")]).is_err());
        assert!(validate(&[s("no-slash", "1.0.0")]).is_err());
        let many: Vec<_> = (0..=MAX_ITEMS)
            .map(|i| s("io.github.a/x", &format!("1.0.{i}")))
            .collect();
        assert!(validate(&many).is_err());
    }
}
