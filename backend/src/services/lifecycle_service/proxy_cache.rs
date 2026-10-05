//! Lifecycle arm for the proxy cache of Remote repositories (#3734).
//!
//! A Remote repository keeps no `artifacts` rows for what it proxies (#1278):
//! cached content lives in `proxy-cache/...` objects catalogued by
//! `proxy_cache_artifacts`, and storage GC deliberately leaves those objects
//! alone. So the artifact executors in the parent module could never reclaim
//! anything there, and a Remote repository's cache only ever grew.
//!
//! Two policy types have a direct meaning for a cache entry and get an arm
//! here:
//!
//! * `max_age_days` keys on `cached_at`, the time the bytes were last written
//!   from upstream;
//! * `no_downloads_days` keys on the entry's last access
//!   (`last_accessed_at`, bumped on every proxy serve) and, like the hosted
//!   predicate, also requires no `proxy_download_statistics` row inside the
//!   window and an entry older than the window.
//!
//! `match.path_prefix` applies to the catalogue's logical `path`. Version
//! exclusions, `match.version_pattern` and `min_keep` cannot be evaluated
//! against a cache entry, which has no version, and a `composite` policy
//! (#2024) has no cache arm, so a policy that carries them does not touch the cache
//! (and is refused for an explicit Remote assignment) rather than deleting
//! what it was written to protect.
//!
//! Only a policy explicitly assigned to a Remote repository reaches its
//! cache. A global (`applies_to_all`) policy is skipped there with a reason:
//! existing global policies were written for hosted cleanup, and the cache
//! may hold the only copy of content gone upstream, so an upgrade must not
//! turn them into cache wipes.
//!
//! The dry run counts and the live run selects through one predicate,
//! [`proxy_cache_retention_where!`], and both report under
//! [`PolicyExecutionResult::proxy_cache`], separately from `artifacts`.

use std::sync::Arc;

use chrono::{DateTime, Utc};

use super::*;
use crate::models::repository::{RepositoryFormat, RepositoryType};
use crate::services::proxy_service::ProxyService;

/// The timestamp a policy's proxy-cache arm ages an entry by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProxyCacheClock {
    /// `max_age_days`: when the bytes were cached from upstream.
    CachedAt,
    /// `no_downloads_days`: when the entry was last served.
    LastAccess,
}

impl ProxyCacheClock {
    /// The `$3` discriminant [`proxy_cache_retention_where!`] switches on.
    pub(crate) fn as_bind(self) -> &'static str {
        match self {
            Self::CachedAt => "cached_at",
            Self::LastAccess => "last_access",
        }
    }
}

/// A policy's proxy-cache selection, fully parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProxyCacheRule {
    pub(crate) clock: ProxyCacheClock,
    pub(crate) days: i32,
    pub(crate) path_prefix: Option<String>,
}

/// Whether a policy reaches proxy-cache entries at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ProxyCacheArm {
    Applies(ProxyCacheRule),
    /// The policy cannot be evaluated against cache entries; the reason is
    /// reported in the run result and in the assignment refusal.
    Unsupported(String),
}

/// Map a policy onto its proxy-cache arm. Pure, so the whole decision table is
/// unit-tested; errors only for a config `validate_policy_config` would reject.
pub(crate) fn proxy_cache_arm(
    policy_type: &str,
    config: &serde_json::Value,
) -> Result<ProxyCacheArm> {
    let kind = PolicyType::parse(policy_type)?;
    let clock = match kind {
        PolicyType::MaxAgeDays => ProxyCacheClock::CachedAt,
        PolicyType::NoDownloadsDays => ProxyCacheClock::LastAccess,
        other => {
            return Ok(ProxyCacheArm::Unsupported(format!(
                "{} has no proxy-cache equivalent; only max_age_days and \
                 no_downloads_days reclaim a Remote repository's cache",
                other.as_wire_str()
            )))
        }
    };
    let filters = parse_policy_filters(config)?;
    if !filters.exclusions.is_empty() {
        return Ok(ProxyCacheArm::Unsupported(
            "exclude matches artifact versions, which proxy-cache entries do not carry; \
             scope the policy with match.path_prefix instead"
                .to_string(),
        ));
    }
    if filters.version_pattern.is_some() {
        return Ok(ProxyCacheArm::Unsupported(
            "match.version_pattern matches artifact versions, which proxy-cache entries do \
             not carry; scope the policy with match.path_prefix instead"
                .to_string(),
        ));
    }
    if kind == PolicyType::MaxAgeDays && parse_min_keep(config)?.is_some() {
        return Ok(ProxyCacheArm::Unsupported(
            "min_keep keeps the newest versions of each package, which proxy-cache \
             entries do not carry"
                .to_string(),
        ));
    }
    let days = parse_i64_field(config, kind.as_wire_str(), "days")?;
    Ok(ProxyCacheArm::Applies(ProxyCacheRule {
        clock,
        days: i32::try_from(days).unwrap_or(i32::MAX),
        path_prefix: filters.path_prefix,
    }))
}

/// Whether a Remote repository of `format` keeps `artifacts` rows the hosted
/// executors can act on. OCI remotes do: a pulled manifest is recorded as an
/// `artifacts` row (`oci_v2.rs`), so every policy type reaches it.
pub(crate) fn remote_keeps_artifact_rows(format: &RepositoryFormat) -> bool {
    format.handler_key() == "oci"
}

/// Selection predicate shared by the dry-run count and the live candidate
/// scan. Binds: `$1` repository id, `$2` days, `$3` [`ProxyCacheClock`]
/// discriminant, `$4` nullable `match.path_prefix`.
///
/// `last_access` mirrors the hosted `no_downloads_where!`: the entry must be
/// older than the window, unserved inside it (`last_accessed_at`, falling back
/// to `cached_at` for a row that predates the column being bumped), and have
/// no recorded proxy download inside it either.
macro_rules! proxy_cache_retention_where {
    () => {
        concat!(
            "WHERE p.repository_id = $1\n",
            "    AND CASE $3::TEXT\n",
            "        WHEN 'cached_at' THEN\n",
            "            p.cached_at < NOW() - make_interval(days => $2::INT)\n",
            "        WHEN 'last_access' THEN\n",
            "            GREATEST(p.cached_at, COALESCE(p.last_accessed_at, p.cached_at))\n",
            "                < NOW() - make_interval(days => $2::INT)\n",
            "            AND NOT EXISTS (\n",
            "                SELECT 1 FROM proxy_download_statistics d\n",
            "                WHERE d.proxy_cache_id = p.id\n",
            "                  AND d.downloaded_at > NOW() - make_interval(days => $2::INT)\n",
            "            )\n",
            "        ELSE false\n",
            "    END\n",
            path_prefix_predicate!("p.", "$4")
        )
    };
}

/// Dry-run (and live-run `matched`) count over [`proxy_cache_retention_where!`].
pub(crate) const PROXY_CACHE_COUNT_SQL: &str = concat!(
    "SELECT COUNT(*)::BIGINT AS count, COALESCE(SUM(p.size_bytes), 0)::BIGINT AS bytes\n",
    "FROM proxy_cache_artifacts p\n",
    proxy_cache_retention_where!()
);

/// Live-run candidate page over the same predicate, keyset-paginated on `id`
/// (`$5` the last id seen, `$6` the page size) so a failed entry is skipped
/// rather than re-selected forever within one run.
pub(crate) const PROXY_CACHE_CANDIDATES_SQL: &str = concat!(
    "SELECT p.id, p.path, p.storage_key, p.metadata_key, p.size_bytes, p.cached_at\n",
    "FROM proxy_cache_artifacts p\n",
    proxy_cache_retention_where!(),
    "    AND p.id > $5\n",
    "ORDER BY p.id\n",
    "LIMIT $6\n"
);

/// Per-entry re-check over the same predicate, run immediately before an
/// entry is evicted (`$5` its id, `$6` the `cached_at` the page read). An
/// entry served or re-cached since its page was read is no longer a
/// candidate and is left alone.
pub(crate) const PROXY_CACHE_RECHECK_SQL: &str = concat!(
    "SELECT EXISTS (\n",
    "SELECT 1 FROM proxy_cache_artifacts p\n",
    proxy_cache_retention_where!(),
    "    AND p.id = $5 AND p.cached_at = $6\n",
    ")\n"
);

/// Candidates fetched per page of a live run.
pub(super) const EVICTION_PAGE_SIZE: i64 = 500;

/// Consecutive storage failures tolerated in one repository before its sweep
/// stops. An unreachable object store would otherwise fail every entry, one
/// round trip and one error line at a time. Consecutive rather than total, so
/// a handful of permanently undeletable entries (object lock, a denied
/// prefix) at the low end of the id range cannot stall the sweep forever.
const MAX_EVICTION_FAILURES: usize = 10;

/// Reported for a global policy on a Remote repository.
pub(crate) const GLOBAL_POLICY_REASON: &str =
    "global policies do not reach a Remote repository's proxy cache; assign the policy to \
     the repository explicitly to evict cached entries";

/// Reported when there is nothing to evict with.
const NO_PROXY_STORE_REASON: &str =
    "this instance has no proxy cache store, so a live run evicts nothing";

/// Proxy-cache side of a policy run (#3734), reported separately from the
/// `artifacts` counters.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, ToSchema)]
pub struct ProxyCacheExecutionResult {
    /// Cache entries the policy selects (dry run and live run alike).
    pub entries_matched: i64,
    /// Cache entries evicted: both objects deleted and the catalogue row
    /// removed. Always zero for a dry run.
    pub entries_removed: i64,
    /// Bytes held by `entries_matched`.
    pub bytes_matched: i64,
    /// Bytes reclaimed by `entries_removed`: the catalogued size of each
    /// removed entry whose objects were actually present and deleted. Always
    /// zero for a dry run.
    pub bytes_freed: i64,
    /// Set when a Remote repository in scope was not swept, and why (the
    /// policy type or config has no proxy-cache meaning, or this instance has
    /// no proxy cache store).
    pub skipped_reason: Option<String>,
}

impl ProxyCacheExecutionResult {
    fn skipped(reason: impl Into<String>) -> Self {
        Self {
            skipped_reason: Some(reason.into()),
            ..Self::default()
        }
    }

    /// Fold one repository's outcome into the policy total.
    pub(crate) fn absorb(&mut self, other: Self) {
        self.entries_matched += other.entries_matched;
        self.entries_removed += other.entries_removed;
        self.bytes_matched += other.bytes_matched;
        self.bytes_freed += other.bytes_freed;
        if self.skipped_reason.is_none() {
            self.skipped_reason = other.skipped_reason;
        }
    }
}

/// What one repository's live sweep works with.
#[derive(Clone, Copy)]
struct Sweep<'a> {
    proxy: &'a ProxyService,
    repository_key: &'a str,
    repository_id: Uuid,
    rule: &'a ProxyCacheRule,
    abort: &'a CancellationToken,
}

#[derive(Debug, sqlx::FromRow)]
struct EvictionCandidate {
    id: Uuid,
    path: String,
    storage_key: String,
    metadata_key: String,
    size_bytes: i64,
    cached_at: DateTime<Utc>,
}

/// Bind a [`ProxyCacheRule`] to `$1..$4` of a [`proxy_cache_retention_where!`]
/// expansion.
macro_rules! bind_proxy_cache_rule {
    ($query:expr, $repository_id:expr, $rule:expr) => {
        $query
            .bind($repository_id)
            .bind($rule.days)
            .bind($rule.clock.as_bind())
            .bind(&$rule.path_prefix)
    };
}

/// The refusal for assigning a policy to a Remote repository it cannot reclaim
/// anything in.
pub(crate) fn inert_remote_assignment_message(
    policy_type: &str,
    repository_key: &str,
    reason: &str,
) -> String {
    format!(
        "A {policy_type} policy cannot reclaim anything in Remote repository \
         '{repository_key}': {reason}"
    )
}

impl LifecycleService {
    /// Attach the proxy service whose store holds Remote repositories' cached
    /// objects. Without it a live run still counts proxy-cache candidates but
    /// evicts none (and says so in `skipped_reason`).
    pub fn with_proxy_service(mut self, proxy_service: Option<Arc<ProxyService>>) -> Self {
        self.proxy_service = proxy_service;
        self
    }

    /// Refuse an explicit assignment of a policy to a Remote repository where
    /// it would match nothing (#3734): its type or config has no proxy-cache
    /// meaning and the repository keeps no `artifacts` rows for the hosted
    /// executors either. Previously such a policy was accepted and silently
    /// never deleted anything.
    pub(super) async fn reject_inert_remote_assignments(
        conn: &mut sqlx::PgConnection,
        policy_type: &str,
        config: &serde_json::Value,
        repository_ids: &[Uuid],
    ) -> Result<()> {
        if repository_ids.is_empty() {
            return Ok(());
        }
        let ProxyCacheArm::Unsupported(reason) = proxy_cache_arm(policy_type, config)? else {
            return Ok(());
        };
        let remotes: Vec<(String, RepositoryFormat)> = sqlx::query_as(
            "SELECT key, format FROM repositories \
             WHERE id = ANY($1) AND repo_type = 'remote' ORDER BY key",
        )
        .bind(repository_ids)
        .fetch_all(conn)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
        match remotes
            .iter()
            .find(|(_, format)| !remote_keeps_artifact_rows(format))
        {
            Some((key, _)) => Err(AppError::UnprocessableEntity(
                inert_remote_assignment_message(policy_type, key, &reason),
            )),
            None => Ok(()),
        }
    }

    /// Test hook: shrink the live sweep's page size so a few entries exercise
    /// keyset continuation.
    #[cfg(test)]
    pub(super) fn with_proxy_cache_page_size(mut self, page_size: i64) -> Self {
        self.proxy_cache_page_size = page_size;
        self
    }

    /// Run `policy`'s proxy-cache arm in one repository. Non-Remote
    /// repositories have no cache and return an empty result. Per-entry
    /// storage failures are appended to `errors` and leave the entry (row and
    /// any surviving object) for the next run.
    pub(super) async fn run_proxy_cache_arm(
        &self,
        policy: &LifecyclePolicy,
        repository_id: Uuid,
        dry_run: bool,
        abort: &CancellationToken,
        errors: &mut Vec<String>,
    ) -> Result<ProxyCacheExecutionResult> {
        let repository: Option<(String, RepositoryType, RepositoryFormat)> =
            sqlx::query_as("SELECT key, repo_type, format FROM repositories WHERE id = $1")
                .bind(repository_id)
                .fetch_optional(&self.db)
                .await
                .map_err(|e| AppError::Database(e.to_string()))?;
        let Some((repository_key, RepositoryType::Remote, format)) = repository else {
            return Ok(ProxyCacheExecutionResult::default());
        };
        let rule = match proxy_cache_arm(&policy.policy_type, &policy.config)? {
            ProxyCacheArm::Applies(rule) => rule,
            // An OCI remote keeps `artifacts` rows the policy does act on, so
            // there is nothing to warn about.
            ProxyCacheArm::Unsupported(_) if remote_keeps_artifact_rows(&format) => {
                return Ok(ProxyCacheExecutionResult::default())
            }
            ProxyCacheArm::Unsupported(reason) => {
                return Ok(ProxyCacheExecutionResult::skipped(reason))
            }
        };
        // Upgrade safety: a global policy written for hosted cleanup must not
        // start evicting every Remote cache, which may be the only surviving
        // copy of content gone upstream. Only an explicit assignment opts a
        // Remote repository's cache in.
        if policy.applies_to_all {
            return Ok(ProxyCacheExecutionResult::skipped(GLOBAL_POLICY_REASON));
        }

        let matched = bind_proxy_cache_rule!(
            sqlx::query_as::<_, CountBytes>(PROXY_CACHE_COUNT_SQL),
            repository_id,
            rule
        )
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
        let mut result = ProxyCacheExecutionResult {
            entries_matched: matched.count,
            bytes_matched: matched.bytes,
            ..ProxyCacheExecutionResult::default()
        };
        // Checked for the preview too, so it does not promise an eviction the
        // live run cannot perform.
        let Some(proxy) = self.proxy_service.as_ref() else {
            if matched.count > 0 {
                result.skipped_reason = Some(NO_PROXY_STORE_REASON.to_string());
            }
            return Ok(result);
        };
        if dry_run || matched.count == 0 {
            return Ok(result);
        }
        let sweep = Sweep {
            proxy,
            repository_key: &repository_key,
            repository_id,
            rule: &rule,
            abort,
        };
        self.sweep_proxy_cache(&sweep, &mut result, errors).await?;
        if result.entries_removed > 0 {
            tracing::info!(
                policy = %policy.name,
                repository = %repository_key,
                entries = result.entries_removed,
                bytes = result.bytes_freed,
                "Lifecycle: evicted proxy-cache entries"
            );
        }
        Ok(result)
    }

    /// The live sweep: page through the candidates, re-check each one, evict
    /// its objects, then delete its row.
    async fn sweep_proxy_cache(
        &self,
        sweep: &Sweep<'_>,
        result: &mut ProxyCacheExecutionResult,
        errors: &mut Vec<String>,
    ) -> Result<()> {
        let Sweep {
            proxy,
            repository_key,
            repository_id,
            rule,
            abort,
        } = *sweep;
        let mut after = Uuid::nil();
        let mut consecutive_failures = 0usize;
        loop {
            // Scheduler lease lost (#3502): another replica may be running
            // the same sweep. Deletes are idempotent, but stop rather than
            // duplicate the work.
            if abort.is_cancelled() {
                errors.push(format!(
                    "stopped the proxy-cache sweep of '{repository_key}': scheduler lease lost"
                ));
                return Ok(());
            }
            let page: Vec<EvictionCandidate> = bind_proxy_cache_rule!(
                sqlx::query_as(PROXY_CACHE_CANDIDATES_SQL),
                repository_id,
                rule
            )
            .bind(after)
            .bind(self.proxy_cache_page_size)
            .fetch_all(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
            let Some(last) = page.last() else {
                break;
            };
            after = last.id;

            for entry in &page {
                let still_candidate: bool = bind_proxy_cache_rule!(
                    sqlx::query_scalar(PROXY_CACHE_RECHECK_SQL),
                    repository_id,
                    rule
                )
                .bind(entry.id)
                .bind(entry.cached_at)
                .fetch_one(&self.db)
                .await
                .map_err(|e| AppError::Database(e.to_string()))?;
                if !still_candidate {
                    continue;
                }
                let recorded = [entry.storage_key.as_str(), entry.metadata_key.as_str()];
                let objects = match proxy
                    .evict_cached_entry(repository_key, &entry.path, recorded)
                    .await
                {
                    Ok(objects) => objects,
                    Err(e) => {
                        consecutive_failures += 1;
                        errors.push(format!(
                            "proxy-cache entry '{}' in '{repository_key}' was kept: {e}",
                            entry.path
                        ));
                        if consecutive_failures >= MAX_EVICTION_FAILURES {
                            errors.push(format!(
                                "stopped the proxy-cache sweep of '{repository_key}' after \
                                 {consecutive_failures} consecutive storage failures"
                            ));
                            return Ok(());
                        }
                        continue;
                    }
                };
                consecutive_failures = 0;
                // Objects first, row second: a crash in between leaves a row
                // the next run re-selects, never an object nothing reclaims.
                // Guarded on `cached_at` so a re-cache that upserted the row
                // (same id) while we deleted is not erased with it.
                let deleted = sqlx::query(
                    "DELETE FROM proxy_cache_artifacts WHERE id = $1 AND cached_at = $2",
                )
                .bind(entry.id)
                .bind(entry.cached_at)
                .execute(&self.db)
                .await
                .map_err(|e| AppError::Database(e.to_string()))?
                .rows_affected();
                if deleted > 0 {
                    result.entries_removed += 1;
                    if objects > 0 {
                        result.bytes_freed += entry.size_bytes;
                    }
                }
            }
            if (page.len() as i64) < self.proxy_cache_page_size {
                break;
            }
        }
        Ok(())
    }
}

#[cfg(ak_test_shard = "services-1")]
#[cfg(test)]
mod tests;
