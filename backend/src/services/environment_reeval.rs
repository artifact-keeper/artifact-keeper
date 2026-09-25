//! Environment re-evaluation on advisory delta (#4055).
//!
//! An environment scanned clean in March is not clean in June: advisories are
//! published against components already installed, and nothing about the
//! stored environment — lockfile, artifacts, bytes — changes when that
//! happens. #4054 stored the environment and the component -> environment
//! reverse index; this module re-evaluates that STORED component set when
//! advisory data changes. A re-evaluation is a match against
//! `environment_packages`, never a rescan of bytes, so it is cheap enough to
//! run on every detected feed change.
//!
//! # The delta, not a timer
//!
//! Advisory data enters this system through the [`AdvisoryClient`]'s answer
//! cache: a scan asks OSV about `(ecosystem, name, version)` and the answer
//! is cached for an hour. When a refresh produces an advisory-id set
//! different from the previously cached answer, that IS the advisory-data
//! change — the client reports an [`AdvisoryDelta`] for the `(ecosystem,
//! name)` to an [`AdvisoryDeltaSink`], and [`DbAdvisoryDeltaSink`] persists
//! it (one upserted row per package, so a burst of per-version cache misses
//! collapses to a single pending delta). A cluster-leased scheduler tick
//! (`environment_reeval`) drains pending deltas. There is deliberately no
//! timer that walks every environment: an environment whose components have
//! no advisory-data change is re-evaluated never.
//!
//! # Cost: O(delta), not O(environments)
//!
//! Processing one delta is an index scan over
//! `idx_environment_packages_identity((ecosystem, name))` — the stored
//! versions of the delta's ONE package across every environment — plus one
//! batched feed query for those versions. A delta for a package present in
//! no environment touches no rows. Total environment count appears nowhere.
//!
//! # Version-range matching is the feed's, not ours
//!
//! Whether stored version 2.18.4 falls inside an advisory's affected range
//! is decided by querying the feed for exactly that `(ecosystem, name,
//! version)` — the same [`AdvisoryClient`] path a scan uses. This module
//! writes no third semver/range evaluator.
//!
//! # Transitions, not steady state
//!
//! The feed's per-version answer is diffed against
//! `environment_advisory_state` (row present == affected). Only the diff is
//! recorded, in `environment_advisory_transitions` (`new-affected` /
//! `no-longer-affected`), and published on the [`EventBus`]
//! (`environment.advisory_affected` / `environment.advisory_cleared`): an
//! environment BECOMING affected is the event worth surfacing; an
//! environment that was affected and still is produces nothing (#4088's
//! lesson). A withdrawal or a fixed-version shift past the stored version
//! makes the feed stop naming the advisory for that version, which the diff
//! records as `no-longer-affected` — no special withdrawal modelling.
//!
//! A degraded feed answer (transport error, partial batch) records NOTHING:
//! absence of an answer is not absence of affectedness, so the delta stays
//! pending and is retried on a later tick, bounded by [`MAX_DELTA_ATTEMPTS`]
//! so one unreachable feed cannot stall the queue.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{AppError, Result};
use crate::services::environment_lock::Ecosystem;
use crate::services::event_bus::{DomainEvent, EventBus};
use crate::services::repository_service::{build_member_visibility_clause, MemberVisibility};
use crate::services::scanner_service::{AdvisoryClient, AdvisoryMatch, Dependency};

/// Transition kinds, constrained by the migration's CHECK.
pub const TRANSITION_NEW_AFFECTED: &str = "new-affected";
pub const TRANSITION_NO_LONGER_AFFECTED: &str = "no-longer-affected";

/// EventBus event types for the two transition directions. Two types rather
/// than one with a payload field: [`DomainEvent`] carries no detail beyond
/// its type, and the DIRECTION is the fact a subscriber pages on.
pub const EVENT_ADVISORY_AFFECTED: &str = "environment.advisory_affected";
pub const EVENT_ADVISORY_CLEARED: &str = "environment.advisory_cleared";

/// A delta whose feed answer stays degraded is retried on later ticks this
/// many times, then given up on (logged, marked processed). Bounds the queue
/// when a feed is down for longer than the cache TTL.
const MAX_DELTA_ATTEMPTS: i32 = 5;

/// Default and hard cap for the transitions listing.
const DEFAULT_TRANSITION_LIMIT: i64 = 100;
const MAX_TRANSITION_LIMIT: i64 = 500;

/// An advisory-data change detected against one `(ecosystem, name)`.
///
/// `ecosystem` is the feed's naming (`PyPI`, `npm`, `crates.io`); the mapping
/// to the stored purl-type ecosystem and the ecosystem's name normalisation
/// happen here, in one place, rather than at every detection site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdvisoryDelta {
    pub ecosystem: String,
    pub name: String,
    /// The advisory-id set observed after the change. Informational only:
    /// processing re-queries the feed for current truth rather than trusting
    /// the detection-time snapshot.
    pub advisory_ids: Vec<String>,
}

/// Where the advisory client reports detected deltas. A trait so the client
/// holds no database handle and tests can capture deltas synchronously.
#[async_trait]
pub trait AdvisoryDeltaSink: Send + Sync {
    async fn record(&self, delta: AdvisoryDelta);
}

/// Persists detected deltas for the leased scheduler tick to drain.
pub struct DbAdvisoryDeltaSink {
    db: PgPool,
}

impl DbAdvisoryDeltaSink {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }
}

#[async_trait]
impl AdvisoryDeltaSink for DbAdvisoryDeltaSink {
    /// Upsert keyed on `(ecosystem, name)`: a second detected change before
    /// the tick runs RE-ARMS the same row (`processed_at = NULL`, attempts
    /// reset), so the queue holds at most one pending delta per package no
    /// matter how many versions' cache entries refreshed.
    async fn record(&self, delta: AdvisoryDelta) {
        let result = sqlx::query(
            "INSERT INTO advisory_deltas (ecosystem, name, advisory_ids) \
             VALUES ($1, $2, $3) \
             ON CONFLICT (ecosystem, name) DO UPDATE \
             SET advisory_ids = EXCLUDED.advisory_ids, \
                 detected_at = now(), processed_at = NULL, attempts = 0",
        )
        .bind(&delta.ecosystem)
        .bind(&delta.name)
        .bind(&delta.advisory_ids)
        .execute(&self.db)
        .await;
        if let Err(e) = result {
            // A lost delta is a lost re-evaluation until the next change, so
            // this is louder than debug — but the scan that detected the
            // delta must never fail over the side channel.
            tracing::warn!(
                "failed to persist advisory delta for {}/{}: {}",
                delta.ecosystem,
                delta.name,
                e
            );
        }
    }
}

/// The stored (purl-type) ecosystem a feed ecosystem maps to, if any.
///
/// `conda` maps to nothing: no advisory feed serves it — the scan path
/// resolves conda packages through the PyPI alias graph BEFORE querying
/// (#4042), so a detected delta always carries a feed ecosystem. `*`
/// (unscoped vendored-library queries) has no ecosystem to key a reverse
/// lookup on and maps to nothing.
fn stored_ecosystem(feed: &str) -> Option<Ecosystem> {
    match feed {
        "PyPI" | "pypi" => Some(Ecosystem::PyPi),
        "npm" => Some(Ecosystem::Npm),
        "crates.io" | "cargo" => Some(Ecosystem::Cargo),
        _ => None,
    }
}

/// The ecosystem name the feed expects for a stored ecosystem — the inverse
/// of [`stored_ecosystem`] for the re-query. Conda never reaches it (deltas
/// keyed on conda are skipped), hence `Option`.
fn feed_ecosystem(ecosystem: Ecosystem) -> Option<&'static str> {
    match ecosystem {
        Ecosystem::PyPi => Some("PyPI"),
        Ecosystem::Npm => Some("npm"),
        Ecosystem::Cargo => Some("crates.io"),
        Ecosystem::Conda => None,
    }
}

/// What processing one delta did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DeltaOutcome {
    /// The delta's ecosystem has no stored counterpart (conda, unscoped);
    /// nothing to key a lookup on. Counts as processed, not as failure.
    pub skipped: bool,
    /// The feed did not answer; nothing was recorded and the caller must
    /// leave the delta pending for a later tick.
    pub degraded: bool,
    pub environments_evaluated: usize,
    pub new_affected: usize,
    pub no_longer_affected: usize,
}

/// One row of current affectedness, joined with its environment for display.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AffectednessRecord {
    pub environment_id: Uuid,
    pub advisory_id: String,
    pub ecosystem: String,
    pub name: String,
    pub version: String,
    pub summary: Option<String>,
    pub severity: Option<String>,
    pub fixed_version: Option<String>,
    pub source_url: Option<String>,
    pub affected_since: DateTime<Utc>,
    pub last_evaluated_at: DateTime<Utc>,
}

/// One recorded transition, joined with environment and repository for the
/// API answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitionRecord {
    pub id: i64,
    pub environment_id: Uuid,
    pub environment_name: String,
    pub repository_id: Uuid,
    pub repository_key: String,
    pub advisory_id: String,
    pub ecosystem: String,
    pub name: String,
    pub version: String,
    pub kind: String,
    pub summary: Option<String>,
    pub severity: Option<String>,
    pub fixed_version: Option<String>,
    pub source_url: Option<String>,
    pub detected_at: DateTime<Utc>,
}

/// Filters for the transitions listing. All optional; `limit` is clamped to
/// [`MAX_TRANSITION_LIMIT`].
#[derive(Debug, Default, Clone)]
pub struct TransitionFilter {
    pub advisory_id: Option<String>,
    pub kind: Option<String>,
    pub since: Option<DateTime<Utc>>,
    pub until: Option<DateTime<Utc>>,
    pub limit: Option<i64>,
}

pub struct EnvironmentReevalService {
    db: PgPool,
    advisory: Option<Arc<AdvisoryClient>>,
    events: Arc<EventBus>,
}

impl EnvironmentReevalService {
    pub fn new(db: PgPool, advisory: Arc<AdvisoryClient>, events: Arc<EventBus>) -> Self {
        Self {
            db,
            advisory: Some(advisory),
            events,
        }
    }

    /// The read paths (transitions listing, current state) need no feed
    /// client; the API constructs this form.
    pub fn read_only(db: PgPool, events: Arc<EventBus>) -> Self {
        Self {
            db,
            advisory: None,
            events,
        }
    }

    /// Re-evaluate every stored environment against one advisory delta.
    ///
    /// Complexity: one index scan over
    /// `idx_environment_packages_identity((ecosystem, name))` returning the
    /// delta package's stored versions, plus one batched feed query of that
    /// size. The total number of stored environments appears nowhere in the
    /// cost; a delta for a package in NO environment touches no rows.
    pub async fn process_delta(&self, delta: &AdvisoryDelta) -> Result<DeltaOutcome> {
        let Some(ecosystem) = stored_ecosystem(&delta.ecosystem) else {
            return Ok(DeltaOutcome {
                skipped: true,
                ..Default::default()
            });
        };
        let Some(feed_ecosystem) = feed_ecosystem(ecosystem) else {
            return Ok(DeltaOutcome {
                skipped: true,
                ..Default::default()
            });
        };
        // The name normalised exactly the way ingest normalised the stored
        // row, so an advisory's "Zope.Interface" finds the stored
        // "zope-interface".
        let name = ecosystem.normalize(&delta.name);
        let stored = ecosystem.as_str();

        // The delta-path lookup: an index scan over
        // idx_environment_packages_identity((ecosystem, name)), returning
        // this ONE package's stored versions across every environment. A
        // delta for a package in no environment returns zero rows and the
        // rest of the method is a no-op.
        let rows: Vec<(Uuid, String)> = sqlx::query_as(
            "SELECT DISTINCT environment_id, version FROM environment_packages \
             WHERE ecosystem = $1 AND name = $2 AND version IS NOT NULL",
        )
        .bind(stored)
        .bind(&name)
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        let mut versions: BTreeSet<String> = BTreeSet::new();
        let mut environments: BTreeMap<Uuid, BTreeSet<String>> = BTreeMap::new();
        for (environment_id, version) in rows {
            versions.insert(version.clone());
            environments
                .entry(environment_id)
                .or_default()
                .insert(version);
        }

        // Version-range matching is the feed's, not ours: each stored
        // version is queried exactly the way a scan queries it, and the
        // feed's per-version answer IS the affectedness verdict. One batch,
        // sized by the package's distinct stored versions.
        let version_list: Vec<&String> = versions.iter().collect();
        let deps: Vec<Dependency> = version_list
            .iter()
            .map(|v| Dependency {
                name: name.clone(),
                version: Some((*v).clone()),
                ecosystem: feed_ecosystem.to_string(),
            })
            .collect();
        let advisory = self.advisory.as_ref().ok_or_else(|| {
            AppError::Internal(
                "environment re-evaluation without a feed client (read-only service)".to_string(),
            )
        })?;
        let lookup = advisory.query_osv_detailed(&deps).await;
        if lookup.degraded {
            // An unanswered feed is not a clean feed: recording from it
            // would publish a false all-clear as `no-longer-affected`
            // transitions. Nothing is written; the caller retries.
            return Ok(DeltaOutcome {
                degraded: true,
                ..Default::default()
            });
        }
        let answer_for = |version: &str| -> &[AdvisoryMatch] {
            version_list
                .iter()
                .position(|v| v.as_str() == version)
                .and_then(|i| lookup.per_dep.get(i))
                .map(Vec::as_slice)
                .unwrap_or(&[])
        };

        // Current affectedness per (environment, version, advisory), from
        // the feed's answers over the STORED component set.
        let mut current: BTreeSet<(Uuid, String, String)> = BTreeSet::new();
        for (environment_id, env_versions) in &environments {
            for version in env_versions {
                for m in answer_for(version) {
                    current.insert((*environment_id, version.clone(), m.id.clone()));
                }
            }
        }

        let state_rows: Vec<StateRow> = sqlx::query_as(
            "SELECT environment_id, advisory_id, version, summary, severity, \
                    fixed_version, source_url \
             FROM environment_advisory_state WHERE ecosystem = $1 AND name = $2",
        )
        .bind(stored)
        .bind(&name)
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
        let stored_set: BTreeSet<(Uuid, String, String)> = state_rows
            .iter()
            .map(|r| (r.environment_id, r.version.clone(), r.advisory_id.clone()))
            .collect();

        // The diff, both directions. `gone` covers every way affectedness
        // ends — withdrawal, a fixed-version shift past the stored version,
        // and the component being re-solved out of the environment — which
        // all render the same way: the transition is no longer true.
        let new: Vec<&(Uuid, String, String)> = current.difference(&stored_set).collect();
        let gone: Vec<&(Uuid, String, String)> = stored_set.difference(&current).collect();

        if new.is_empty() && gone.is_empty() {
            // Steady state. Refresh the evaluation timestamp so a reader can
            // tell "still affected, checked recently" from "not looked at
            // since March", and record nothing else.
            sqlx::query(
                "UPDATE environment_advisory_state SET last_evaluated_at = now() \
                 WHERE ecosystem = $1 AND name = $2",
            )
            .bind(stored)
            .bind(&name)
            .execute(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
            return Ok(DeltaOutcome {
                environments_evaluated: environments.len(),
                ..Default::default()
            });
        }

        let mut tx = self
            .db
            .begin()
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        // Every insert is guarded on the environment still existing: an
        // environment can be deleted (or re-ingested away) between the
        // membership read above and this write, and a re-evaluation must
        // never fail over an environment that is already gone — there is
        // nothing left to protect. The transition counts come from the
        // guarded inserts' row counts, so a skipped insert is not reported
        // as an event.
        let mut new_affected = 0usize;
        for (environment_id, version, advisory_id) in &new {
            let m = answer_for(version)
                .iter()
                .find(|m| m.id == *advisory_id)
                .expect("a new-affected id came from this version's answer");
            let state_written = sqlx::query(
                "INSERT INTO environment_advisory_state \
                 (environment_id, advisory_id, ecosystem, name, version, \
                  summary, severity, fixed_version, source_url) \
                 SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9 \
                 WHERE EXISTS (SELECT 1 FROM environments WHERE id = $1) \
                 ON CONFLICT DO NOTHING",
            )
            .bind(environment_id)
            .bind(advisory_id)
            .bind(stored)
            .bind(&name)
            .bind(version)
            .bind(&m.summary)
            .bind(&m.severity)
            .bind(&m.fixed_version)
            .bind(&m.source_url)
            .execute(&mut *tx)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?
            .rows_affected();
            if state_written == 0 {
                continue;
            }
            new_affected += sqlx::query(
                "INSERT INTO environment_advisory_transitions \
                 (environment_id, advisory_id, ecosystem, name, version, kind, \
                  summary, severity, fixed_version, source_url) \
                 SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9, $10 \
                 WHERE EXISTS (SELECT 1 FROM environments WHERE id = $1)",
            )
            .bind(environment_id)
            .bind(advisory_id)
            .bind(stored)
            .bind(&name)
            .bind(version)
            .bind(TRANSITION_NEW_AFFECTED)
            .bind(&m.summary)
            .bind(&m.severity)
            .bind(&m.fixed_version)
            .bind(&m.source_url)
            .execute(&mut *tx)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?
            .rows_affected() as usize;
        }

        let mut no_longer_affected = 0usize;
        for (environment_id, version, advisory_id) in &gone {
            let prior = state_rows
                .iter()
                .find(|r| {
                    r.environment_id == *environment_id
                        && r.version == *version
                        && r.advisory_id == *advisory_id
                })
                .expect("a gone id came from the stored state");
            let state_removed = sqlx::query(
                "DELETE FROM environment_advisory_state \
                 WHERE environment_id = $1 AND advisory_id = $2 AND ecosystem = $3 \
                   AND name = $4 AND version = $5",
            )
            .bind(environment_id)
            .bind(advisory_id)
            .bind(stored)
            .bind(&name)
            .bind(version)
            .execute(&mut *tx)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?
            .rows_affected();
            if state_removed == 0 {
                continue;
            }
            no_longer_affected += sqlx::query(
                "INSERT INTO environment_advisory_transitions \
                 (environment_id, advisory_id, ecosystem, name, version, kind, \
                  summary, severity, fixed_version, source_url) \
                 SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9, $10 \
                 WHERE EXISTS (SELECT 1 FROM environments WHERE id = $1)",
            )
            .bind(environment_id)
            .bind(advisory_id)
            .bind(stored)
            .bind(&name)
            .bind(version)
            .bind(TRANSITION_NO_LONGER_AFFECTED)
            .bind(&prior.summary)
            .bind(&prior.severity)
            .bind(&prior.fixed_version)
            .bind(&prior.source_url)
            .execute(&mut *tx)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?
            .rows_affected() as usize;
        }

        // Still-affected rows: the fact is unchanged, only its freshness
        // moves.
        sqlx::query(
            "UPDATE environment_advisory_state SET last_evaluated_at = now() \
             WHERE ecosystem = $1 AND name = $2",
        )
        .bind(stored)
        .bind(&name)
        .execute(&mut *tx)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        tx.commit()
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        // Events after the commit: a subscriber must be able to read the
        // transition it was told about. One event per transition, typed by
        // DIRECTION — that is the fact a subscriber pages on.
        let environment_ids: Vec<Uuid> = new
            .iter()
            .chain(gone.iter())
            .map(|(id, _, _)| *id)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let repo_rows: Vec<(Uuid, Uuid)> =
            sqlx::query_as("SELECT id, repository_id FROM environments WHERE id = ANY($1)")
                .bind(&environment_ids)
                .fetch_all(&self.db)
                .await
                .map_err(|e| AppError::Database(e.to_string()))?;
        let repo_of: std::collections::HashMap<Uuid, Uuid> = repo_rows.into_iter().collect();
        for (environment_id, _, _) in &new {
            if let Some(repository_id) = repo_of.get(environment_id) {
                self.events.publish(DomainEvent::now_for_repo(
                    EVENT_ADVISORY_AFFECTED,
                    environment_id.to_string(),
                    *repository_id,
                    None,
                ));
            }
        }
        for (environment_id, _, _) in &gone {
            if let Some(repository_id) = repo_of.get(environment_id) {
                self.events.publish(DomainEvent::now_for_repo(
                    EVENT_ADVISORY_CLEARED,
                    environment_id.to_string(),
                    *repository_id,
                    None,
                ));
            }
        }

        Ok(DeltaOutcome {
            environments_evaluated: environments.len(),
            new_affected,
            no_longer_affected,
            ..Default::default()
        })
    }

    /// Drain pending advisory deltas, oldest first, up to `limit`. Runs
    /// under the scheduler's `environment_reeval` singleton lease, so no
    /// row claiming is needed. A delta whose processing reports a degraded
    /// feed stays pending (attempts incremented, given up on after
    /// [`MAX_DELTA_ATTEMPTS`]); every other outcome marks the delta
    /// processed. Returns how many deltas were marked processed.
    pub async fn process_pending_deltas(&self, limit: i64) -> Result<usize> {
        let pending: Vec<(i64, String, String, Vec<String>)> = sqlx::query_as(
            "SELECT id, ecosystem, name, advisory_ids FROM advisory_deltas \
             WHERE processed_at IS NULL ORDER BY id LIMIT $1",
        )
        .bind(limit)
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        let mut processed = 0;
        for (id, ecosystem, name, advisory_ids) in pending {
            let outcome = self
                .process_delta(&AdvisoryDelta {
                    ecosystem,
                    name,
                    advisory_ids,
                })
                .await?;
            if outcome.degraded {
                let attempts: i32 = sqlx::query_scalar(
                    "UPDATE advisory_deltas SET attempts = attempts + 1 \
                     WHERE id = $1 RETURNING attempts",
                )
                .bind(id)
                .fetch_one(&self.db)
                .await
                .map_err(|e| AppError::Database(e.to_string()))?;
                if attempts >= MAX_DELTA_ATTEMPTS {
                    tracing::warn!(
                        "advisory delta {id}: feed still degraded after {attempts} \
                         attempts; giving up on this detection"
                    );
                    sqlx::query("UPDATE advisory_deltas SET processed_at = now() WHERE id = $1")
                        .bind(id)
                        .execute(&self.db)
                        .await
                        .map_err(|e| AppError::Database(e.to_string()))?;
                    processed += 1;
                }
                continue;
            }
            sqlx::query("UPDATE advisory_deltas SET processed_at = now() WHERE id = $1")
                .bind(id)
                .execute(&self.db)
                .await
                .map_err(|e| AppError::Database(e.to_string()))?;
            processed += 1;
        }
        Ok(processed)
    }

    /// Recorded transitions across the repositories `visibility` may read,
    /// newest first. The visibility clause is rendered by
    /// [`build_member_visibility_clause`] exactly as `require_visible` would
    /// decide row by row — a caller never learns that an environment in a
    /// repository they cannot read transitioned.
    pub async fn list_transitions(
        &self,
        visibility: &MemberVisibility,
        filter: &TransitionFilter,
    ) -> Result<Vec<TransitionRecord>> {
        let limit = filter
            .limit
            .unwrap_or(DEFAULT_TRANSITION_LIMIT)
            .clamp(1, MAX_TRANSITION_LIMIT);
        // The clause references $2 (user) and $3 (repo-scope ids); binds the
        // clause does not reference are sent as typed NULLs, as in
        // environment_service::lookup_by_purl.
        let (clause, user_bind, scope_bind) = build_member_visibility_clause(visibility, "r", 2);
        let sql = format!(
            r#"SELECT t.id, t.environment_id, e.name AS environment_name,
                      e.repository_id, r.key AS repository_key,
                      t.advisory_id, t.ecosystem, t.name, t.version, t.kind,
                      t.summary, t.severity, t.fixed_version, t.source_url, t.detected_at
               FROM environment_advisory_transitions t
               JOIN environments e ON e.id = t.environment_id
               JOIN repositories r ON r.id = e.repository_id
               WHERE {clause}
                 AND ($4::text IS NULL OR t.advisory_id = $4)
                 AND ($5::text IS NULL OR t.kind = $5)
                 AND ($6::timestamptz IS NULL OR t.detected_at >= $6)
                 AND ($7::timestamptz IS NULL OR t.detected_at <= $7)
               ORDER BY t.detected_at DESC, t.id DESC
               LIMIT $8"#
        );
        // AssertSqlSafe: the only interpolated value is `clause`, rendered by
        // build_member_visibility_clause from fixed SQL fragments — every
        // caller-controlled value travels as a bind parameter ($1..$8).
        let rows: Vec<TransitionRow> = sqlx::query_as(sqlx::AssertSqlSafe(&*sql))
            .bind(Option::<Uuid>::None) // $1 unused; the clause starts at $2
            .bind(user_bind)
            .bind(scope_bind)
            .bind(&filter.advisory_id)
            .bind(&filter.kind)
            .bind(filter.since)
            .bind(filter.until)
            .bind(limit)
            .fetch_all(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
        Ok(rows.into_iter().map(TransitionRow::into_model).collect())
    }

    /// The current affectedness state of one stored environment.
    pub async fn environment_advisories(
        &self,
        environment_id: Uuid,
    ) -> Result<Vec<AffectednessRecord>> {
        let rows: Vec<AffectednessRow> = sqlx::query_as(
            "SELECT environment_id, advisory_id, ecosystem, name, version, \
                    summary, severity, fixed_version, source_url, \
                    affected_since, last_evaluated_at \
             FROM environment_advisory_state \
             WHERE environment_id = $1 \
             ORDER BY advisory_id, name, version",
        )
        .bind(environment_id)
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
        Ok(rows.into_iter().map(AffectednessRow::into_model).collect())
    }
}

#[derive(sqlx::FromRow)]
struct StateRow {
    environment_id: Uuid,
    advisory_id: String,
    version: String,
    summary: Option<String>,
    severity: Option<String>,
    fixed_version: Option<String>,
    source_url: Option<String>,
}

#[derive(sqlx::FromRow)]
struct AffectednessRow {
    environment_id: Uuid,
    advisory_id: String,
    ecosystem: String,
    name: String,
    version: String,
    summary: Option<String>,
    severity: Option<String>,
    fixed_version: Option<String>,
    source_url: Option<String>,
    affected_since: DateTime<Utc>,
    last_evaluated_at: DateTime<Utc>,
}

impl AffectednessRow {
    fn into_model(self) -> AffectednessRecord {
        AffectednessRecord {
            environment_id: self.environment_id,
            advisory_id: self.advisory_id,
            ecosystem: self.ecosystem,
            name: self.name,
            version: self.version,
            summary: self.summary,
            severity: self.severity,
            fixed_version: self.fixed_version,
            source_url: self.source_url,
            affected_since: self.affected_since,
            last_evaluated_at: self.last_evaluated_at,
        }
    }
}

#[derive(sqlx::FromRow)]
struct TransitionRow {
    id: i64,
    environment_id: Uuid,
    environment_name: String,
    repository_id: Uuid,
    repository_key: String,
    advisory_id: String,
    ecosystem: String,
    name: String,
    version: String,
    kind: String,
    summary: Option<String>,
    severity: Option<String>,
    fixed_version: Option<String>,
    source_url: Option<String>,
    detected_at: DateTime<Utc>,
}

impl TransitionRow {
    fn into_model(self) -> TransitionRecord {
        TransitionRecord {
            id: self.id,
            environment_id: self.environment_id,
            environment_name: self.environment_name,
            repository_id: self.repository_id,
            repository_key: self.repository_key,
            advisory_id: self.advisory_id,
            ecosystem: self.ecosystem,
            name: self.name,
            version: self.version,
            kind: self.kind,
            summary: self.summary,
            severity: self.severity,
            fixed_version: self.fixed_version,
            source_url: self.source_url,
            detected_at: self.detected_at,
        }
    }
}

#[cfg(ak_test_shard = "services-1")]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::handlers::test_db_helpers as tdh;
    use crate::services::environment_service::EnvironmentService;
    use std::time::Duration;

    /// A pip package pinned across two platforms — the already-installed
    /// component a March scan found clean.
    ///
    /// Every test gets its OWN package name: a delta is evaluated against
    /// every stored environment containing the package, so two tests sharing
    /// a name would re-evaluate — and, with contradictory mock feed answers,
    /// rewrite — each other's state rows when nextest runs them in parallel.
    fn env_lockfile(pkg: &str) -> String {
        format!(
            r#"
version: 1
metadata:
  platforms:
    - linux-64
    - osx-arm64
package:
  - name: {pkg}
    version: 2.18.4
    manager: pip
    platform: linux-64
    dependencies: {{}}
  - name: {pkg}
    version: 2.18.4
    manager: pip
    platform: osx-arm64
    dependencies: {{}}
"#
        )
    }

    const ADVISORY_ID: &str = "GHSA-j8r2-6p8f-2345";

    fn advisory_body(ids: &[&str]) -> serde_json::Value {
        let vulns: Vec<serde_json::Value> = ids
            .iter()
            .map(|id| {
                serde_json::json!({
                    "id": id,
                    "summary": "requests smuggles headers",
                    "database_specific": { "severity": "HIGH" },
                    "aliases": ["CVE-2026-38041"],
                    "affected": [{
                        "ranges": [{
                            "type": "ECOSYSTEM",
                            "events": [{ "introduced": "0" }, { "fixed": "2.20.0" }]
                        }]
                    }]
                })
            })
            .collect();
        serde_json::json!({ "results": [{ "vulns": vulns }] })
    }

    /// Answers the batch positionally, the way OSV does: one result per
    /// query. A fixed single-result body would read as a SHORT answer for
    /// any batch larger than one, and a short answer is degraded by design
    /// (#4080) — a different fact from what these tests exercise.
    struct PerQuery {
        vulns: Vec<serde_json::Value>,
    }

    impl wiremock::Respond for PerQuery {
        fn respond(&self, request: &wiremock::Request) -> wiremock::ResponseTemplate {
            let body: serde_json::Value =
                serde_json::from_slice(&request.body).unwrap_or(serde_json::json!({}));
            let n = body["queries"].as_array().map(Vec::len).unwrap_or(0);
            let results: Vec<serde_json::Value> = (0..n)
                .map(|_| serde_json::json!({ "vulns": self.vulns }))
                .collect();
            wiremock::ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({ "results": results }))
        }
    }

    async fn mount_osv(server: &wiremock::MockServer, body: serde_json::Value) {
        use wiremock::matchers::{method, path};
        use wiremock::Mock;
        let vulns = body["results"][0]["vulns"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        Mock::given(method("POST"))
            .and(path("/v1/querybatch"))
            .respond_with(PerQuery { vulns })
            .mount(server)
            .await;
    }

    fn test_service(pool: PgPool, osv_url: &str) -> EnvironmentReevalService {
        // A 1ms cache TTL keeps every evaluation honest: each process_delta
        // re-asks the (mock) feed rather than replaying the previous phase's
        // cached answer, which is exactly what a withdrawal test needs.
        let advisory = Arc::new(AdvisoryClient::for_test(
            format!("{osv_url}/v1/querybatch"),
            Duration::from_millis(1),
        ));
        EnvironmentReevalService::new(pool, advisory, Arc::new(EventBus::new(16)))
    }

    async fn ingest_requests(pool: &PgPool, repo_id: Uuid, pkg: &str) -> Uuid {
        let env = crate::services::environment_lock::parse_named_lockfile(
            "conda-lock.yml",
            env_lockfile(pkg).as_bytes(),
        )
        .expect("fixture lockfile parses");
        EnvironmentService::new(pool.clone())
            .ingest(repo_id, pkg, &format!("sha256-{pkg}"), &env)
            .await
            .expect("ingest")
            .id
    }

    async fn transition_kinds(pool: &PgPool, environment_id: Uuid) -> Vec<String> {
        sqlx::query_scalar(
            "SELECT kind FROM environment_advisory_transitions \
             WHERE environment_id = $1 ORDER BY id",
        )
        .bind(environment_id)
        .fetch_all(pool)
        .await
        .expect("transitions")
    }

    /// The acceptance test: an advisory published against an ALREADY-STORED
    /// component marks the environment affected, with no artifact, lockfile
    /// or environment row changing.
    #[tokio::test]
    async fn new_advisory_marks_stored_environment_affected() {
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let pkg = "req4055-new";
        let env_id = ingest_requests(&fx.pool, fx.repo_id, pkg).await;
        let env_before: (DateTime<Utc>,) =
            sqlx::query_as("SELECT updated_at FROM environments WHERE id = $1")
                .bind(env_id)
                .fetch_one(&fx.pool)
                .await
                .expect("environment row");

        let server = wiremock::MockServer::start().await;
        mount_osv(&server, advisory_body(&[ADVISORY_ID])).await;
        let svc = test_service(fx.pool.clone(), &server.uri());

        let outcome = svc
            .process_delta(&AdvisoryDelta {
                ecosystem: "PyPI".to_string(),
                name: pkg.to_string(),
                advisory_ids: vec![ADVISORY_ID.to_string()],
            })
            .await
            .expect("process delta");

        assert!(!outcome.skipped && !outcome.degraded, "{outcome:?}");
        // Global counts are lower bounds: the shared test DB may hold other
        // suites' `requests` environments, which this delta legitimately
        // evaluates too. The EXACT assertions are scoped to this fixture's
        // environment below — one transition for one environment, not per
        // platform.
        assert!(outcome.environments_evaluated >= 1, "{outcome:?}");
        assert!(outcome.new_affected >= 1, "{outcome:?}");

        let state = svc
            .environment_advisories(env_id)
            .await
            .expect("state read");
        assert_eq!(state.len(), 1, "{state:?}");
        assert_eq!(state[0].advisory_id, ADVISORY_ID);
        assert_eq!(state[0].version, "2.18.4");
        assert_eq!(state[0].severity.as_deref(), Some("high"));
        assert_eq!(state[0].fixed_version.as_deref(), Some("2.20.0"));

        assert_eq!(
            transition_kinds(&fx.pool, env_id).await,
            vec![TRANSITION_NEW_AFFECTED.to_string()],
        );

        // Steady state is not an event (#4088): re-processing the same
        // advisory data records NOTHING new.
        let again = svc
            .process_delta(&AdvisoryDelta {
                ecosystem: "PyPI".to_string(),
                name: pkg.to_string(),
                advisory_ids: vec![ADVISORY_ID.to_string()],
            })
            .await
            .expect("reprocess");
        // Steady state records nothing new FOR THIS ENVIRONMENT — the
        // mutation check (#4088): the transition log, not the outcome
        // counters, is the surface that must stay silent.
        assert_eq!(
            transition_kinds(&fx.pool, env_id).await,
            vec![TRANSITION_NEW_AFFECTED.to_string()],
            "steady state must not emit transitions: {again:?}"
        );

        // The environment itself was not touched: re-evaluation is a match
        // against the stored component set, not a write to the environment.
        let env_after: (DateTime<Utc>,) =
            sqlx::query_as("SELECT updated_at FROM environments WHERE id = $1")
                .bind(env_id)
                .fetch_one(&fx.pool)
                .await
                .expect("environment row");
        assert_eq!(env_before, env_after);

        fx.teardown().await;
    }

    /// A delta for a package in NO environment touches no rows — the cost
    /// and the effect both scale with the delta, never with the environment
    /// count.
    #[tokio::test]
    async fn advisory_for_absent_package_touches_no_rows() {
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let pkg = "req4055-absent";
        let env_id = ingest_requests(&fx.pool, fx.repo_id, pkg).await;

        let server = wiremock::MockServer::start().await;
        mount_osv(&server, advisory_body(&[ADVISORY_ID])).await;
        let svc = test_service(fx.pool.clone(), &server.uri());

        // Establish affected state for requests first, so the test proves
        // the absent-package delta leaves EXISTING rows alone too.
        svc.process_delta(&AdvisoryDelta {
            ecosystem: "PyPI".to_string(),
            name: pkg.to_string(),
            advisory_ids: vec![ADVISORY_ID.to_string()],
        })
        .await
        .expect("process requests delta");

        let outcome = svc
            .process_delta(&AdvisoryDelta {
                ecosystem: "PyPI".to_string(),
                name: "not-installed-anywhere".to_string(),
                advisory_ids: vec!["GHSA-aaaa-bbbb-cccc".to_string()],
            })
            .await
            .expect("process absent delta");
        assert_eq!(outcome.environments_evaluated, 0, "{outcome:?}");
        assert_eq!(outcome.new_affected, 0, "{outcome:?}");
        assert_eq!(outcome.no_longer_affected, 0, "{outcome:?}");

        // The requests state survived: delta scoping is real.
        let state = svc
            .environment_advisories(env_id)
            .await
            .expect("state read");
        assert_eq!(state.len(), 1, "{state:?}");
        assert_eq!(state[0].name, pkg);
        assert_eq!(
            transition_kinds(&fx.pool, env_id).await,
            vec![TRANSITION_NEW_AFFECTED.to_string()],
        );
        fx.teardown().await;
    }

    /// The feed stops naming the advisory for the stored version (withdrawn,
    /// or its fixed range shifted past 2.18.4 — the two render identically
    /// in the feed answer): a `no-longer-affected` transition, not silence
    /// and not a lingering state row.
    #[tokio::test]
    async fn withdrawn_advisory_records_no_longer_affected_transition() {
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let pkg = "req4055-withdrawn";
        let env_id = ingest_requests(&fx.pool, fx.repo_id, pkg).await;

        let server = wiremock::MockServer::start().await;
        mount_osv(&server, advisory_body(&[ADVISORY_ID])).await;
        let svc = test_service(fx.pool.clone(), &server.uri());

        svc.process_delta(&AdvisoryDelta {
            ecosystem: "PyPI".to_string(),
            name: pkg.to_string(),
            advisory_ids: vec![ADVISORY_ID.to_string()],
        })
        .await
        .expect("affected phase");
        assert_eq!(svc.environment_advisories(env_id).await.unwrap().len(), 1);

        // The feed's answer changes: the advisory no longer covers 2.18.4.
        // A fresh server AND a fresh client: the 1ms cache TTL makes the
        // second evaluation re-ask rather than replay, and a new mock server
        // sidesteps any question of mounted-mock precedence.
        let server2 = wiremock::MockServer::start().await;
        mount_osv(&server2, advisory_body(&[])).await;
        let svc = test_service(fx.pool.clone(), &server2.uri());
        let outcome = svc
            .process_delta(&AdvisoryDelta {
                ecosystem: "PyPI".to_string(),
                name: pkg.to_string(),
                advisory_ids: vec![],
            })
            .await
            .expect("withdrawn phase");

        assert!(outcome.no_longer_affected >= 1, "{outcome:?}");
        assert_eq!(outcome.new_affected, 0, "{outcome:?}");
        assert!(
            svc.environment_advisories(env_id).await.unwrap().is_empty(),
            "state row must be gone"
        );
        assert_eq!(
            transition_kinds(&fx.pool, env_id).await,
            vec![
                TRANSITION_NEW_AFFECTED.to_string(),
                TRANSITION_NO_LONGER_AFFECTED.to_string(),
            ],
        );
        fx.teardown().await;
    }

    /// The queue drain: a degraded feed leaves the delta pending (attempts
    /// bounded); a healthy answer marks it processed.
    #[tokio::test]
    async fn degraded_feed_retries_then_gives_up() {
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let pkg = "req4055-degraded";
        ingest_requests(&fx.pool, fx.repo_id, pkg).await;
        // Deterministic drain counts: a crashed earlier run may have left
        // this package's delta row behind.
        sqlx::query("DELETE FROM advisory_deltas WHERE ecosystem = 'PyPI' AND name = $1")
            .bind(pkg)
            .execute(&fx.pool)
            .await
            .expect("clean delta row");

        let sink = DbAdvisoryDeltaSink::new(fx.pool.clone());
        sink.record(AdvisoryDelta {
            ecosystem: "PyPI".to_string(),
            name: pkg.to_string(),
            advisory_ids: vec![ADVISORY_ID.to_string()],
        })
        .await;

        let server = wiremock::MockServer::start().await;
        // No mock mounted: every query is a 404, i.e. unanswered, i.e.
        // degraded — nothing may be recorded as clean.
        let svc = test_service(fx.pool.clone(), &server.uri());
        let processed = svc.process_pending_deltas(10).await.expect("drain");
        assert_eq!(processed, 0);
        let (attempts, processed_at): (i32, Option<DateTime<Utc>>) = sqlx::query_as(
            "SELECT attempts, processed_at FROM advisory_deltas \
             WHERE ecosystem = 'PyPI' AND name = $1",
        )
        .bind(pkg)
        .fetch_one(&fx.pool)
        .await
        .expect("delta row");
        assert_eq!(attempts, 1);
        assert!(processed_at.is_none(), "degraded stays pending");

        // Exhaust the retry budget: the delta is given up on, not wedged.
        sqlx::query(
            "UPDATE advisory_deltas SET attempts = $1 WHERE ecosystem = 'PyPI' AND name = $2",
        )
        .bind(MAX_DELTA_ATTEMPTS - 1)
        .bind(pkg)
        .execute(&fx.pool)
        .await
        .expect("seed attempts");
        svc.process_pending_deltas(10).await.expect("drain");
        let processed_at: Option<DateTime<Utc>> = sqlx::query_scalar(
            "SELECT processed_at FROM advisory_deltas WHERE ecosystem = 'PyPI' AND name = $1",
        )
        .bind(pkg)
        .fetch_one(&fx.pool)
        .await
        .expect("delta row");
        assert!(
            processed_at.is_some(),
            "retry budget exhausted -> processed"
        );

        // A healthy answer on a fresh delta processes it.
        sink.record(AdvisoryDelta {
            ecosystem: "PyPI".to_string(),
            name: pkg.to_string(),
            advisory_ids: vec![ADVISORY_ID.to_string()],
        })
        .await;
        mount_osv(&server, advisory_body(&[ADVISORY_ID])).await;
        let processed = svc.process_pending_deltas(10).await.expect("drain");
        assert_eq!(processed, 1);
        fx.teardown().await;
    }

    /// A delta keyed on an ecosystem no feed serves for stored environments
    /// is processed as a skip: no lookup, no error, no pending row left.
    #[tokio::test]
    async fn unsupported_ecosystem_delta_is_skipped() {
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        ingest_requests(&fx.pool, fx.repo_id, "req4055-skip").await;
        let svc = test_service(fx.pool.clone(), "http://127.0.0.1:1");
        let outcome = svc
            .process_delta(&AdvisoryDelta {
                ecosystem: "conda".to_string(),
                name: "requests".to_string(),
                advisory_ids: vec![],
            })
            .await
            .expect("skip is not an error");
        assert!(outcome.skipped, "{outcome:?}");
        assert_eq!(outcome.environments_evaluated, 0);
        fx.teardown().await;
    }

    /// The delta-path lookup can run as an index scan over the (ecosystem,
    /// name) identity index, not a scan over environments. Mirrors #4054's
    /// EXPLAIN fence for the purl_base index — sequential scan disabled, so
    /// the assertion is about the index being *usable for this predicate*,
    /// not about the planner's row-count estimate on a test-sized table.
    #[tokio::test]
    async fn delta_lookup_uses_identity_index() {
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        ingest_requests(&fx.pool, fx.repo_id, "req4055-explain").await;
        let mut tx = fx.pool.begin().await.expect("tx");
        sqlx::query("SET LOCAL enable_seqscan = off")
            .execute(&mut *tx)
            .await
            .expect("seqscan off");
        let plans: Vec<String> = sqlx::query_scalar(
            "EXPLAIN SELECT DISTINCT environment_id, version FROM environment_packages \
             WHERE ecosystem = 'pypi' AND name = 'requests' AND version IS NOT NULL",
        )
        .fetch_all(&mut *tx)
        .await
        .expect("explain");
        tx.rollback().await.expect("rollback");
        let plan_text = plans.join("\n");
        assert!(
            plan_text.contains("idx_environment_packages_identity"),
            "delta lookup must use the identity index, got:\n{plan_text}"
        );
        fx.teardown().await;
    }

    /// Transitions are listable with since/until scoping and honour the
    /// repository visibility rule.
    #[tokio::test]
    async fn transitions_listing_scopes_by_time_and_visibility() {
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let pkg = "req4055-listing";
        let env_id = ingest_requests(&fx.pool, fx.repo_id, pkg).await;
        let server = wiremock::MockServer::start().await;
        mount_osv(&server, advisory_body(&[ADVISORY_ID])).await;
        let svc = test_service(fx.pool.clone(), &server.uri());
        svc.process_delta(&AdvisoryDelta {
            ecosystem: "PyPI".to_string(),
            name: pkg.to_string(),
            advisory_ids: vec![ADVISORY_ID.to_string()],
        })
        .await
        .expect("process");

        let all = svc
            .list_transitions(&MemberVisibility::Unfiltered, &TransitionFilter::default())
            .await
            .expect("list");
        let mine: Vec<_> = all.iter().filter(|t| t.environment_id == env_id).collect();
        assert_eq!(mine.len(), 1, "{mine:?}");
        assert_eq!(mine[0].kind, TRANSITION_NEW_AFFECTED);
        assert_eq!(mine[0].repository_id, fx.repo_id);

        // since in the future / until in the past both exclude the row.
        let future = svc
            .list_transitions(
                &MemberVisibility::Unfiltered,
                &TransitionFilter {
                    since: Some(Utc::now() + chrono::Duration::hours(1)),
                    ..Default::default()
                },
            )
            .await
            .expect("list");
        assert!(future.iter().all(|t| t.environment_id != env_id));
        let past = svc
            .list_transitions(
                &MemberVisibility::Unfiltered,
                &TransitionFilter {
                    until: Some(Utc::now() - chrono::Duration::hours(1)),
                    ..Default::default()
                },
            )
            .await
            .expect("list");
        assert!(past.iter().all(|t| t.environment_id != env_id));

        // Advisory filter.
        let by_advisory = svc
            .list_transitions(
                &MemberVisibility::Unfiltered,
                &TransitionFilter {
                    advisory_id: Some(ADVISORY_ID.to_string()),
                    ..Default::default()
                },
            )
            .await
            .expect("list");
        assert!(by_advisory.iter().any(|t| t.environment_id == env_id));
        let other_advisory = svc
            .list_transitions(
                &MemberVisibility::Unfiltered,
                &TransitionFilter {
                    advisory_id: Some("GHSA-zzzz".to_string()),
                    ..Default::default()
                },
            )
            .await
            .expect("list");
        assert!(other_advisory.iter().all(|t| t.environment_id != env_id));

        // A non-member of the fixture's repository sees nothing about it.
        let Some(stranger) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let stranger_view = svc
            .list_transitions(
                &MemberVisibility::Principal {
                    user_id: stranger.user_id,
                    is_admin: false,
                    allowed_repo_ids: None,
                },
                &TransitionFilter::default(),
            )
            .await
            .expect("list");
        assert!(
            stranger_view.iter().all(|t| t.environment_id != env_id),
            "a non-member must not see the transition: {stranger_view:?}"
        );

        fx.teardown().await;
        stranger.teardown().await;
    }

    #[test]
    fn ecosystem_mapping_round_trips() {
        assert_eq!(stored_ecosystem("PyPI"), Some(Ecosystem::PyPi));
        assert_eq!(stored_ecosystem("npm"), Some(Ecosystem::Npm));
        assert_eq!(stored_ecosystem("crates.io"), Some(Ecosystem::Cargo));
        assert_eq!(stored_ecosystem("conda"), None);
        assert_eq!(stored_ecosystem("*"), None);
        for feed in ["PyPI", "npm", "crates.io"] {
            let stored = stored_ecosystem(feed).expect("mapped");
            assert_eq!(feed_ecosystem(stored), Some(feed));
        }
    }

    #[test]
    fn pypi_names_normalise_the_way_ingest_normalised_them() {
        // An advisory names "Zope.Interface"; the stored row is PEP-503
        // normalised. The delta lookup must normalise with the same rule.
        let eco = stored_ecosystem("PyPI").unwrap();
        assert_eq!(eco.normalize("Zope.Interface"), "zope-interface");
    }
}
