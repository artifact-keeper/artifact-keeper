//! Scheduled retention for CI build records (artifact-keeper-web#618)
//!
//! Two system settings, both off (0) by default and read on every pass:
//!
//! - `build_retention_days`: a build whose `finished_at` (or `created_at`
//!   while it never finished) is older than this many days is deleted. A
//!   `running` or `pending` build that old is stale and goes too
//! - `build_retention_keep_last`: per build name, only the newest this many
//!   builds (by build number) are kept. Builds still `running` or `pending`
//!   are never deleted by this rule
//!
//! A build matching either rule is deleted. Only the records go, with their
//! `build_artifacts` rows (`ON DELETE CASCADE`), the artifacts in
//! repositories are not touched. The pass is the `audit_retention` one: hourly,
//! one replica at a time under a scheduler lease, oldest first in batches of
//! [`BUILD_RETENTION_BATCH_SIZE`], one summary log line per pass

use sqlx::{PgConnection, PgExecutor, PgPool};
use tokio_util::sync::CancellationToken;

use crate::error::{AppError, Result};
use crate::services::audit_retention::retention_days_from_setting;

/// The `system_settings` key holding the age limit in days
pub const BUILD_RETENTION_DAYS_SETTING: &str = "build_retention_days";
/// The `system_settings` key holding how many builds to keep per name
pub const BUILD_RETENTION_KEEP_LAST_SETTING: &str = "build_retention_keep_last";
/// Scheduler lease name, one replica runs a pass at a time
pub const BUILD_RETENTION_LEASE_NAME: &str = "build_retention";
/// Lease TTL, renewed for as long as a pass runs
pub const BUILD_RETENTION_LEASE_TTL_SECS: f64 = 600.0;
/// How often the pass runs
pub const BUILD_RETENTION_INTERVAL_SECS: u64 = 3600;
/// Builds deleted per statement
pub const BUILD_RETENTION_BATCH_SIZE: i64 = 5000;

/// The limits in force, `None` for a rule that is off
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct BuildRetentionPolicy {
    pub days: Option<i32>,
    pub keep_last: Option<i32>,
}

impl BuildRetentionPolicy {
    pub fn is_off(&self) -> bool {
        self.days.is_none() && self.keep_last.is_none()
    }
}

/// Largest age limit the pass applies, the settings API's own bound. A
/// larger value stored by hand would put the cutoff before the earliest
/// timestamp Postgres can hold and fail every pass
pub const BUILD_RETENTION_MAX_DAYS: i32 = 36_500;

/// Read both settings. A missing, zero, negative or non-numeric value turns
/// its rule off, an age above [`BUILD_RETENTION_MAX_DAYS`] is read as that
pub async fn configured_policy(db: impl PgExecutor<'_>) -> Result<BuildRetentionPolicy> {
    let rows: Vec<(String, serde_json::Value)> =
        sqlx::query_as("SELECT key, value FROM system_settings WHERE key = ANY($1)")
            .bind([
                BUILD_RETENTION_DAYS_SETTING,
                BUILD_RETENTION_KEEP_LAST_SETTING,
            ])
            .fetch_all(db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
    let value = |key: &str| {
        rows.iter()
            .find(|(k, _)| k == key)
            .and_then(|(_, v)| retention_days_from_setting(Some(v)))
    };
    Ok(BuildRetentionPolicy {
        days: value(BUILD_RETENTION_DAYS_SETTING).map(|d| d.min(BUILD_RETENTION_MAX_DAYS)),
        keep_last: value(BUILD_RETENTION_KEEP_LAST_SETTING),
    })
}

/// The outcome of one retention pass
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct BuildRetentionReport {
    pub policy: BuildRetentionPolicy,
    /// Builds deleted by `build_retention_days`
    pub deleted_by_age: u64,
    /// Builds deleted by `build_retention_keep_last`
    pub deleted_by_count: u64,
    pub batches: u32,
    /// The pass stopped early because the scheduler lease was lost
    pub interrupted: bool,
}

const DELETE_BY_AGE: &str = "DELETE FROM builds WHERE id IN ( \
     SELECT id FROM builds \
     WHERE COALESCE(finished_at, created_at) < NOW() - make_interval(days => $1) \
     ORDER BY created_at \
     LIMIT $2)";

const DELETE_BY_COUNT: &str = "DELETE FROM builds WHERE id IN ( \
     SELECT id FROM ( \
         SELECT id, status, created_at, \
                row_number() OVER (PARTITION BY name \
                                   ORDER BY build_number DESC, created_at DESC, id DESC) AS rank \
         FROM builds) ranked \
     WHERE rank > $1 AND status IN ('success', 'failed', 'cancelled') \
     ORDER BY created_at \
     LIMIT $2)";

/// Apply `policy`: delete the matching builds in batches of `batch_size`,
/// oldest first, until none are left or `lost` is cancelled
pub async fn apply_retention(
    db: &mut PgConnection,
    policy: BuildRetentionPolicy,
    batch_size: i64,
    lost: Option<&CancellationToken>,
) -> Result<BuildRetentionReport> {
    let mut report = BuildRetentionReport {
        policy,
        ..Default::default()
    };
    let batch_size = batch_size.max(1);
    let rules = [
        (policy.days, DELETE_BY_AGE),
        (policy.keep_last, DELETE_BY_COUNT),
    ];
    for (index, (limit, sql)) in rules.into_iter().enumerate() {
        let Some(limit) = limit else { continue };
        loop {
            if lost.is_some_and(CancellationToken::is_cancelled) {
                report.interrupted = true;
                return Ok(report);
            }
            let deleted = sqlx::query(sql)
                .bind(limit)
                .bind(batch_size)
                .execute(&mut *db)
                .await
                .map_err(|e| AppError::Database(e.to_string()))?
                .rows_affected();
            if index == 0 {
                report.deleted_by_age += deleted;
            } else {
                report.deleted_by_count += deleted;
            }
            report.batches += 1;
            if deleted < batch_size as u64 {
                break;
            }
        }
    }
    Ok(report)
}

/// One scheduled pass under `policy`: take the scheduler lease, apply the
/// policy while the lease is renewed, record and log the result. `None` when
/// another replica holds the lease
pub async fn run_pass(
    db: &PgPool,
    policy: BuildRetentionPolicy,
) -> Result<Option<BuildRetentionReport>> {
    let Some(lease) = crate::services::cluster_work::try_acquire_scheduler_lease_quiet(
        db,
        BUILD_RETENTION_LEASE_NAME,
        BUILD_RETENTION_LEASE_TTL_SECS,
    )
    .await
    else {
        tracing::debug!("Another replica owns the build retention lease");
        return Ok(None);
    };
    let (renewal, lost) =
        lease.spawn_renewal_with_cancellation(db.clone(), BUILD_RETENTION_LEASE_TTL_SECS);
    let result = match db.acquire().await {
        Ok(mut conn) => {
            apply_retention(&mut conn, policy, BUILD_RETENTION_BATCH_SIZE, Some(&lost)).await
        }
        Err(e) => Err(AppError::Database(e.to_string())),
    };
    drop(renewal);
    lease.release(db).await;
    let report = result?;
    crate::services::metrics_service::record_cleanup(
        "builds",
        report.deleted_by_age + report.deleted_by_count,
    );
    tracing::info!(
        retention_days = policy.days,
        keep_last = policy.keep_last,
        deleted_by_age = report.deleted_by_age,
        deleted_by_count = report.deleted_by_count,
        batches = report.batches,
        interrupted = report.interrupted,
        "Build retention pass"
    );
    Ok(Some(report))
}

/// The startup line stating the limits in force
pub fn startup_message(policy: BuildRetentionPolicy) -> String {
    if policy.is_off() {
        return format!(
            "Build retention is off: system settings {BUILD_RETENTION_DAYS_SETTING} and \
             {BUILD_RETENTION_KEEP_LAST_SETTING} are not set to a positive number, so build \
             records are kept until deleted"
        );
    }
    let mut rules = Vec::new();
    if let Some(days) = policy.days {
        rules.push(format!("older than {days} days"));
    }
    if let Some(keep) = policy.keep_last {
        rules.push(format!("beyond the newest {keep} per build name"));
    }
    format!(
        "Build retention: build records {} are deleted every hour",
        rules.join(" or ")
    )
}

#[cfg(ak_test_shard = "services-1")]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::handlers::test_db_helpers as tdh;
    use uuid::Uuid;

    #[test]
    fn startup_message_names_each_rule_or_says_off() {
        assert!(startup_message(BuildRetentionPolicy::default()).contains("off"));
        let both = startup_message(BuildRetentionPolicy {
            days: Some(30),
            keep_last: Some(5),
        });
        assert!(both.contains("older than 30 days"), "{both}");
        assert!(both.contains("newest 5 per build name"), "{both}");
        let days = startup_message(BuildRetentionPolicy {
            days: Some(7),
            keep_last: None,
        });
        assert!(!days.contains("newest"), "{days}");
    }

    /// Seed one build of `name`, `number`, created and finished `age_days` ago
    async fn seed(
        pool: &mut PgConnection,
        name: &str,
        number: i32,
        status: &str,
        age_days: i32,
    ) -> Uuid {
        sqlx::query_scalar(
            "INSERT INTO builds (name, build_number, status, created_at, finished_at) \
             VALUES ($1, $2, $3, NOW() - make_interval(days => $4), \
                     CASE WHEN $3 IN ('running', 'pending') THEN NULL \
                          ELSE NOW() - make_interval(days => $4) END) \
             RETURNING id",
        )
        .bind(name)
        .bind(number)
        .bind(status)
        .bind(age_days)
        .fetch_one(&mut *pool)
        .await
        .expect("seed build")
    }

    async fn surviving(pool: &mut PgConnection, prefix: &str) -> Vec<(String, i32)> {
        sqlx::query_as(
            "SELECT name, build_number FROM builds WHERE name LIKE $1 ORDER BY name, build_number",
        )
        .bind(format!("{prefix}%"))
        .fetch_all(&mut *pool)
        .await
        .expect("surviving builds")
    }

    async fn settings(pool: &mut PgConnection, days: Option<i64>, keep: Option<i64>) {
        for (key, value) in [
            (BUILD_RETENTION_DAYS_SETTING, days),
            (BUILD_RETENTION_KEEP_LAST_SETTING, keep),
        ] {
            match value {
                Some(v) => sqlx::query(
                    "INSERT INTO system_settings (key, value) VALUES ($1, $2) \
                     ON CONFLICT (key) DO UPDATE SET value = $2",
                )
                .bind(key)
                .bind(serde_json::json!(v))
                .execute(&mut *pool)
                .await
                .expect("set"),
                None => sqlx::query("DELETE FROM system_settings WHERE key = $1")
                    .bind(key)
                    .execute(&mut *pool)
                    .await
                    .expect("unset"),
            };
        }
    }

    /// The age rule deletes builds that finished (or, unfinished, were
    /// created) before the limit, the count rule keeps the newest N finished
    /// builds per name and never a running one, and the artifact rows go with
    /// their build
    #[tokio::test]
    async fn deletes_by_age_and_by_count_and_keeps_the_rest() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        // Retention is instance-wide, so the test runs in a transaction it
        // rolls back: other tests' builds and settings are never touched
        let mut tx = pool.begin().await.expect("begin");
        let pool = &mut *tx;
        let p = format!("ph-618-ret-{}", Uuid::new_v4());
        let (a, b) = (format!("{p}-a"), format!("{p}-b"));
        // a: 1 old success, 2 old stale running, 3..6 recent
        let old = seed(pool, &a, 1, "success", 400).await;
        seed(pool, &a, 2, "running", 400).await;
        seed(pool, &a, 3, "failed", 3).await;
        seed(pool, &a, 4, "success", 2).await;
        seed(pool, &a, 5, "running", 1).await;
        seed(pool, &a, 6, "success", 0).await;
        // b: two recent, under the count
        seed(pool, &b, 1, "success", 1).await;
        seed(pool, &b, 2, "success", 0).await;
        sqlx::query(
            "INSERT INTO build_artifacts (build_id, name, path, checksum_sha256, size_bytes) \
             VALUES ($1, 'x.jar', 'dist/x.jar', $2, 1)",
        )
        .bind(old)
        .bind("0".repeat(64))
        .execute(&mut *pool)
        .await
        .expect("artifact");

        let report = apply_retention(
            pool,
            BuildRetentionPolicy {
                days: Some(365),
                keep_last: None,
            },
            1,
            None,
        )
        .await
        .expect("age pass");
        assert!(report.deleted_by_age >= 2, "{report:?}");
        assert_eq!(
            surviving(pool, &p).await,
            [
                (a.clone(), 3),
                (a.clone(), 4),
                (a.clone(), 5),
                (a.clone(), 6),
                (b.clone(), 1),
                (b.clone(), 2),
            ]
        );
        let artifacts: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM build_artifacts WHERE build_id = $1")
                .bind(old)
                .fetch_one(&mut *pool)
                .await
                .expect("count");
        assert_eq!(artifacts, 0);

        // keep 2 per name: a keeps 6 and 5 by number, 5 is running anyway,
        // 4 and 3 go. b keeps both
        let report = apply_retention(
            pool,
            BuildRetentionPolicy {
                days: None,
                keep_last: Some(2),
            },
            BUILD_RETENTION_BATCH_SIZE,
            None,
        )
        .await
        .expect("count pass");
        assert!(report.deleted_by_count >= 2, "{report:?}");
        assert_eq!(
            surviving(pool, &p).await,
            [
                (a.clone(), 5),
                (a.clone(), 6),
                (b.clone(), 1),
                (b.clone(), 2)
            ]
        );

        // keep 1: a's running 5 is newest but one, it stays
        apply_retention(
            pool,
            BuildRetentionPolicy {
                days: None,
                keep_last: Some(1),
            },
            BUILD_RETENTION_BATCH_SIZE,
            None,
        )
        .await
        .expect("count pass");
        assert_eq!(
            surviving(pool, &p).await,
            [(a.clone(), 5), (a.clone(), 6), (b.clone(), 2)]
        );

        tx.rollback().await.expect("rollback");
    }

    /// Both settings off delete nothing, a lost lease stops the pass before
    /// it deletes, and the settings are read as stored
    #[tokio::test]
    async fn off_or_lost_lease_deletes_nothing_and_settings_are_read() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        // Retention is instance-wide, so the test runs in a transaction it
        // rolls back: other tests' builds and settings are never touched
        let mut tx = pool.begin().await.expect("begin");
        let pool = &mut *tx;
        let p = format!("ph-618-ret-off-{}", Uuid::new_v4());
        seed(pool, &p, 1, "success", 4000).await;

        let off = apply_retention(pool, BuildRetentionPolicy::default(), 10, None)
            .await
            .expect("off");
        assert_eq!(off, BuildRetentionReport::default());
        let lost = CancellationToken::new();
        lost.cancel();
        let interrupted = apply_retention(
            pool,
            BuildRetentionPolicy {
                days: Some(1),
                keep_last: None,
            },
            10,
            Some(&lost),
        )
        .await
        .expect("lost");
        assert!(interrupted.interrupted);
        assert_eq!(surviving(pool, &p).await, [(p.clone(), 1)]);

        settings(pool, Some(30), Some(0)).await;
        assert_eq!(
            configured_policy(&mut *pool).await.expect("read"),
            BuildRetentionPolicy {
                days: Some(30),
                keep_last: None,
            }
        );
        settings(pool, None, Some(3)).await;
        assert_eq!(
            configured_policy(&mut *pool).await.expect("read"),
            BuildRetentionPolicy {
                days: None,
                keep_last: Some(3),
            }
        );
        settings(pool, None, None).await;
        assert!(configured_policy(&mut *pool).await.expect("read").is_off());

        // A hand-set age past what a timestamp can reach is read as the API's
        // upper bound, so the pass runs instead of failing on the cutoff
        settings(pool, Some(3_000_000), None).await;
        let huge = configured_policy(&mut *pool).await.expect("read");
        assert_eq!(huge.days, Some(BUILD_RETENTION_MAX_DAYS));
        apply_retention(pool, huge, 10, None)
            .await
            .expect("pass with a clamped age");
        assert_eq!(surviving(pool, &p).await, [(p.clone(), 1)]);

        tx.rollback().await.expect("rollback");
    }

    /// A scheduled pass deletes what the policy matches and releases its
    /// lease, and skips while another replica holds the lease
    #[tokio::test]
    async fn run_pass_applies_under_the_lease_and_skips_a_held_one() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        // The pass is instance-wide, so the policy only matches builds older
        // than 100 years, which no other test seeds
        let policy = BuildRetentionPolicy {
            days: Some(36500),
            keep_last: None,
        };
        let p = format!("ph-618-ret-pass-{}", Uuid::new_v4());
        let mut conn = pool.acquire().await.expect("conn");
        seed(&mut conn, &p, 1, "success", 40000).await;
        seed(&mut conn, &p, 2, "success", 0).await;

        let other = crate::services::cluster_work::try_acquire_scheduler_lease(
            &pool,
            BUILD_RETENTION_LEASE_NAME,
            &format!("other-replica-{p}"),
            60.0,
        )
        .await
        .expect("claim")
        .expect("lease free");
        assert_eq!(run_pass(&pool, policy).await.expect("held"), None);
        assert_eq!(
            surviving(&mut conn, &p).await,
            [(p.clone(), 1), (p.clone(), 2)]
        );
        other.release(&pool).await;

        let report = run_pass(&pool, policy)
            .await
            .expect("pass")
            .expect("lease taken");
        assert!(report.deleted_by_age >= 1, "{report:?}");
        assert!(!report.interrupted, "{report:?}");
        assert_eq!(surviving(&mut conn, &p).await, [(p.clone(), 2)]);
        // released, so the next pass takes it again
        assert!(run_pass(&pool, policy).await.expect("again").is_some());

        sqlx::query("DELETE FROM builds WHERE name = $1")
            .bind(&p)
            .execute(&mut *conn)
            .await
            .expect("cleanup");
    }
}
