//! Scheduled retention for the download statistics tables (#4541).
//!
//! `download_statistics` (hosted serves) and `proxy_download_statistics`
//! (proxy serves) get one row per download and, since #4540 stopped proxy
//! history from being deleted with its cache entry, neither shrinks except on
//! repository delete. This pass bounds them:
//!
//! - `DOWNLOAD_STATS_RETENTION_DAYS` set to a positive number of days turns it
//!   on. Unset, zero, negative or not a number leaves it off, which is the
//!   default: nothing is deleted unless a period was explicitly configured.
//! - Rows whose `downloaded_at` is older than the period are deleted in
//!   batches of [`DOWNLOAD_STATS_RETENTION_BATCH_SIZE`], one short statement
//!   each, so a large backlog never holds one long transaction or lock.
//! - It runs every `DOWNLOAD_STATS_RETENTION_INTERVAL_SECS` (default one hour,
//!   at least [`MIN_INTERVAL_SECS`]), on one replica at a time (scheduler
//!   lease, renewed for the whole pass); a lost lease stops the pass between
//!   batches.
//!
//! What the period costs: every figure computed from these rows forgets
//! downloads older than it. That is the per-artifact and per-path download
//! counts, the download trend and top-download views, the by-IP and
//! downloader lists, the `no_downloads_days` lifecycle predicate (a row older
//! than the period no longer protects its artifact or cache entry, which is
//! the same answer once the period is longer than the policy window) and the
//! blast-radius report's pull attribution. Keep the period at least as long as
//! the longest analytics window and `no_downloads_days` policy you rely on.
//! The daily `storage_metrics` snapshots already taken are not affected.

use sqlx::PgPool;
use tokio_util::sync::CancellationToken;

use crate::error::{AppError, Result};

/// Environment variable holding the retention period in days.
pub const RETENTION_DAYS_ENV: &str = "DOWNLOAD_STATS_RETENTION_DAYS";
/// Environment variable holding the pass interval in seconds.
pub const RETENTION_INTERVAL_ENV: &str = "DOWNLOAD_STATS_RETENTION_INTERVAL_SECS";
/// Scheduler lease name; one replica runs a pass at a time.
pub const DOWNLOAD_STATS_RETENTION_LEASE_NAME: &str = "download_stats_retention";
/// Lease TTL, renewed for as long as a pass runs.
pub const DOWNLOAD_STATS_RETENTION_LEASE_TTL_SECS: f64 = 600.0;
/// The default interval between passes.
pub const DEFAULT_INTERVAL_SECS: u64 = 3600;
/// The shortest interval accepted; a smaller value is raised to it.
pub const MIN_INTERVAL_SECS: u64 = 10;
/// Rows deleted per statement.
pub const DOWNLOAD_STATS_RETENTION_BATCH_SIZE: i64 = 5000;
/// The longest period accepted (about 1000 years); a larger value is lowered
/// to it. `NOW() - make_interval(days => n)` is out of the timestamp range for
/// an `n` near `i32::MAX`, which would fail every pass.
pub const MAX_RETENTION_DAYS: i32 = 365_000;

/// The tables a pass trims, in the order it trims them, each with its batch
/// statement.
///
/// Each picks its rows through the table's `downloaded_at` index (migrations
/// 313, 315), so a batch reads what it deletes and a batch with nothing to
/// delete reads a few index pages, plus the entries of rows already deleted
/// that vacuum has not removed yet. Two details of the statements serve that:
///
/// - `id = ANY (ARRAY(...))`: with `id IN (SELECT ...)`, a generic plan, which
///   a prepared statement can switch to, hash-joins the batch against a
///   sequential scan of the whole table, on every batch and with the index in
///   place.
/// - `ORDER BY downloaded_at`: the index is then the one cheap way to satisfy
///   the `LIMIT`, wherever expired rows sit in the heap, and the oldest rows go
///   first.
const RETAINED_TABLES: [(&str, &str); 2] = [
    (
        "download_statistics",
        "DELETE FROM download_statistics WHERE id = ANY (ARRAY( \
             SELECT id FROM download_statistics \
             WHERE downloaded_at < NOW() - make_interval(days => $1) \
             ORDER BY downloaded_at LIMIT $2))",
    ),
    (
        "proxy_download_statistics",
        "DELETE FROM proxy_download_statistics WHERE id = ANY (ARRAY( \
             SELECT id FROM proxy_download_statistics \
             WHERE downloaded_at < NOW() - make_interval(days => $1) \
             ORDER BY downloaded_at LIMIT $2))",
    ),
];

/// The retention period an environment value configures: `Some(days)` for a
/// positive integer (at most [`MAX_RETENTION_DAYS`]), `None` (retention off)
/// for anything else.
pub fn retention_days_from_value(value: Option<&str>) -> Option<i32> {
    value
        .and_then(|v| v.trim().parse::<i64>().ok())
        .filter(|days| *days > 0)
        .map(|days| days.min(i64::from(MAX_RETENTION_DAYS)) as i32)
}

/// The pass interval an environment value configures.
pub fn interval_secs_from_value(value: Option<&str>) -> u64 {
    value
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(DEFAULT_INTERVAL_SECS)
        .max(MIN_INTERVAL_SECS)
}

/// The configured retention period (`None` when retention is off).
pub fn retention_days_from_env() -> Option<i32> {
    retention_days_from_value(std::env::var(RETENTION_DAYS_ENV).ok().as_deref())
}

/// The configured pass interval.
pub fn interval_secs_from_env() -> u64 {
    interval_secs_from_value(std::env::var(RETENTION_INTERVAL_ENV).ok().as_deref())
}

/// The outcome of one retention pass.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DownloadStatsRetentionReport {
    /// The period applied; `None` when retention is off and nothing ran.
    pub retention_days: Option<i32>,
    /// Rows deleted from `download_statistics`.
    pub hosted_rows_deleted: u64,
    /// Rows deleted from `proxy_download_statistics`.
    pub proxy_rows_deleted: u64,
    pub batches: u32,
    /// The pass stopped early because the scheduler lease was lost.
    pub interrupted: bool,
}

/// Delete statistics rows older than `retention_days` (when `Some` and
/// positive) from both tables in batches of `batch_size`, until none are left
/// or `lost` is cancelled. Oldest rows go first, so an interrupted pass leaves
/// the newest of what it had to delete.
pub async fn apply_retention(
    db: &PgPool,
    retention_days: Option<i32>,
    batch_size: i64,
    lost: Option<&CancellationToken>,
) -> Result<DownloadStatsRetentionReport> {
    let mut report = DownloadStatsRetentionReport {
        retention_days: retention_days.filter(|days| *days > 0),
        ..Default::default()
    };
    let Some(days) = report.retention_days else {
        return Ok(report);
    };
    let batch_size = batch_size.max(1);
    for (table, sql) in RETAINED_TABLES {
        loop {
            if lost.is_some_and(CancellationToken::is_cancelled) {
                report.interrupted = true;
                return Ok(report);
            }
            let deleted = sqlx::query(sql)
                .bind(days)
                .bind(batch_size)
                .execute(db)
                .await
                .map_err(|e| AppError::Database(e.to_string()))?
                .rows_affected();
            if table == "download_statistics" {
                report.hosted_rows_deleted += deleted;
            } else {
                report.proxy_rows_deleted += deleted;
            }
            report.batches += 1;
            if deleted < batch_size as u64 {
                break;
            }
        }
    }
    Ok(report)
}

/// The startup line stating the retention period in force.
pub fn startup_message(retention_days: Option<i32>, interval_secs: u64) -> String {
    match retention_days {
        Some(days) => format!(
            "Download statistics retention: download_statistics and proxy_download_statistics \
             rows older than {days} days are deleted every {interval_secs}s \
             ({RETENTION_DAYS_ENV})"
        ),
        None => format!(
            "Download statistics retention is off: {RETENTION_DAYS_ENV} is not set to a \
             positive number of days, so download history is kept until its repository is \
             deleted"
        ),
    }
}

#[cfg(ak_test_shard = "services-1")]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::handlers::test_db_helpers as tdh;
    use sqlx::AssertSqlSafe;
    use uuid::Uuid;

    /// Ages this far back are never seeded by other tests, and the period
    /// below them is long enough that a pass run here cannot delete another
    /// test's rows while it runs alongside (the pass is instance-wide).
    const ANCIENT_DAYS: i32 = 4000;
    const PERIOD_DAYS: i32 = 3650;

    #[test]
    fn env_values_map_to_period_and_interval() {
        assert_eq!(retention_days_from_value(Some("90")), Some(90));
        assert_eq!(retention_days_from_value(Some(" 7 ")), Some(7));
        assert_eq!(retention_days_from_value(Some("0")), None);
        assert_eq!(retention_days_from_value(Some("-3")), None);
        assert_eq!(retention_days_from_value(Some("ninety")), None);
        assert_eq!(retention_days_from_value(None), None);
        assert_eq!(
            retention_days_from_value(Some("99999999999")),
            Some(MAX_RETENTION_DAYS)
        );
        assert_eq!(
            retention_days_from_value(Some("2147483647")),
            Some(MAX_RETENTION_DAYS)
        );
        assert_eq!(interval_secs_from_value(None), DEFAULT_INTERVAL_SECS);
        assert_eq!(interval_secs_from_value(Some("120")), 120);
        assert_eq!(interval_secs_from_value(Some("1")), MIN_INTERVAL_SECS);
        assert_eq!(interval_secs_from_value(Some("x")), DEFAULT_INTERVAL_SECS);
    }

    #[test]
    fn startup_message_states_the_period_or_that_retention_is_off() {
        assert!(startup_message(Some(30), 3600).contains("older than 30 days"));
        assert!(startup_message(None, 3600).contains("off"));
    }

    struct Seeded {
        repo_id: Uuid,
        artifact_id: Uuid,
    }

    async fn seed(pool: &PgPool) -> Seeded {
        let (repo_id, key, _dir) = tdh::create_repo(pool, "local", "generic").await;
        let artifact_id: Uuid = sqlx::query_scalar(
            "INSERT INTO artifacts (repository_id, path, name, size_bytes, checksum_sha256, \
             content_type, storage_key) VALUES ($1, $2, 'retention.bin', 1, $3, \
             'application/octet-stream', $4) RETURNING id",
        )
        .bind(repo_id)
        .bind(format!("retention/{}.bin", Uuid::new_v4()))
        .bind(format!("{:0>64}", Uuid::new_v4().simple()))
        .bind(format!("{key}/retention/{}", Uuid::new_v4()))
        .fetch_one(pool)
        .await
        .expect("seed artifact");
        Seeded {
            repo_id,
            artifact_id,
        }
    }

    async fn hosted_row(pool: &PgPool, s: &Seeded, age_days: i32) {
        sqlx::query(
            "INSERT INTO download_statistics (artifact_id, downloaded_at) \
             VALUES ($1, NOW() - make_interval(days => $2))",
        )
        .bind(s.artifact_id)
        .bind(age_days)
        .execute(pool)
        .await
        .expect("seed hosted download");
    }

    async fn proxy_row(pool: &PgPool, s: &Seeded, age_days: i32) {
        sqlx::query(
            "INSERT INTO proxy_download_statistics (repository_id, path, downloaded_at) \
             VALUES ($1, 'retention/pulled.bin', NOW() - make_interval(days => $2))",
        )
        .bind(s.repo_id)
        .bind(age_days)
        .execute(pool)
        .await
        .expect("seed proxy download");
    }

    async fn ages(pool: &PgPool, s: &Seeded) -> (Vec<i32>, Vec<i32>) {
        let hosted: Vec<i32> = sqlx::query_scalar(
            "SELECT EXTRACT(DAY FROM NOW() - downloaded_at)::INT FROM download_statistics \
             WHERE artifact_id = $1 ORDER BY 1",
        )
        .bind(s.artifact_id)
        .fetch_all(pool)
        .await
        .unwrap();
        let proxy: Vec<i32> = sqlx::query_scalar(
            "SELECT EXTRACT(DAY FROM NOW() - downloaded_at)::INT FROM proxy_download_statistics \
             WHERE repository_id = $1 ORDER BY 1",
        )
        .bind(s.repo_id)
        .fetch_all(pool)
        .await
        .unwrap();
        (hosted, proxy)
    }

    async fn drop_seed(pool: &PgPool, s: &Seeded) {
        let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(s.repo_id)
            .execute(pool)
            .await;
    }

    /// #4541: rows older than the period go from BOTH tables, in batches; rows
    /// inside it stay. Before, nothing ever trimmed either table.
    #[tokio::test]
    async fn deletes_rows_past_the_period_from_both_tables() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let s = seed(&pool).await;
        for age in [ANCIENT_DAYS, ANCIENT_DAYS + 1, 1] {
            hosted_row(&pool, &s, age).await;
            proxy_row(&pool, &s, age).await;
        }

        // A batch of one forces several statements per table.
        let report = apply_retention(&pool, Some(PERIOD_DAYS), 1, None)
            .await
            .expect("retention pass");
        let (hosted, proxy) = ages(&pool, &s).await;
        drop_seed(&pool, &s).await;

        assert_eq!(hosted, vec![1], "only the recent hosted row may survive");
        assert_eq!(proxy, vec![1], "only the recent proxy row may survive");
        assert_eq!(report.retention_days, Some(PERIOD_DAYS));
        assert!(report.hosted_rows_deleted >= 2, "{report:?}");
        assert!(report.proxy_rows_deleted >= 2, "{report:?}");
        assert!(report.batches >= 6, "batched one row at a time: {report:?}");
        assert!(!report.interrupted);
    }

    /// `EXPLAIN (ANALYZE, BUFFERS)` of a batch statement that has nothing to
    /// delete, which is the last batch of every pass, under `plan_cache_mode`:
    /// the connection pool prepares the statement, so after five executions
    /// PostgreSQL may switch it to a generic plan that cannot see the period.
    /// Returns the plan and the shared buffers it touched.
    async fn explain_empty_batch(
        pool: &PgPool,
        sql: &str,
        plan_cache_mode: &str,
    ) -> (serde_json::Value, i64) {
        // Far past any age a test seeds, so this deletes nothing.
        const NOTHING_THIS_OLD_DAYS: i32 = 300_000;
        let mut conn = pool.acquire().await.expect("connection");
        let setup = [
            format!("SET plan_cache_mode = {plan_cache_mode}"),
            format!("PREPARE retention_batch (int, bigint) AS {sql}"),
        ];
        for statement in setup {
            sqlx::query(AssertSqlSafe(statement))
                .execute(&mut *conn)
                .await
                .expect("prepare batch statement");
        }
        let plan: serde_json::Value = sqlx::query_scalar(AssertSqlSafe(format!(
            "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) EXECUTE retention_batch \
             ({NOTHING_THIS_OLD_DAYS}, {DOWNLOAD_STATS_RETENTION_BATCH_SIZE})"
        )))
        .fetch_one(&mut *conn)
        .await
        .expect("explain batch statement");
        for statement in ["DEALLOCATE retention_batch", "RESET plan_cache_mode"] {
            sqlx::query(statement)
                .execute(&mut *conn)
                .await
                .expect("restore connection");
        }
        let root = &plan[0]["Plan"];
        let buffers = root["Shared Hit Blocks"].as_i64().unwrap_or(0)
            + root["Shared Read Blocks"].as_i64().unwrap_or(0);
        (plan, buffers)
    }

    /// #4963: a batch that finds nothing to delete reads the time index and a
    /// handful of pages. Before, with no index on the download time, it read
    /// every page of the table, and the last batch of every pass is that batch.
    #[tokio::test]
    async fn empty_batch_reads_the_time_index_not_the_table() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let s = seed(&pool).await;
        sqlx::query(
            "INSERT INTO download_statistics (artifact_id, downloaded_at) \
             SELECT $1, NOW() - (g % 30) * INTERVAL '1 day' FROM generate_series(1, 20000) g",
        )
        .bind(s.artifact_id)
        .execute(&pool)
        .await
        .expect("seed hosted downloads");
        sqlx::query(
            "INSERT INTO proxy_download_statistics (repository_id, path, downloaded_at) \
             SELECT $1, 'retention/pulled.bin', NOW() - (g % 30) * INTERVAL '1 day' \
             FROM generate_series(1, 20000) g",
        )
        .bind(s.repo_id)
        .execute(&pool)
        .await
        .expect("seed proxy downloads");

        let mut observed = Vec::new();
        for ((table, sql), index) in RETAINED_TABLES.into_iter().zip([
            "idx_download_stats_downloaded_at",
            "idx_proxy_dl_stats_downloaded_at",
        ]) {
            sqlx::query(AssertSqlSafe(format!("ANALYZE {table}")))
                .execute(&pool)
                .await
                .expect("analyze");
            for mode in ["force_custom_plan", "force_generic_plan"] {
                let (plan, buffers) = explain_empty_batch(&pool, sql, mode).await;
                observed.push((table, mode, index, plan.to_string(), buffers));
            }
        }
        drop_seed(&pool, &s).await;

        for (table, mode, index, plan, buffers) in observed {
            assert!(!plan.contains("Seq Scan"), "{table} {mode} scanned: {plan}");
            assert!(plan.contains(index), "{table} {mode} needs {index}: {plan}");
            assert!(buffers <= 32, "{table} {mode} touched {buffers}: {plan}");
        }
    }

    /// #4963: the online index builds behind the bound are registered for the
    /// startup repair, so an interrupted build is retried rather than left
    /// INVALID, which the planner would ignore without any error.
    #[test]
    fn time_index_builds_are_repaired_after_an_interrupted_migration() {
        use crate::migration_repair::CONCURRENT_INDEX_MIGRATIONS as BUILDS;
        for index in [
            "idx_download_stats_downloaded_at",
            "idx_proxy_dl_stats_downloaded_at",
        ] {
            assert!(BUILDS.iter().any(|(_, name)| *name == index), "{index}");
        }
    }

    /// No period deletes nothing; a lost lease stops the pass before it
    /// deletes. The rows are 1000 days old: inside the period the test above
    /// may be applying at the same time, but past the 500-day period the
    /// interrupted pass here would apply if it ran.
    #[tokio::test]
    async fn no_period_or_lost_lease_deletes_nothing() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let s = seed(&pool).await;
        hosted_row(&pool, &s, 1000).await;
        proxy_row(&pool, &s, 1000).await;

        let absent = apply_retention(&pool, None, 10, None).await.unwrap();
        let zero = apply_retention(&pool, Some(0), 10, None).await.unwrap();
        let lost = CancellationToken::new();
        lost.cancel();
        let interrupted = apply_retention(&pool, Some(500), 10, Some(&lost))
            .await
            .unwrap();
        let (hosted, proxy) = ages(&pool, &s).await;
        drop_seed(&pool, &s).await;

        assert_eq!(hosted.len(), 1);
        assert_eq!(proxy.len(), 1);
        assert_eq!(absent, DownloadStatsRetentionReport::default());
        assert_eq!(zero, DownloadStatsRetentionReport::default());
        assert!(interrupted.interrupted);
        assert_eq!(
            interrupted.hosted_rows_deleted + interrupted.proxy_rows_deleted,
            0
        );
    }
}
