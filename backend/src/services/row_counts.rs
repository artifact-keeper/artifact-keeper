//! Exact row counts kept by triggers (#3094, migration 414).
//!
//! `GET /admin/stats` reports four counts that used to be a `COUNT(*)` over
//! the whole table on every call. Migration 414 makes every write append its
//! net row change to `row_count_deltas` in the writing transaction, so a
//! table's count is `SUM(delta)` over a handful of rows. This module holds the
//! three operations around that table:
//!
//! * [`read`]: the counts, in the caller's snapshot. A table that has not been
//!   seeded yet reads `None`, and the caller falls back to the live count.
//! * [`true_up`]: seeds a table, or corrects it, from one REPEATABLE READ
//!   snapshot. See its docs for why that is exact under concurrent writes.
//! * [`compact`]: folds the delta rows into one per table.
//!
//! The scheduler seeds unseeded tables at startup, compacts every minute and
//! trues every table up once a day on one replica ([`true_up_if_due`]).

use sqlx::PgPool;

use crate::error::{AppError, Result};

/// A counted table and the live query its count must equal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CountedTable {
    pub name: &'static str,
    /// `COUNT(*)` under exactly the rule the migration-414 triggers apply.
    pub live_count_sql: &'static str,
}

pub const ARTIFACTS: CountedTable = CountedTable {
    name: "artifacts",
    live_count_sql: "SELECT COUNT(*) FROM artifacts WHERE is_deleted = false",
};
pub const PROXY_CACHE_ARTIFACTS: CountedTable = CountedTable {
    name: "proxy_cache_artifacts",
    live_count_sql: "SELECT COUNT(*) FROM proxy_cache_artifacts",
};
pub const DOWNLOAD_STATISTICS: CountedTable = CountedTable {
    name: "download_statistics",
    live_count_sql: "SELECT COUNT(*) FROM download_statistics",
};
pub const PROXY_DOWNLOAD_STATISTICS: CountedTable = CountedTable {
    name: "proxy_download_statistics",
    live_count_sql: "SELECT COUNT(*) FROM proxy_download_statistics",
};

/// Every table migration 414 counts.
pub const COUNTED_TABLES: [CountedTable; 4] = [
    ARTIFACTS,
    PROXY_CACHE_ARTIFACTS,
    DOWNLOAD_STATISTICS,
    PROXY_DOWNLOAD_STATISTICS,
];

/// Trigger-kept counts; `None` for a table not seeded yet.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RowCounts {
    pub artifacts: Option<i64>,
    pub proxy_cache_artifacts: Option<i64>,
    pub download_statistics: Option<i64>,
    pub proxy_download_statistics: Option<i64>,
}

/// The counts in one statement, so all four come from the same snapshot.
/// Reads `row_count_seeds` (four rows) and `row_count_deltas` (one row per
/// table after compaction, plus whatever was written since), never the
/// counted tables.
pub async fn read(conn: &mut sqlx::PgConnection) -> Result<RowCounts> {
    let rows: Vec<(String, i64)> = sqlx::query_as(
        "SELECT s.table_name, \
                COALESCE((SELECT SUM(d.delta) FROM row_count_deltas d \
                           WHERE d.table_name = s.table_name), 0)::BIGINT \
           FROM row_count_seeds s",
    )
    .fetch_all(conn)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;
    let mut counts = RowCounts::default();
    for (table, n) in rows {
        let slot = match table.as_str() {
            "artifacts" => &mut counts.artifacts,
            "proxy_cache_artifacts" => &mut counts.proxy_cache_artifacts,
            "download_statistics" => &mut counts.download_statistics,
            "proxy_download_statistics" => &mut counts.proxy_download_statistics,
            _ => continue,
        };
        *slot = Some(n);
    }
    Ok(counts)
}

/// Seed or correct one table's count. Returns the correction it inserted
/// (the drift; `0` on a consistent table), or `None` when another true-up of
/// the same table ran at the same time and this one stood down.
///
/// One REPEATABLE READ transaction, so every statement reads the snapshot S
/// taken by the first one. It inserts `C - D` as a delta row, where `C` is the
/// live count and `D` the sum of the deltas, both as of S. Any later reader
/// then sums `D + (C - D) + (deltas committed after S) = C + (rows changed
/// after S)`, the live count: a write that committed before S is in both `C`
/// and `D`, and one that commits after S is in neither but has its own delta.
///
/// The first statement claims the table's `row_count_seeds` row. Two
/// concurrent true-ups would each add the same correction; the second one
/// instead waits on that row and then fails to serialise (SQLSTATE 40001),
/// which is reported as `None` and changes nothing.
pub async fn true_up(db: &PgPool, table: CountedTable) -> Result<Option<i64>> {
    let attempt = async {
        let mut tx = db.begin().await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "INSERT INTO row_count_seeds (table_name, trued_up_at) VALUES ($1, now()) \
             ON CONFLICT (table_name) DO UPDATE SET trued_up_at = now()",
        )
        .bind(table.name)
        .execute(&mut *tx)
        .await?;
        let live: i64 = sqlx::query_scalar(table.live_count_sql)
            .fetch_one(&mut *tx)
            .await?;
        let recorded: i64 = sqlx::query_scalar(
            "SELECT COALESCE(SUM(delta), 0)::BIGINT FROM row_count_deltas WHERE table_name = $1",
        )
        .bind(table.name)
        .fetch_one(&mut *tx)
        .await?;
        let correction = live - recorded;
        if correction != 0 {
            sqlx::query("INSERT INTO row_count_deltas (table_name, delta) VALUES ($1, $2)")
                .bind(table.name)
                .bind(correction)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        Ok::<i64, sqlx::Error>(correction)
    };
    match attempt.await {
        Ok(correction) => Ok(Some(correction)),
        Err(e) if is_serialization_failure(&e) => Ok(None),
        Err(e) => Err(AppError::Database(e.to_string())),
    }
}

/// [`true_up`] every counted table that has no seed yet. Returns how many it
/// seeded.
pub async fn seed_missing(db: &PgPool) -> Result<usize> {
    let seeded: Vec<String> = sqlx::query_scalar("SELECT table_name FROM row_count_seeds")
        .fetch_all(db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
    let mut n = 0;
    for table in COUNTED_TABLES {
        if !seeded.iter().any(|s| s == table.name) && true_up(db, table).await?.is_some() {
            n += 1;
        }
    }
    Ok(n)
}

/// Scheduler lease name for [`true_up_if_due`]: one replica per day.
pub const TRUE_UP_LEASE: &str = "row_counts_true_up";

/// How long a table's true-up stays fresh. Each true-up is a full `COUNT(*)`
/// inside a REPEATABLE READ snapshot, which holds back vacuum for its
/// duration, so it runs at most about once a day across the cluster.
pub const TRUE_UP_INTERVAL_SECS: i64 = 23 * 3600;

/// The daily drift safety net. Trues up only the seeded tables whose last
/// true-up is older than [`TRUE_UP_INTERVAL_SECS`], and only on the replica
/// that holds the [`TRUE_UP_LEASE`] scheduler lease (kept for the same
/// interval), so a fleet of N replicas still counts each table once a day.
/// Returns `(table, drift)` for every table it trued up; `None` drift means
/// a concurrent true-up stood down.
pub async fn true_up_if_due(db: &PgPool) -> Result<Vec<(&'static str, Option<i64>)>> {
    let due: Vec<String> = sqlx::query_scalar(
        "SELECT table_name FROM row_count_seeds \
          WHERE trued_up_at <= now() - make_interval(secs => $1)",
    )
    .bind(TRUE_UP_INTERVAL_SECS as f64)
    .fetch_all(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;
    if due.is_empty() {
        return Ok(Vec::new());
    }
    if crate::services::cluster_work::try_acquire_scheduler_lease_quiet(
        db,
        TRUE_UP_LEASE,
        TRUE_UP_INTERVAL_SECS as f64,
    )
    .await
    .is_none()
    {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for table in COUNTED_TABLES {
        if due.iter().any(|d| d == table.name) {
            out.push((table.name, true_up(db, table).await?));
        }
    }
    Ok(out)
}

/// Fold all delta rows into one row per table. A single statement: the
/// DELETE removes exactly the rows its snapshot sees and the INSERT writes
/// their sums, atomically, so every table's `SUM(delta)` is the same before
/// and after for any reader. Rows committed after the snapshot are left for
/// the next run. Two replicas compacting at once is safe: the second DELETE
/// waits on the rows the first one deleted and then skips them. Returns the
/// number of rows removed.
pub async fn compact(db: &PgPool) -> Result<u64> {
    let removed: i64 = sqlx::query_scalar(
        "WITH gone AS (DELETE FROM row_count_deltas RETURNING table_name, delta), \
              folded AS (INSERT INTO row_count_deltas (table_name, delta) \
                         SELECT table_name, SUM(delta) FROM gone GROUP BY table_name \
                         HAVING SUM(delta) <> 0) \
         SELECT COUNT(*) FROM gone",
    )
    .fetch_one(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;
    Ok(removed as u64)
}

fn is_serialization_failure(e: &sqlx::Error) -> bool {
    e.as_database_error()
        .and_then(|d| d.code())
        .is_some_and(|c| c == "40001")
}

#[cfg(ak_test_shard = "services-2")]
#[cfg(test)]
mod tests {
    use super::*;

    /// The live-count SQL is what `/admin/stats` reported before #3094:
    /// changing one of these changes the published figure.
    #[test]
    fn live_count_rules_match_the_old_queries() {
        assert_eq!(
            ARTIFACTS.live_count_sql,
            "SELECT COUNT(*) FROM artifacts WHERE is_deleted = false"
        );
        for t in [
            PROXY_CACHE_ARTIFACTS,
            DOWNLOAD_STATISTICS,
            PROXY_DOWNLOAD_STATISTICS,
        ] {
            assert_eq!(t.live_count_sql, format!("SELECT COUNT(*) FROM {}", t.name));
        }
    }

    /// Every counted table gets the migration-414 insert, delete and
    /// truncate triggers.
    #[test]
    fn migration_414_counts_every_listed_table() {
        let sql = include_str!("../../migrations/414_row_count_deltas.sql");
        for t in COUNTED_TABLES {
            for event in ["INSERT", "DELETE", "TRUNCATE"] {
                assert!(
                    sql.contains(&format!("AFTER {event} ON {} ", t.name))
                        || sql.contains(&format!("AFTER {event} ON {}\n", t.name)),
                    "{} has no AFTER {event} trigger",
                    t.name
                );
            }
        }
    }
}
