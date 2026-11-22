//! #6429: the re-catalog sweep for proxy-cache entries with no catalog row.
//!
//! The DB-backed tests run against a real filesystem proxy-cache store: every
//! seeded entry has its `__content__` body and `__cache_meta__.json` sidecar on
//! disk, the way a fill leaves them.

use std::path::Path;

use serde_json::json;

use super::*;
use crate::api::handlers::test_db_helpers as tdh;
use crate::services::storage_service::FilesystemBackend;

fn meta_json(cached_at: DateTime<Utc>, size: i64, digest: &str) -> serde_json::Value {
    json!({
        "cached_at": cached_at,
        "expires_at": cached_at + chrono::Duration::days(365),
        "content_type": "application/octet-stream",
        "size_bytes": size,
        "checksum_sha256": digest,
    })
}

fn meta(value: serde_json::Value) -> CacheMetadata {
    serde_json::from_value(value).expect("sidecar json")
}

fn old() -> DateTime<Utc> {
    Utc::now() - chrono::Duration::hours(2)
}

// ---------------------------------------------------------------------------
// Pure
// ---------------------------------------------------------------------------

#[test]
fn config_defaults_off_switch_and_bounds() {
    let d = SweepConfig::from_values(None, None, None);
    assert_eq!(d.interval, Some(Duration::from_secs(DEFAULT_INTERVAL_SECS)));
    assert_eq!(d.budget, DEFAULT_BUDGET);
    assert_eq!(d.min_age_secs, DEFAULT_MIN_AGE_SECS);
    assert_eq!(d.startup_delay_secs(), MAX_STARTUP_DELAY_SECS);
    for off in ["0", "off", " OFF ", "false", "no"] {
        let c = SweepConfig::from_values(Some(off), None, None);
        assert_eq!(c.interval, None, "{off}");
        assert_eq!(c.startup_delay_secs(), 0);
        assert!(c.startup_message().contains("off"));
    }
    let fast = SweepConfig::from_values(Some("3"), Some("250"), Some("0"));
    assert_eq!(fast.interval, Some(Duration::from_secs(MIN_INTERVAL_SECS)));
    assert_eq!(fast.startup_delay_secs(), MIN_INTERVAL_SECS);
    assert_eq!(fast.budget, 250);
    assert_eq!(fast.min_age_secs, 0);
    assert!(fast.startup_message().contains("250 keys"));
    let junk = SweepConfig::from_values(Some("soon"), Some("0"), Some("-5"));
    assert_eq!(
        junk.interval,
        Some(Duration::from_secs(DEFAULT_INTERVAL_SECS))
    );
    assert_eq!(junk.budget, DEFAULT_BUDGET);
    assert_eq!(junk.min_age_secs, DEFAULT_MIN_AGE_SECS);
}

#[test]
fn sidecar_skip_reasons() {
    let now = Utc::now();
    let created = now - chrono::Duration::days(1);
    let ok = meta(meta_json(now - chrono::Duration::hours(1), 10, "d"));
    assert_eq!(sidecar_skip(&ok, now, 600, created), None);
    // Younger than the minimum age.
    let young = meta(meta_json(now - chrono::Duration::seconds(30), 10, "d"));
    assert_eq!(sidecar_skip(&young, now, 600, created), Some(Skip::Young));
    assert_eq!(sidecar_skip(&young, now, 0, created), None);
    // Written before the Remote existed.
    let stale = meta(meta_json(now - chrono::Duration::days(3), 10, "d"));
    assert_eq!(sidecar_skip(&stale, now, 600, created), Some(Skip::Stale));
    // A cached 404, even an expired one.
    let mut negative = meta_json(now - chrono::Duration::hours(1), 0, "");
    negative["negative_cached_until"] = json!(now - chrono::Duration::minutes(1));
    assert_eq!(
        sidecar_skip(&meta(negative), now, 600, created),
        Some(Skip::Negative)
    );
}

#[test]
fn listed_entries_keeps_only_sidecars_that_derive_back() {
    let scope = ProxyCacheScope::unscoped();
    let root = scope.repo_root("r");
    let keys: Vec<String> = [
        "a/b.whl/__cache_meta__.json",
        "a/b.whl/__content__",
        "simple/x/__cache_meta__.json",
        "a/.__cache_meta__.json.1234.tmp",
        "__cache_meta__.json",
        "a/../b/__cache_meta__.json",
    ]
    .iter()
    .map(|k| format!("{root}{k}"))
    .chain([
        "proxy-cache/other/c/__cache_meta__.json".to_string(),
        "maven/x/__cache_meta__.json".to_string(),
    ])
    .collect();
    let entries = listed_entries(&scope, "r", &keys);
    let paths: Vec<&str> = entries.iter().map(|e| e.path.as_str()).collect();
    assert_eq!(paths, ["a/b.whl", "simple/x"]);
    assert_eq!(entries[0].content_key, format!("{root}a/b.whl/__content__"));
    assert_eq!(
        entries[0].metadata_key,
        format!("{root}a/b.whl/__cache_meta__.json")
    );
}

#[test]
fn report_counts_skips_by_reason() {
    let mut r = SweepReport::default();
    r.count_skip(Skip::Negative);
    r.count_skip(Skip::Young);
    r.count_skip(Skip::Young);
    r.count_skip(Skip::Stale);
    assert_eq!(
        (r.skipped_negative, r.skipped_young, r.skipped_stale),
        (1, 2, 1)
    );
    // Logging and metrics take any report.
    log_pass(&r);
    r.recataloged = 1;
    log_pass(&r);
    r.record_metrics();
}

// ---------------------------------------------------------------------------
// DB-backed
// ---------------------------------------------------------------------------

struct Rig {
    pool: PgPool,
    repo: Uuid,
    key: String,
    dir: std::path::PathBuf,
    scope: ProxyCacheScope,
}

impl Rig {
    async fn new() -> Option<Self> {
        let pool = tdh::try_pool().await?;
        let (repo, key, dir) = tdh::create_repo(&pool, "remote", "generic").await;
        // The repository row is created now; sidecars below are older.
        sqlx::query("UPDATE repositories SET created_at = NOW() - INTERVAL '1 day' WHERE id = $1")
            .bind(repo)
            .execute(&pool)
            .await
            .unwrap();
        Some(Self {
            pool,
            repo,
            key,
            dir,
            scope: ProxyCacheScope::unscoped(),
        })
    }

    fn sweep(&self, page_size: usize, budget: usize) -> RecatalogSweep {
        let mut config = SweepConfig::from_values(None, Some(&budget.to_string()), None);
        config.page_size = page_size;
        config.page_pause = Duration::ZERO;
        RecatalogSweep::new(
            self.pool.clone(),
            Arc::new(FilesystemBackend::new(self.dir.clone())),
            self.scope.clone(),
            config,
        )
    }

    async fn remote(&self) -> Remote {
        sqlx::query_as("SELECT id, key, created_at FROM repositories WHERE id = $1")
            .bind(self.repo)
            .fetch_one(&self.pool)
            .await
            .unwrap()
    }

    fn keys(&self, path: &str) -> CacheKeys {
        CacheKeys::derive(&self.scope, &self.key, path).unwrap()
    }

    /// Write an entry's body and sidecar the way a fill does.
    fn put(&self, path: &str, body: &[u8], sidecar: serde_json::Value) -> CacheKeys {
        let keys = self.keys(path);
        write(&self.dir, &keys.content, body);
        write(
            &self.dir,
            &keys.metadata,
            &serde_json::to_vec(&sidecar).unwrap(),
        );
        keys
    }

    fn put_old(&self, path: &str, size: usize) -> (CacheKeys, String) {
        let digest = format!("{:0>64}", Uuid::new_v4().simple());
        let keys = self.put(
            path,
            &vec![b'x'; size],
            meta_json(old(), size as i64, &digest),
        );
        (keys, digest)
    }

    async fn run(&self, sweep: &RecatalogSweep) -> (SweepReport, RemoteSweep) {
        let mut report = SweepReport::default();
        let mut budget = sweep.config().budget;
        let outcome = sweep
            .sweep_remote(&self.remote().await, None, &mut budget, &mut report, None)
            .await
            .unwrap();
        (report, outcome)
    }

    async fn row(&self, path: &str) -> Option<(i64, Option<String>, Option<DateTime<Utc>>)> {
        sqlx::query_as(
            "SELECT size_bytes, checksum_sha256, quarantine_until FROM proxy_cache_artifacts \
             WHERE repository_id = $1 AND path = $2",
        )
        .bind(self.repo)
        .bind(path)
        .fetch_optional(&self.pool)
        .await
        .unwrap()
    }

    async fn ledger_and_live(&self) -> (i64, i64) {
        sqlx::query_as(
            "SELECT (SELECT proxy_bytes FROM repository_usage_ledger WHERE repository_id = $1), \
                    (SELECT COALESCE(SUM(size_bytes), 0)::BIGINT FROM proxy_cache_artifacts \
                     WHERE repository_id = $1)",
        )
        .bind(self.repo)
        .fetch_one(&self.pool)
        .await
        .unwrap()
    }

    async fn legacy_row(&self, path: &str, content_key: &str, removal: &str) {
        let sql = format!(
            "INSERT INTO artifacts (repository_id, path, name, size_bytes, checksum_sha256, \
             content_type, storage_key, is_deleted, quarantine_status) \
             VALUES ($1, $2, $2, 1, 'l', 'application/octet-stream', $3, {removal})"
        );
        sqlx::query(sqlx::AssertSqlSafe(&*sql))
            .bind(self.repo)
            .bind(path)
            .bind(content_key)
            .execute(&self.pool)
            .await
            .unwrap();
    }

    async fn cleanup(self) {
        let _ = sqlx::query("DELETE FROM artifacts WHERE repository_id = $1")
            .bind(self.repo)
            .execute(&self.pool)
            .await;
        let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(self.repo)
            .execute(&self.pool)
            .await;
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn write(base: &Path, key: &str, bytes: &[u8]) {
    let path = base.join(key);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, bytes).unwrap();
}

/// The issue's acceptance: a sidecar whose row is gone is re-cataloged within
/// one sweep with the sidecar's size and digest, the ledger's `proxy_bytes`
/// equals the live sum afterwards, and a second pass changes nothing.
#[tokio::test]
async fn lost_row_is_recataloged_and_ledger_matches_6429() {
    let Some(rig) = Rig::new().await else { return };
    let (_, digest) = rig.put_old("pkg/a-1.0.tgz", 1234);
    let (kept_keys, _) = rig.put_old("pkg/b-1.0.tgz", 99);
    // b still has its row; a lost its row.
    proxy_catalog::upsert(
        &rig.pool,
        rig.repo,
        "pkg/b-1.0.tgz",
        &kept_keys.content,
        &kept_keys.metadata,
        99,
        Some("b"),
        None,
        None,
        None,
    )
    .await
    .unwrap();
    assert_eq!(rig.row("pkg/a-1.0.tgz").await, None);

    let sweep = rig.sweep(1000, 1000);
    let (report, outcome) = rig.run(&sweep).await;
    assert_eq!(outcome, RemoteSweep::Done);
    assert_eq!(report.scanned, 4, "{report:?}");
    assert_eq!(report.sidecars, 2);
    assert_eq!(report.recataloged, 1, "{report:?}");
    assert_eq!(report.recataloged_bytes, 1234);
    let (size, sum, hold) = rig.row("pkg/a-1.0.tgz").await.expect("row restored");
    assert_eq!(
        (size, sum.as_deref(), hold),
        (1234, Some(digest.as_str()), None)
    );
    // The kept row was not touched by the sweep.
    assert_eq!(
        rig.row("pkg/b-1.0.tgz").await.unwrap().1.as_deref(),
        Some("b")
    );
    let (ledger, live) = rig.ledger_and_live().await;
    assert_eq!(ledger, live);
    assert_eq!(live, 1234 + 99);

    // Idempotent.
    let (again, _) = rig.run(&sweep).await;
    assert_eq!(again.recataloged, 0, "{again:?}");
    assert_eq!(rig.ledger_and_live().await, (live, live));
    rig.cleanup().await;
}

/// An entry an operator removed (its legacy `artifacts` row trashed or
/// rejected), a cached 404, a sidecar with no body, a young sidecar, a
/// leftover from before the Remote existed and an unreadable sidecar are all
/// left without a row; a held entry is re-cataloged with its hold.
#[tokio::test]
async fn removed_negative_young_and_stale_entries_are_not_recataloged_6429() {
    let Some(rig) = Rig::new().await else { return };
    let (trashed, _) = rig.put_old("t/trashed.bin", 10);
    rig.legacy_row("t/trashed.bin", &trashed.content, "true, NULL")
        .await;
    let (rejected, _) = rig.put_old("t/rejected.bin", 10);
    rig.legacy_row("t/rejected.bin", &rejected.content, "false, 'rejected'")
        .await;
    let mut negative = meta_json(old(), 0, "");
    negative["negative_cached_until"] = json!(Utc::now() + chrono::Duration::hours(1));
    rig.put("t/missing-upstream", b"", negative);
    let no_body = rig.put_old("t/no-body.bin", 10).0;
    std::fs::remove_file(rig.dir.join(&no_body.content)).unwrap();
    rig.put("t/young.bin", b"y", meta_json(Utc::now(), 1, "y"));
    rig.put(
        "t/stale.bin",
        b"s",
        meta_json(Utc::now() - chrono::Duration::days(30), 1, "s"),
    );
    let garbled = rig.keys("t/garbled.bin");
    write(&rig.dir, &garbled.content, b"g");
    write(&rig.dir, &garbled.metadata, b"{not json");
    let mut held = meta_json(old(), 5, "h");
    let until = Utc::now() + chrono::Duration::days(3);
    held["quarantine_until"] = json!(until);
    rig.put("t/held.bin", b"hhhhh", held);

    let (report, _) = rig.run(&rig.sweep(1000, 1000)).await;
    assert_eq!(report.skipped_deleted, 2, "{report:?}");
    assert_eq!(report.skipped_negative, 1, "{report:?}");
    assert_eq!(report.skipped_no_content, 1, "{report:?}");
    assert_eq!(report.skipped_young, 1, "{report:?}");
    assert_eq!(report.skipped_stale, 1, "{report:?}");
    assert_eq!(report.skipped_unreadable, 1, "{report:?}");
    assert_eq!(report.recataloged, 1, "{report:?}");
    for path in [
        "t/trashed.bin",
        "t/rejected.bin",
        "t/missing-upstream",
        "t/no-body.bin",
        "t/young.bin",
        "t/stale.bin",
        "t/garbled.bin",
    ] {
        assert_eq!(rig.row(path).await, None, "{path} was re-cataloged");
    }
    let (_, _, hold) = rig.row("t/held.bin").await.expect("held entry restored");
    let hold = hold.expect("the row carries the sidecar's hold");
    assert!((hold - until).num_seconds().abs() <= 1);
    rig.cleanup().await;
}

/// A pass stops at its key budget and the next resumes from the cursor; the
/// pages together cover every entry exactly once.
#[tokio::test]
async fn budget_bounds_a_pass_and_the_next_resumes_6429() {
    let Some(rig) = Rig::new().await else { return };
    for i in 0..5 {
        rig.put_old(&format!("p/{i}.bin"), 10 + i);
    }
    let sweep = rig.sweep(3, 4);
    let remote = rig.remote().await;
    let mut report = SweepReport::default();
    let mut budget = 4;
    let outcome = sweep
        .sweep_remote(&remote, None, &mut budget, &mut report, None)
        .await
        .unwrap();
    assert_eq!(report.scanned, 4, "{report:?}");
    let RemoteSweep::Stopped(Some(cursor)) = outcome else {
        panic!("expected a resumable stop, got {outcome:?}");
    };
    let mut budget = 100;
    let rest = sweep
        .sweep_remote(&remote, Some(cursor), &mut budget, &mut report, None)
        .await
        .unwrap();
    assert_eq!(rest, RemoteSweep::Done);
    assert_eq!(report.scanned, 10, "{report:?}");
    assert_eq!(report.recataloged, 5, "{report:?}");
    let (ledger, live) = rig.ledger_and_live().await;
    assert_eq!((ledger, live), (60, 60));

    // A lost lease stops a pass before its next page.
    let lost = CancellationToken::new();
    lost.cancel();
    let mut report = SweepReport::default();
    let mut budget = 100;
    let stopped = sweep
        .sweep_remote(&remote, None, &mut budget, &mut report, Some(&lost))
        .await
        .unwrap();
    assert_eq!(stopped, RemoteSweep::Stopped(None));
    assert!(report.interrupted);
    rig.cleanup().await;
}

/// `run_pass` visits the Remote and saves where it stopped.
#[tokio::test]
async fn run_pass_restores_rows_across_remotes_6429() {
    let Some(rig) = Rig::new().await else { return };
    rig.put_old("q/one.bin", 7);
    let sweep = rig.sweep(1000, usize::MAX);
    let report = sweep.run_pass(None).await.unwrap();
    assert!(report.remotes >= 1);
    assert!(report.complete, "{report:?}");
    assert!(rig.row("q/one.bin").await.is_some());
    rig.cleanup().await;
}

/// The row a backfill inserts is taken back only while it is still the one
/// the sweep wrote.
#[tokio::test]
async fn delete_backfilled_spares_a_rewritten_row_6429() {
    let Some(rig) = Rig::new().await else { return };
    let keys = rig.keys("r/x.bin");
    let insert = || {
        proxy_catalog::backfill_from_sidecar_returning(
            &rig.pool,
            rig.repo,
            "r/x.bin",
            &keys.content,
            &keys.metadata,
            3,
            Some("x"),
            None,
            None,
        )
    };
    let first = insert().await.unwrap();
    assert!(first.inserted);
    let met = insert().await.unwrap();
    assert!(!met.inserted);
    assert_eq!(met.id, first.id);
    // A fill rewrites the row: a new `cached_at`.
    sqlx::query("UPDATE proxy_cache_artifacts SET cached_at = cached_at + INTERVAL '1 second' WHERE id = $1")
        .bind(first.id)
        .execute(&rig.pool)
        .await
        .unwrap();
    assert_eq!(
        proxy_catalog::delete_backfilled(&rig.pool, &first)
            .await
            .unwrap(),
        0
    );
    assert!(rig.row("r/x.bin").await.is_some());
    let current = insert().await.unwrap();
    assert_eq!(
        proxy_catalog::delete_backfilled(&rig.pool, &current)
            .await
            .unwrap(),
        1
    );
    assert_eq!(rig.row("r/x.bin").await, None);
    rig.cleanup().await;
}
