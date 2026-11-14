//! Rescan stored artifacts after a vulnerability-database update (#5947).
//!
//! A verdict is only as fresh as the database it was graded against
//! (`scan_results.vuln_db_published_at`, migration 259). When a scanner's
//! database build moves past the one a stored artifact's latest scan used, that
//! artifact's digest is queued as a `rescan` job at [`PRIORITY_RESCAN`], below
//! every other band. One job per digest, not per artifact row: the worker scans
//! the first row holding the digest and copies that fresh result onto the
//! others, within this instance's database only.
//!
//! Off unless `SCAN_RESCAN_MAX_PER_DAY` is above 0 (default 0), and only with
//! the durable scan queue on. A rescan adds `scan_results` rows; it never
//! deletes or rewrites the earlier ones.

use std::time::Duration;

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{AppError, Result};
use crate::services::scan_queue::PRIORITY_RESCAN;

/// How often a worker looks for stale verdicts.
pub const RESCAN_TICK: Duration = Duration::from_secs(15 * 60);

/// Most digests one tick queues, whatever is left of the daily cap.
const BATCH_MAX: i64 = 500;

/// Ledger rows older than this are dropped; they only bound one update's pass.
const LEDGER_RETENTION_DAYS: f64 = 30.0;

/// `pg_try_advisory_xact_lock` key, so one replica selects at a time and the
/// daily cap holds across a fleet.
const TICK_LOCK_KEY: i64 = 0x5947_5ca9;

/// How far back [`observed_builds`] looks for databases scanners reported
/// with a scan (the adapter reports its Trivy DB that way, not by probe). Only
/// how a new build is learned: [`refresh_builds`] keeps it after that.
const OBSERVED_WINDOW_HOURS: f64 = 48.0;

/// One scan type's current database build.
pub type Build = (String, DateTime<Utc>);

/// Database builds recent scans recorded, per scan type. Covers scanners that
/// report their database only alongside a scan. Live-API feeds are excluded.
pub async fn observed_builds(db: &PgPool) -> Result<Vec<Build>> {
    sqlx::query_as(
        r#"
        SELECT scan_type, MAX(vuln_db_published_at)
        FROM scan_results
        WHERE created_at > NOW() - make_interval(hours => $1)
          AND status = 'completed'
          AND vuln_db_published_at IS NOT NULL
          AND (vuln_db_version IS NULL OR vuln_db_version NOT LIKE 'live:%')
        GROUP BY scan_type
        "#,
    )
    .bind(OBSERVED_WINDOW_HOURS)
    .fetch_all(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))
}

/// The newest build per scan type across both sources, sorted by scan type.
///
/// Timestamps are truncated to microseconds, Postgres' resolution, so a build
/// read back from `scan_vuln_db_builds` keys the same as the live probe's.
pub fn merge_builds(a: Vec<Build>, b: Vec<Build>) -> Vec<Build> {
    use chrono::SubsecRound;
    let mut by_type = std::collections::BTreeMap::<String, DateTime<Utc>>::new();
    for (scan_type, at) in a.into_iter().chain(b) {
        let at = at.trunc_subsecs(6);
        let slot = by_type.entry(scan_type).or_insert(at);
        if at > *slot {
            *slot = at;
        }
    }
    by_type.into_iter().collect()
}

/// Record `seen` in `scan_vuln_db_builds` (never moving a build backwards)
/// and return every scan type's last-known build. A scanner seen once stays
/// compared after a quiet spell with no scans, instead of dropping out.
pub async fn refresh_builds(db: &PgPool, seen: &[Build]) -> Result<Vec<Build>> {
    let db_err = |e: sqlx::Error| AppError::Database(e.to_string());
    if !seen.is_empty() {
        let (types, ats): (Vec<String>, Vec<DateTime<Utc>>) = seen.iter().cloned().unzip();
        sqlx::query(
            r#"
            INSERT INTO scan_vuln_db_builds (scan_type, built_at)
            SELECT * FROM unnest($1::text[], $2::timestamptz[])
            ON CONFLICT (scan_type) DO UPDATE SET
                built_at = GREATEST(scan_vuln_db_builds.built_at, EXCLUDED.built_at),
                updated_at = NOW()
            "#,
        )
        .bind(&types)
        .bind(&ats)
        .execute(db)
        .await
        .map_err(db_err)?;
    }
    sqlx::query_as("SELECT scan_type, built_at FROM scan_vuln_db_builds ORDER BY scan_type")
        .fetch_all(db)
        .await
        .map_err(db_err)
}

/// Scan types with a known database build: the scanners a rescan runs.
pub async fn rescan_scan_types(db: &PgPool) -> Result<Vec<String>> {
    sqlx::query_scalar("SELECT scan_type FROM scan_vuln_db_builds ORDER BY scan_type")
        .fetch_all(db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))
}

/// Stable identity of a set of builds: a new key means some database moved.
pub fn builds_key(builds: &[Build]) -> String {
    let mut parts: Vec<String> = builds
        .iter()
        .map(|(t, at)| format!("{t}={}", at.to_rfc3339()))
        .collect();
    parts.sort();
    parts.join(";")
}

/// Digests whose newest completed scan of a scan type in `builds` used an
/// older (or unknown) database, in repositories with scanning on, minus those
/// already queued for this builds key. Most recently downloaded first.
const STALE_DIGESTS_SQL: &str = r#"
    WITH builds AS (
        SELECT * FROM unnest($1::text[], $2::timestamptz[]) AS b(scan_type, built_at)
    ),
    -- One probe of idx_scan_results_latest_per_artifact_type per artifact
    -- and scan type for its newest completed row, so the cost follows the
    -- artifacts, not the length of their scan history.
    stale AS (
        SELECT a.id, a.checksum_sha256 AS digest
        FROM artifacts a
        JOIN scan_configs c ON c.repository_id = a.repository_id AND c.scan_enabled = true
        CROSS JOIN builds b
        CROSS JOIN LATERAL (
            SELECT sr.vuln_db_published_at
            FROM scan_results sr
            WHERE sr.artifact_id = a.id AND sr.scan_type = b.scan_type
              AND sr.status = 'completed'
            ORDER BY sr.completed_at DESC NULLS LAST, sr.created_at DESC
            LIMIT 1
        ) l
        WHERE a.is_deleted = false
          AND (l.vuln_db_published_at IS NULL OR l.vuln_db_published_at < b.built_at)
    )
    SELECT s.digest
    FROM stale s
    LEFT JOIN LATERAL (
        SELECT MAX(d.downloaded_at) AS at
        FROM download_statistics d
        WHERE d.artifact_id = s.id
    ) dl ON true
    WHERE NOT EXISTS (
        SELECT 1 FROM scan_rescan_ledger r
        WHERE r.digest = s.digest AND r.builds_key = $3
    )
      -- Already queued (an earlier key's pass still pending): it will grade
      -- against the newest database when it runs, so do not charge it again.
      AND NOT EXISTS (
        SELECT 1 FROM scan_queue q
        WHERE q.kind = 'rescan' AND q.digest = s.digest
          AND q.state IN ('pending', 'running')
    )
    GROUP BY s.digest
    ORDER BY MAX(dl.at) DESC NULLS LAST, s.digest
    LIMIT $4
"#;

/// Queue the rescans a set of database builds calls for, within what is left
/// of `max_per_day`. Returns how many digests were queued. `0` with
/// `max_per_day == 0`, which is the default: nothing is selected at all.
pub async fn enqueue_rescans(db: &PgPool, builds: &[Build], max_per_day: u64) -> Result<u64> {
    if max_per_day == 0 || builds.is_empty() {
        return Ok(0);
    }
    let db_err = |e: sqlx::Error| AppError::Database(e.to_string());
    let key = builds_key(builds);
    let mut tx = db.begin().await.map_err(db_err)?;

    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1)")
        .bind(TICK_LOCK_KEY)
        .fetch_one(&mut *tx)
        .await
        .map_err(db_err)?;
    if !locked {
        return Ok(0);
    }

    let exhausted: Option<String> =
        sqlx::query_scalar("SELECT exhausted_key FROM scan_rescan_state WHERE id")
            .fetch_optional(&mut *tx)
            .await
            .map_err(db_err)?
            .flatten();
    if exhausted.as_deref() == Some(key.as_str()) {
        return Ok(0);
    }

    let used: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM scan_rescan_ledger WHERE enqueued_at > NOW() - INTERVAL '1 day'",
    )
    .fetch_one(&mut *tx)
    .await
    .map_err(db_err)?;
    let budget = i64::try_from(max_per_day)
        .unwrap_or(i64::MAX)
        .saturating_sub(used);
    if budget <= 0 {
        return Ok(0);
    }
    let limit = budget.min(BATCH_MAX);

    let (types, ats): (Vec<String>, Vec<DateTime<Utc>>) = builds.iter().cloned().unzip();
    let digests: Vec<String> = sqlx::query_scalar(STALE_DIGESTS_SQL)
        .bind(&types)
        .bind(&ats)
        .bind(&key)
        .bind(limit)
        .fetch_all(&mut *tx)
        .await
        .map_err(db_err)?;

    let mut queued: Vec<String> = Vec::new();
    if !digests.is_empty() {
        queued = sqlx::query_scalar(
            r#"
            INSERT INTO scan_queue (kind, priority, digest)
            SELECT 'rescan', $1, d FROM unnest($2::text[]) AS d
            ON CONFLICT (kind, digest)
                WHERE state IN ('pending', 'running') AND digest IS NOT NULL
                  AND kind <> 'hosted_image'
            DO NOTHING
            RETURNING digest
            "#,
        )
        .bind(PRIORITY_RESCAN)
        .bind(&digests)
        .fetch_all(&mut *tx)
        .await
        .map_err(db_err)?;
        // Only what was actually queued counts against the cap.
        sqlx::query(
            "INSERT INTO scan_rescan_ledger (digest, builds_key) \
             SELECT d, $2 FROM unnest($1::text[]) AS d ON CONFLICT DO NOTHING",
        )
        .bind(&queued)
        .bind(&key)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
    }

    // A short page means nothing else is stale for these builds: skip the
    // selection until a database moves again.
    if (digests.len() as i64) < limit {
        sqlx::query(
            "INSERT INTO scan_rescan_state (id, exhausted_key, updated_at) VALUES (true, $1, NOW()) \
             ON CONFLICT (id) DO UPDATE SET exhausted_key = EXCLUDED.exhausted_key, \
             updated_at = NOW()",
        )
        .bind(&key)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
    }

    sqlx::query(
        "DELETE FROM scan_rescan_ledger \
         WHERE enqueued_at < NOW() - make_interval(days => $1::int)",
    )
    .bind(LEDGER_RETENTION_DAYS as i32)
    .execute(&mut *tx)
    .await
    .map_err(db_err)?;

    tx.commit().await.map_err(db_err)?;
    if !queued.is_empty() {
        crate::services::scan_queue::enqueue_signal().notify_one();
    }
    Ok(queued.len() as u64)
}

/// Most artifact rows one rescan job touches. A digest held by more rows than
/// this (in practice the empty file, whose digest every zero-byte upload
/// shares) has its newest rows refreshed and the rest keep their earlier
/// result until the next database build.
pub const MAX_ROWS_PER_DIGEST: i64 = 1000;

/// Live artifact rows in this instance whose bytes are `digest`, at most
/// [`MAX_ROWS_PER_DIGEST`], oldest first so the fresh scan lands on a stable
/// row and the rest reuse it.
pub async fn artifacts_with_digest(db: &PgPool, digest: &str) -> Result<Vec<Uuid>> {
    sqlx::query_scalar(
        "SELECT id FROM (SELECT id, created_at FROM artifacts \
             WHERE checksum_sha256 = $1 AND is_deleted = false \
             ORDER BY created_at DESC, id DESC LIMIT $2) newest \
         ORDER BY created_at, id",
    )
    .bind(digest)
    .bind(MAX_ROWS_PER_DIGEST)
    .fetch_all(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))
}

/// The database clock, which stamps `completed_at`, so "graded since" is
/// compared on one clock.
pub async fn db_now(db: &PgPool) -> Result<DateTime<Utc>> {
    sqlx::query_scalar("SELECT NOW()")
        .fetch_one(db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))
}

#[cfg(ak_test_shard = "services-2")]
#[cfg(test)]
mod tests {
    use super::*;

    fn at(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    #[test]
    fn merge_keeps_the_newest_build_per_scan_type() {
        let merged = merge_builds(
            vec![("grype".into(), at("2026-11-01T00:00:00Z"))],
            vec![
                ("grype".into(), at("2026-11-02T00:00:00Z")),
                ("trivy".into(), at("2026-10-01T00:00:00Z")),
            ],
        );
        assert_eq!(
            merged,
            vec![
                ("grype".to_string(), at("2026-11-02T00:00:00Z")),
                ("trivy".to_string(), at("2026-10-01T00:00:00Z")),
            ]
        );
    }

    #[test]
    fn the_builds_key_changes_only_when_a_build_does() {
        let a = vec![
            ("trivy".to_string(), at("2026-10-01T00:00:00Z")),
            ("grype".to_string(), at("2026-11-01T00:00:00Z")),
        ];
        let mut b = a.clone();
        b.reverse();
        assert_eq!(builds_key(&a), builds_key(&b), "order is not identity");
        let mut c = a.clone();
        c[1].1 = at("2026-11-02T00:00:00Z");
        assert_ne!(builds_key(&a), builds_key(&c));
    }

    // ── DB-backed ───────────────────────────────────────────────────────────
    //
    // `db-serial` (nextest): these clear and count the whole scan_queue and
    // the rescan ledger.

    async fn try_pool() -> Option<PgPool> {
        crate::testing::try_pool_with(3).await
    }

    async fn reset(pool: &PgPool) {
        for sql in [
            "DELETE FROM scan_queue",
            "DELETE FROM scan_rescan_ledger",
            "DELETE FROM scan_rescan_state",
            "DELETE FROM scan_vuln_db_builds",
        ] {
            sqlx::query(sql).execute(pool).await.expect(sql);
        }
    }

    async fn repo(pool: &PgPool) -> Uuid {
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO repositories (id, key, name, storage_path, repo_type, format) \
             VALUES ($1, $2, $2, $3, 'local', 'generic')",
        )
        .bind(id)
        .bind(format!("rescan-test-{id}"))
        .bind(format!("/tmp/rescan-test/{id}"))
        .execute(pool)
        .await
        .expect("repository");
        sqlx::query(
            "INSERT INTO scan_configs (repository_id, scan_enabled, scan_on_upload, \
                 scan_on_proxy, block_on_policy_violation, severity_threshold) \
             VALUES ($1, true, false, false, false, 'high')",
        )
        .bind(id)
        .execute(pool)
        .await
        .expect("scan config");
        id
    }

    /// An artifact with a completed `malware` scan graded against `db_at`.
    async fn scanned(pool: &PgPool, repo: Uuid, digest: &str, db_at: &str) -> Uuid {
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO artifacts (id, repository_id, path, name, size_bytes, \
             checksum_sha256, content_type, storage_key) \
             VALUES ($1, $2, $3, $3, 1, $4, 'application/octet-stream', $3)",
        )
        .bind(id)
        .bind(repo)
        .bind(format!("p/{id}"))
        .bind(digest)
        .execute(pool)
        .await
        .expect("artifact");
        sqlx::query(
            "INSERT INTO scan_results (artifact_id, repository_id, scan_type, status, \
             checksum_sha256, completed_at, vuln_db_version, vuln_db_published_at) \
             VALUES ($1, $2, 'malware', 'completed', $3, NOW(), 'probe-db', $4)",
        )
        .bind(id)
        .bind(repo)
        .bind(digest)
        .bind(at(db_at))
        .execute(pool)
        .await
        .expect("scan row");
        id
    }

    async fn rescan_digests(pool: &PgPool) -> Vec<(String, i16)> {
        sqlx::query_as(
            "SELECT digest, priority FROM scan_queue WHERE kind = 'rescan' ORDER BY digest",
        )
        .fetch_all(pool)
        .await
        .expect("rescan jobs")
    }

    fn digest(c: char) -> String {
        c.to_string().repeat(64)
    }

    /// A new build queues ONE rescan per distinct digest, not one per
    /// artifact row: `a` is stored in two repositories. A digest already
    /// graded against the new build is not queued, and a second tick for the
    /// same build queues nothing more.
    #[tokio::test]
    async fn a_db_build_change_queues_one_rescan_per_distinct_digest() {
        let Some(pool) = try_pool().await else { return };
        reset(&pool).await;
        let (r1, r2) = (repo(&pool).await, repo(&pool).await);
        let (a, b, fresh) = (digest('a'), digest('b'), digest('f'));
        scanned(&pool, r1, &a, "2026-11-01T00:00:00Z").await;
        scanned(&pool, r2, &a, "2026-11-01T00:00:00Z").await;
        scanned(&pool, r1, &b, "2026-11-01T00:00:00Z").await;
        scanned(&pool, r2, &fresh, "2026-11-10T00:00:00Z").await;

        let builds = vec![("malware".to_string(), at("2026-11-10T00:00:00Z"))];
        assert_eq!(enqueue_rescans(&pool, &builds, 100).await.expect("tick"), 2);
        assert_eq!(
            rescan_digests(&pool).await,
            vec![(a.clone(), PRIORITY_RESCAN), (b.clone(), PRIORITY_RESCAN)]
        );
        assert_eq!(
            enqueue_rescans(&pool, &builds, 100).await.expect("again"),
            0,
            "one pass per build"
        );

        // The jobs completed (deleted); the ledger still remembers the build.
        sqlx::query("DELETE FROM scan_queue")
            .execute(&pool)
            .await
            .unwrap();
        assert_eq!(
            enqueue_rescans(&pool, &builds, 100).await.expect("after"),
            0
        );

        // The next build queues them again.
        let newer = vec![("malware".to_string(), at("2026-11-12T00:00:00Z"))];
        assert_eq!(enqueue_rescans(&pool, &newer, 100).await.expect("newer"), 3);

        for r in [r1, r2] {
            sqlx::query("DELETE FROM repositories WHERE id = $1")
                .bind(r)
                .execute(&pool)
                .await
                .unwrap();
        }
        reset(&pool).await;
    }

    /// Counts its scans and grades against a newer database than the rows
    /// the test seeds.
    struct CountingProbe(std::sync::Arc<std::sync::atomic::AtomicUsize>);

    const NEW_DB: &str = "2026-11-12T00:00:00Z";

    #[async_trait::async_trait]
    impl crate::services::scanner_service::Scanner for CountingProbe {
        fn name(&self) -> &str {
            "rescan-probe"
        }
        fn scan_type(&self) -> &str {
            "malware"
        }
        async fn scan(
            &self,
            _artifact: &crate::models::artifact::Artifact,
            _metadata: Option<&crate::models::artifact::ArtifactMetadata>,
            _content: &bytes::Bytes,
        ) -> Result<crate::services::scanner_service::ScanOutput> {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            assert!(
                crate::services::scan_queue::in_background_band(),
                "a rescan runs in the background band"
            );
            Ok(crate::services::scanner_service::ScanOutput {
                vuln_db: Some(crate::models::security::VulnDbProvenance {
                    version: "probe-db".to_string(),
                    published_at: Some(at(NEW_DB)),
                }),
                ..Default::default()
            })
        }
    }

    /// End to end through the worker: one `rescan` job for a digest two rows
    /// hold scans the bytes ONCE, gives both rows a result graded against the
    /// new database (the second a reuse of the first), and leaves the earlier
    /// results exactly as they were.
    #[tokio::test]
    async fn a_rescan_job_scans_a_digest_once_and_keeps_history_queued() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        reset(&fx.pool).await;
        sqlx::query(
            "INSERT INTO scan_configs (repository_id, scan_enabled, scan_on_upload, \
                 scan_on_proxy, block_on_policy_violation, severity_threshold) \
             VALUES ($1, true, false, false, false, 'high')",
        )
        .bind(fx.repo_id)
        .execute(&fx.pool)
        .await
        .expect("scan config");

        let content = bytes::Bytes::from_static(b"rescan-5947-content");
        let digest = {
            use sha2::Digest as _;
            hex::encode(sha2::Sha256::digest(&content))
        };
        let repo = fx.repo_info("local", None);
        let mut rows = Vec::new();
        for name in ["first.bin", "second.bin"] {
            let path = format!("rescan/{name}");
            let id = tdh::seed_artifact_with_checksum(
                &fx.state,
                &fx.pool,
                &repo,
                &path,
                &path,
                name,
                "1.0",
                "application/octet-stream",
                content.clone(),
                fx.user_id,
                &digest,
            )
            .await;
            let old: Uuid = sqlx::query_scalar(
                "INSERT INTO scan_results (artifact_id, repository_id, scan_type, status, \
                 checksum_sha256, completed_at, vuln_db_version, vuln_db_published_at) \
                 VALUES ($1, $2, 'malware', 'completed', $3, NOW() - INTERVAL '1 hour', \
                         'probe-db', $4) RETURNING id",
            )
            .bind(id)
            .bind(fx.repo_id)
            .bind(&digest)
            .bind(at("2026-11-01T00:00:00Z"))
            .fetch_one(&fx.pool)
            .await
            .expect("old scan row");
            rows.push((id, old));
        }

        let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let storage_path = fx.storage_dir.to_string_lossy().into_owned();
        let state = tdh::build_scan_state_with_leaf_scanners(
            &fx,
            &storage_path,
            vec![std::sync::Arc::new(CountingProbe(calls.clone()))],
        );
        let builds = refresh_builds(&fx.pool, &[("malware".to_string(), at(NEW_DB))])
            .await
            .expect("record the build");
        assert_eq!(
            enqueue_rescans(&fx.pool, &builds, 10).await.expect("tick"),
            1,
            "one job for the digest both rows hold"
        );
        let (_state, _worker) = tdh::with_scan_worker(state);

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        loop {
            let left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM scan_queue")
                .fetch_one(&fx.pool)
                .await
                .unwrap();
            let fresh: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM scan_results WHERE repository_id = $1 \
                 AND status = 'completed' AND vuln_db_published_at = $2",
            )
            .bind(fx.repo_id)
            .bind(at(NEW_DB))
            .fetch_one(&fx.pool)
            .await
            .unwrap();
            if (left == 0 && fresh >= 2) || std::time::Instant::now() > deadline {
                assert_eq!(left, 0, "the rescan job must complete");
                assert_eq!(fresh, 2, "both rows get a result on the new database");
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        assert_eq!(
            calls.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "the digest is scanned once, not once per row"
        );

        let (first, first_old) = rows[0];
        let (second, second_old) = rows[1];
        let first_new: Uuid =
            sqlx::query_scalar("SELECT id FROM scan_results WHERE artifact_id = $1 AND id <> $2")
                .bind(first)
                .bind(first_old)
                .fetch_one(&fx.pool)
                .await
                .expect("first row's new result");
        let (reused, source): (bool, Option<Uuid>) = sqlx::query_as(
            "SELECT is_reused, source_scan_id FROM scan_results \
             WHERE artifact_id = $1 AND id <> $2",
        )
        .bind(second)
        .bind(second_old)
        .fetch_one(&fx.pool)
        .await
        .expect("second row's new result");
        assert!(reused, "the second row reuses the fresh scan");
        assert_eq!(source, Some(first_new));

        // History: the earlier results are still there, untouched.
        for old in [first_old, second_old] {
            let (status, db_at): (String, Option<DateTime<Utc>>) = sqlx::query_as(
                "SELECT status, vuln_db_published_at FROM scan_results WHERE id = $1",
            )
            .bind(old)
            .fetch_one(&fx.pool)
            .await
            .expect("old row kept");
            assert_eq!(status, "completed");
            assert_eq!(db_at, Some(at("2026-11-01T00:00:00Z")));
        }

        reset(&fx.pool).await;
        fx.teardown().await;
    }

    /// #5947 review (B2): a builds-key change while the first pass is still
    /// pending must not re-charge the daily cap for digests already queued.
    /// Before, the ledger took every selected digest even when the queue
    /// insert hit `ON CONFLICT DO NOTHING`, so the second pass spent 3 of the
    /// cap and queued nothing.
    #[tokio::test]
    async fn a_key_change_does_not_recharge_digests_already_queued() {
        let Some(pool) = try_pool().await else { return };
        reset(&pool).await;
        let r = repo(&pool).await;
        for c in ['g', 'h', 'i'] {
            scanned(&pool, r, &digest(c), "2026-11-01T00:00:00Z").await;
        }
        let first = vec![("malware".to_string(), at("2026-11-10T00:00:00Z"))];
        assert_eq!(enqueue_rescans(&pool, &first, 4).await.expect("first"), 3);

        // Another database moves before any of the three ran: a new key.
        let second = vec![
            ("malware".to_string(), at("2026-11-10T00:00:00Z")),
            ("image".to_string(), at("2026-11-11T00:00:00Z")),
        ];
        assert_eq!(
            enqueue_rescans(&pool, &second, 4).await.expect("second"),
            0,
            "all three are still queued"
        );
        let charged: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM scan_rescan_ledger")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(charged, 3, "only what was actually queued is charged");

        // So the fourth slot of the cap is still there for a new stale digest.
        scanned(&pool, r, &digest('j'), "2026-11-01T00:00:00Z").await;
        let third = vec![
            ("malware".to_string(), at("2026-11-10T00:00:00Z")),
            ("image".to_string(), at("2026-11-12T00:00:00Z")),
        ];
        assert_eq!(enqueue_rescans(&pool, &third, 4).await.expect("third"), 1);
        assert_eq!(rescan_digests(&pool).await.len(), 4);

        sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(r)
            .execute(&pool)
            .await
            .unwrap();
        reset(&pool).await;
    }

    /// #5947 review (B3): a build seen once is kept. With no recent scan and
    /// no live probe the scan type is still compared (and the key unchanged),
    /// and a build never moves backwards.
    #[tokio::test]
    async fn a_known_build_survives_a_quiet_spell() {
        let Some(pool) = try_pool().await else { return };
        reset(&pool).await;
        let newer = at("2026-11-10T00:00:00.123456789Z");
        let kept = refresh_builds(&pool, &merge_builds(vec![("image".into(), newer)], vec![]))
            .await
            .expect("record");
        let quiet = refresh_builds(&pool, &[]).await.expect("nothing seen");
        assert_eq!(quiet, kept, "nothing seen recently: the build is kept");
        assert_eq!(builds_key(&quiet), builds_key(&kept));
        let older = refresh_builds(&pool, &[("image".into(), at("2026-11-01T00:00:00Z"))])
            .await
            .expect("older");
        assert_eq!(older, kept, "a build never moves backwards");
        // Truncated to Postgres' microseconds, so the probe's value keys the
        // same as the stored one.
        assert_eq!(
            merge_builds(vec![("image".into(), newer)], vec![]),
            kept,
            "the live value and the stored value are one key"
        );
        assert_eq!(
            rescan_scan_types(&pool).await.expect("types"),
            vec!["image"]
        );
        reset(&pool).await;
    }

    /// `SCAN_RESCAN_MAX_PER_DAY=0`, the default, queues nothing and selects
    /// nothing; a cap of 1 queues one digest a day.
    #[tokio::test]
    async fn the_daily_cap_bounds_the_rescans_and_zero_queues_none() {
        let Some(pool) = try_pool().await else { return };
        reset(&pool).await;
        let r = repo(&pool).await;
        for c in ['c', 'd', 'e'] {
            scanned(&pool, r, &digest(c), "2026-11-01T00:00:00Z").await;
        }
        let builds = vec![("malware".to_string(), at("2026-11-10T00:00:00Z"))];

        assert_eq!(enqueue_rescans(&pool, &builds, 0).await.expect("off"), 0);
        assert!(rescan_digests(&pool).await.is_empty(), "off queues nothing");
        let ledger: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM scan_rescan_ledger")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(ledger, 0, "off writes nothing either");

        assert_eq!(enqueue_rescans(&pool, &builds, 1).await.expect("cap 1"), 1);
        assert_eq!(
            enqueue_rescans(&pool, &builds, 1).await.expect("cap spent"),
            0,
            "the day's budget is spent"
        );
        assert_eq!(rescan_digests(&pool).await.len(), 1);

        sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(r)
            .execute(&pool)
            .await
            .unwrap();
        reset(&pool).await;
    }
}
