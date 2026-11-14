//! Durable scan queue: enqueue, claim, finalize. Keeps grype off the request path.
//!
//! A `RowClaimedQueue` ([`crate::services::cluster_work`]), the claim CTE follows
//! `sync_worker::claim_pending_sync_tasks`. Schema in migration 362.
//!
//! Jobs carry a storage reference, never the bytes, and that reference may
//! dangle: the proxy cache write is best-effort, so the worker retries then drops.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{AppError, Result};
use crate::services::cluster_work::Claimed;

/// Claim lease, heartbeaten while the scan runs: bounds how long a dead pod's
/// jobs sit idle, not how long a scan may take.
pub const CLAIM_TTL_SECS: f64 = 120.0;

/// Priority bands. A client is parked on a fail-closed job, so it outranks
/// fail-open backfill, which outranks work nobody waits on.
pub const PRIORITY_CLIENT_WAITING: i16 = 100;
pub const PRIORITY_BACKFILL: i16 = 50;
pub const PRIORITY_HOSTED: i16 = 10;

/// The claim CTE sorts on these, and getting the order wrong is a silent
/// latency regression rather than a failure, so assert it at compile time.
const _: () = {
    assert!(PRIORITY_CLIENT_WAITING > PRIORITY_BACKFILL);
    assert!(PRIORITY_BACKFILL > PRIORITY_HOSTED);
};

/// Claim extension for one job. Binds `$1 = id`, `$2 = token`, `$3 = ttl`.
pub const RENEW_CLAIM_SQL: &str = r#"
    UPDATE scan_queue
    SET claim_expires_at = NOW() + make_interval(secs => $3),
        updated_at = NOW()
    WHERE id = $1
      AND state = 'running'
      AND claim_token = $2
"#;

/// The OCI manifest-row test both sides of a `hosted_image` job use (#5946):
/// the enqueue side classifies an upload with it and the worker selects the
/// rows to scan with it, so a row one side counts is a row the other finds. A
/// leading `/` is tolerated, as `parse_oci_manifest_path` tolerates it.
macro_rules! oci_manifest_path_predicate {
    () => {
        "ltrim(path, '/') LIKE 'v2/%/manifests/%'"
    };
}

/// An upload's digest and whether it is an OCI manifest row. Binds `$1 =
/// artifact id`, `$2 = repository id`.
pub const UPLOAD_SCAN_TARGET_SQL: &str = concat!(
    "SELECT checksum_sha256, ",
    oci_manifest_path_predicate!(),
    " AS is_manifest FROM artifacts WHERE id = $1 AND repository_id = $2 AND is_deleted = false"
);

/// Every live manifest row in a repository whose bytes are one digest: all the
/// tags and digest references that point at that manifest, including tags
/// pushed before or after the push that queued the job. Binds `$1 =
/// repository id`, `$2 = digest`.
pub const HOSTED_IMAGE_ROWS_SQL: &str = concat!(
    "SELECT id FROM artifacts WHERE repository_id = $1 AND checksum_sha256 = $2 ",
    "AND is_deleted = false AND ",
    oci_manifest_path_predicate!(),
    " ORDER BY created_at, id"
);

/// Wakes a same-process worker on enqueue so a fail-closed pull does not wait out
/// a tick. `notify_one` parks a permit, so an enqueue between ticks is not lost.
static ENQUEUE_SIGNAL: std::sync::OnceLock<std::sync::Arc<tokio::sync::Notify>> =
    std::sync::OnceLock::new();

/// The process-wide enqueue signal. Cheap to call from either side.
pub fn enqueue_signal() -> &'static std::sync::Arc<tokio::sync::Notify> {
    ENQUEUE_SIGNAL.get_or_init(|| std::sync::Arc::new(tokio::sync::Notify::new()))
}

/// Which shape of work a job is. Migration 362's CHECK keeps the kind and its
/// payload columns in agreement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanJobKind {
    /// A buffered proxy file: scan the cached object at `cache_path`.
    ProxyFile,
    /// A hosted artifact whose `scan_results` placeholders already exist.
    HostedArtifact,
    /// A `scan_on_upload` for one artifact row, run as the in-process trigger
    /// runs it. Migration 383.
    HostedUpload,
    /// A pushed OCI manifest: repository plus manifest digest. The worker scans
    /// every manifest row in that repository with the digest. Migration 383.
    HostedImage,
}

impl ScanJobKind {
    /// Every kind this build runs, for gauges that must publish each one.
    pub const ALL: [Self; 4] = [
        Self::ProxyFile,
        Self::HostedArtifact,
        Self::HostedUpload,
        Self::HostedImage,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::ProxyFile => "proxy_file",
            Self::HostedArtifact => "hosted_artifact",
            Self::HostedUpload => "hosted_upload",
            Self::HostedImage => "hosted_image",
        }
    }

    /// `None` for an unknown kind: a mixed-version fleet sees those mid-deploy, and
    /// stamping them `failed` would discard work another replica can run.
    pub fn from_db(value: &str) -> Option<Self> {
        match value {
            "proxy_file" => Some(Self::ProxyFile),
            "hosted_artifact" => Some(Self::HostedArtifact),
            "hosted_upload" => Some(Self::HostedUpload),
            "hosted_image" => Some(Self::HostedImage),
            _ => None,
        }
    }
}

/// A queued job. Payload columns are nullable per kind, each branch reads only
/// what its CHECK constraint guarantees.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ScanJob {
    pub id: Uuid,
    pub kind: String,
    pub priority: i16,
    pub repository_id: Option<Uuid>,
    pub cache_path: Option<String>,
    pub digest: Option<String>,
    pub content_type: Option<String>,
    pub size_bytes: Option<i64>,
    pub expected_ecosystem: Option<String>,
    pub expected_name: Option<String>,
    pub expected_version: Option<String>,
    pub artifact_id: Option<Uuid>,
    pub prepared: Option<serde_json::Value>,
    pub bypass_dedup: bool,
    pub attempts: i32,
    pub max_attempts: i32,
    pub created_at: DateTime<Utc>,
}

impl ScanJob {
    /// The decoded kind, or `None` for a kind this build does not know.
    pub fn job_kind(&self) -> Option<ScanJobKind> {
        ScanJobKind::from_db(&self.kind)
    }

    /// The identity these bytes are served as (#3003). `Err` means an undecodable
    /// ecosystem: leave the job, since unpinned `clean` would be a lie.
    pub fn expected_component(
        &self,
    ) -> std::result::Result<Option<crate::services::scanner_service::ExpectedComponent>, String>
    {
        use crate::services::scanner_service::{ComponentEcosystem, ExpectedComponent};
        match (
            self.expected_ecosystem.as_deref(),
            self.expected_name.as_deref(),
            self.expected_version.as_deref(),
        ) {
            (None, None, None) => Ok(None),
            (Some(eco), Some(name), Some(version)) => match ComponentEcosystem::from_db_str(eco) {
                Some(ecosystem) => Ok(Some(ExpectedComponent::new(ecosystem, name, version))),
                None => Err(format!("unknown expected ecosystem {eco:?}")),
            },
            // The CHECK constraint makes this unreachable from a well-formed
            // row. Refusing rather than dropping the pin keeps a schema drift
            // from silently disabling the assessment gate.
            _ => Err("expected component is partially populated".to_string()),
        }
    }

    /// Any attempts left after the one about to be recorded.
    pub fn will_retry_after_failure(&self) -> bool {
        self.attempts + 1 < self.max_attempts
    }
}

/// Depth for one `(kind, state)`, the scaling signal.
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize, utoipa::ToSchema)]
pub struct ScanQueueDepth {
    pub kind: String,
    pub state: String,
    pub jobs: i64,
    pub oldest_pending_secs: Option<f64>,
}

/// One live queue row, for the operator-facing queue view.
#[derive(Debug, Clone, serde::Serialize, utoipa::ToSchema)]
pub struct ScanQueueJobRow {
    pub id: Uuid,
    pub kind: String,
    pub state: String,
    pub priority: i16,
    pub attempts: i32,
    pub max_attempts: i32,
    pub repository_id: Option<Uuid>,
    /// The proxy-cache path a `proxy_file` job reads back.
    pub target: Option<String>,
    pub digest: Option<String>,
    pub artifact_id: Option<Uuid>,
    pub last_error: Option<String>,
    pub claimed_by: Option<String>,
    pub created_at: DateTime<Utc>,
    pub next_attempt_at: DateTime<Utc>,
    pub claim_expires_at: Option<DateTime<Utc>>,
}

/// Enqueue / claim / finalize over `scan_queue`.
#[derive(Clone)]
pub struct ScanQueue {
    db: PgPool,
}

impl ScanQueue {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    /// Queue a scan of the proxy object cached at `cache_path`. Returns
    /// whether a row was inserted: a burst pulling the same digest, or a second
    /// replica serving the same bytes, dedups to one.
    #[allow(clippy::too_many_arguments)]
    pub async fn enqueue_proxy_file(
        &self,
        repository_id: Uuid,
        cache_path: &str,
        digest: &str,
        content_type: Option<&str>,
        size_bytes: i64,
        expected: Option<&crate::services::scanner_service::ExpectedComponent>,
        priority: i16,
    ) -> Result<bool> {
        use sqlx::Row;
        let result = sqlx::query(
            r#"
            INSERT INTO scan_queue
                (kind, priority, repository_id, cache_path, digest, content_type, size_bytes,
                 expected_ecosystem, expected_name, expected_version)
            VALUES ('proxy_file', $1, $2, $3, $4, $5, $6, $7, $8, $9)
            -- A waiting fail-closed pull must overtake queued backfill; GREATEST
            -- only ever raises, so backfill cannot demote it.
            ON CONFLICT (kind, digest)
                WHERE state IN ('pending', 'running') AND digest IS NOT NULL
                  AND kind <> 'hosted_image'
            DO UPDATE SET
                priority = GREATEST(scan_queue.priority, EXCLUDED.priority),
                updated_at = NOW()
            -- Both report one affected row; xmax is zero only on a fresh insert.
            RETURNING (xmax = 0) AS inserted
            "#,
        )
        .bind(priority)
        .bind(repository_id)
        .bind(cache_path)
        .bind(digest)
        .bind(content_type)
        .bind(size_bytes)
        .bind(expected.map(|e| e.ecosystem.as_db_str()))
        .bind(expected.map(|e| e.name.clone()))
        .bind(expected.map(|e| e.version.clone()))
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
        let inserted: bool = result.try_get("inserted").unwrap_or(false);
        if inserted {
            // Wake an in-process worker now rather than at its next tick.
            enqueue_signal().notify_one();
        }
        Ok(inserted)
    }

    /// Queue a hosted artifact whose `scan_results` placeholders exist. `prepared`
    /// carries their ids so the worker finalizes them instead of orphaning them.
    ///
    /// `false` means a RUNNING job owns an older `prepared` map, so the rows behind
    /// this call will never be finalized and the caller must say so.
    pub async fn enqueue_hosted_artifact(
        &self,
        artifact_id: Uuid,
        prepared: &serde_json::Value,
        bypass_dedup: bool,
        priority: i16,
    ) -> Result<bool> {
        let claimed = sqlx::query(
            r#"
            INSERT INTO scan_queue (kind, priority, artifact_id, prepared, bypass_dedup)
            VALUES ('hosted_artifact', $1, $2, $3, $4)
            -- Pending only: a running worker already took the old map into memory,
            -- so rewriting under it would promise rows it cannot finish.
            ON CONFLICT (kind, artifact_id)
                WHERE state IN ('pending', 'running') AND artifact_id IS NOT NULL
            DO UPDATE SET
                prepared = EXCLUDED.prepared,
                bypass_dedup = EXCLUDED.bypass_dedup,
                priority = GREATEST(scan_queue.priority, EXCLUDED.priority),
                updated_at = NOW()
            WHERE scan_queue.state = 'pending'
            RETURNING id
            "#,
        )
        .bind(priority)
        .bind(artifact_id)
        .bind(prepared)
        .bind(bypass_dedup)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .is_some();
        if claimed {
            // Wake an in-process worker now rather than at its next tick.
            enqueue_signal().notify_one();
        }
        Ok(claimed)
    }

    /// Queue the `scan_on_upload` of one committed artifact row (#5946). Returns
    /// whether a row was inserted. A second upload of the artifact while its job
    /// is pending dedups into it; while it is running, the job is marked to run
    /// again once it completes, since the worker may have read the old bytes.
    pub async fn enqueue_hosted_upload(&self, artifact_id: Uuid, priority: i16) -> Result<bool> {
        let row = sqlx::query(
            r#"
                INSERT INTO scan_queue (kind, priority, artifact_id)
                VALUES ('hosted_upload', $1, $2)
                ON CONFLICT (kind, artifact_id)
                    WHERE state IN ('pending', 'running') AND artifact_id IS NOT NULL
                DO UPDATE SET
                    priority = GREATEST(scan_queue.priority, EXCLUDED.priority),
                    requeue = scan_queue.requeue OR scan_queue.state = 'running',
                    updated_at = NOW()
                RETURNING (xmax = 0) AS inserted
                "#,
        )
        .bind(priority)
        .bind(artifact_id)
        .fetch_one(&self.db)
        .await;
        Self::hosted_enqueued(row)
    }

    /// Queue the scan of a pushed OCI manifest (#5946): one job per
    /// `(repository, digest)`, `digest` being the manifest's sha256 hex as
    /// `artifacts.checksum_sha256` stores it. A push of the same manifest while
    /// the job is pending dedups into it; while it is running, the job is marked
    /// to run again, so a tag pushed after the worker listed the rows is scanned.
    pub async fn enqueue_hosted_image(
        &self,
        repository_id: Uuid,
        digest: &str,
        priority: i16,
    ) -> Result<bool> {
        let row = sqlx::query(
            r#"
                INSERT INTO scan_queue (kind, priority, repository_id, digest)
                VALUES ('hosted_image', $1, $2, $3)
                ON CONFLICT (repository_id, digest)
                    WHERE kind = 'hosted_image' AND state IN ('pending', 'running')
                DO UPDATE SET
                    priority = GREATEST(scan_queue.priority, EXCLUDED.priority),
                    requeue = scan_queue.requeue OR scan_queue.state = 'running',
                    updated_at = NOW()
                RETURNING (xmax = 0) AS inserted
                "#,
        )
        .bind(priority)
        .bind(repository_id)
        .bind(digest)
        .fetch_one(&self.db)
        .await;
        Self::hosted_enqueued(row)
    }

    /// Decode a hosted enqueue's `RETURNING (xmax = 0) AS inserted`.
    fn hosted_enqueued(
        row: std::result::Result<sqlx::postgres::PgRow, sqlx::Error>,
    ) -> Result<bool> {
        use sqlx::Row;
        let row = row.map_err(|e| AppError::Database(e.to_string()))?;
        let inserted: bool = row.try_get("inserted").unwrap_or(false);
        if inserted {
            // Wake an in-process worker now rather than at its next tick.
            enqueue_signal().notify_one();
        }
        Ok(inserted)
    }

    /// Claim up to `limit` due jobs. Select and flip in one statement, so replicas
    /// drain disjoint jobs.
    ///
    /// No per-repo cap, so one repository's burst can monopolize claim slots.
    /// `sync_worker`'s per-target advisory lock is the fix if that starves anyone.
    pub async fn claim(
        &self,
        limit: i64,
        claimed_by: &str,
        claim_ttl_secs: f64,
    ) -> Result<Vec<Claimed<ScanJob>>> {
        use sqlx::{FromRow, Row};

        let rows = sqlx::query(
            r#"
            WITH candidate AS (
                SELECT q.id
                FROM scan_queue q
                WHERE q.state = 'pending'
                  AND q.next_attempt_at <= NOW()
                ORDER BY q.priority DESC, q.created_at ASC
                LIMIT $1
                FOR UPDATE OF q SKIP LOCKED
            ),
            claimed AS (
                UPDATE scan_queue q
                SET state = 'running',
                    -- A claim reads everything afresh, so an earlier mark is spent.
                    requeue = false,
                    claimed_by = $2,
                    claim_token = gen_random_uuid(),
                    claim_expires_at = NOW() + make_interval(secs => $3),
                    updated_at = NOW()
                FROM candidate
                WHERE q.id = candidate.id
                RETURNING q.*
            )
            SELECT
                c.id, c.kind, c.priority,
                c.repository_id, c.cache_path, c.digest, c.content_type, c.size_bytes,
                c.artifact_id, c.prepared, c.bypass_dedup,
                c.expected_ecosystem, c.expected_name, c.expected_version,
                c.attempts, c.max_attempts, c.created_at,
                c.claim_token, c.claimed_by, c.claim_expires_at
            FROM claimed c
            ORDER BY c.priority DESC, c.created_at ASC
            "#,
        )
        .bind(limit)
        .bind(claimed_by)
        .bind(claim_ttl_secs)
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        rows.into_iter()
            .map(|row| {
                let job = ScanJob::from_row(&row)
                    .map_err(|e| AppError::Database(format!("failed to decode scan job: {e}")))?;
                let claim_token: Uuid = row.try_get("claim_token").map_err(|e| {
                    AppError::Database(format!("failed to decode claim_token: {e}"))
                })?;
                let claimed_by: String = row
                    .try_get("claimed_by")
                    .map_err(|e| AppError::Database(format!("failed to decode claimed_by: {e}")))?;
                let claim_expires_at: DateTime<Utc> =
                    row.try_get("claim_expires_at").map_err(|e| {
                        AppError::Database(format!("failed to decode claim_expires_at: {e}"))
                    })?;
                Ok(Claimed::from_claim_row(
                    job,
                    claim_token,
                    claimed_by,
                    claim_expires_at,
                ))
            })
            .collect()
    }

    /// Retire a finished job, token-guarded. Deleted, since the verdict row is the
    /// durable record. `false` means the claim lapsed and someone else owns it.
    ///
    /// A job an enqueue marked `requeue` while it ran (migration 383) goes back
    /// to `pending` instead, with its attempts reset: the new request was never
    /// tried.
    pub async fn complete(&self, job_id: Uuid, claim_token: Uuid) -> Result<bool> {
        // Two statements, requeue first. A mark set between them makes the
        // delete miss, so look once more rather than leave the row running
        // until its lease lapses.
        for _ in 0..3 {
            let requeued = sqlx::query(
                r#"
                UPDATE scan_queue
                SET state = 'pending',
                    requeue = false,
                    attempts = 0,
                    last_error = NULL,
                    next_attempt_at = NOW(),
                    claimed_by = NULL,
                    claim_token = NULL,
                    claim_expires_at = NULL,
                    updated_at = NOW()
                WHERE id = $1 AND state = 'running' AND claim_token = $2 AND requeue
                "#,
            )
            .bind(job_id)
            .bind(claim_token)
            .execute(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
            if requeued.rows_affected() == 1 {
                enqueue_signal().notify_one();
                return Ok(true);
            }
            let deleted = sqlx::query(
                "DELETE FROM scan_queue \
                 WHERE id = $1 AND state = 'running' AND claim_token = $2 AND NOT requeue",
            )
            .bind(job_id)
            .bind(claim_token)
            .execute(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
            if deleted.rows_affected() == 1 {
                return Ok(true);
            }
            let still_ours: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM scan_queue \
                 WHERE id = $1 AND state = 'running' AND claim_token = $2)",
            )
            .bind(job_id)
            .bind(claim_token)
            .fetch_one(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
            if !still_ours {
                return Ok(false);
            }
        }
        Ok(false)
    }

    /// Back to `pending` behind a backoff, or terminal `failed` once attempts run
    /// out. The dedup indexes exclude terminal rows, so a re-pull queues afresh.
    /// A job marked `requeue` goes back to `pending` with a fresh budget either
    /// way, as in [`Self::complete`]; so do [`Self::mark_terminal`] and
    /// [`Self::recover_expired_claims`].
    pub async fn fail(
        &self,
        job_id: Uuid,
        claim_token: Uuid,
        error: &str,
        backoff_secs: f64,
    ) -> Result<bool> {
        let result = sqlx::query(
            r#"
            UPDATE scan_queue
            SET attempts = CASE WHEN requeue THEN 0 ELSE attempts + 1 END,
                last_error = $3,
                -- An enqueue marked it while it ran (migration 383): that
                -- request was never tried, so it does not inherit this
                -- attempt's exhaustion.
                state = CASE
                    WHEN requeue OR attempts + 1 < max_attempts THEN 'pending'
                    ELSE 'failed'
                END,
                requeue = false,
                next_attempt_at = NOW() + make_interval(secs => $4),
                claimed_by = NULL,
                claim_token = NULL,
                claim_expires_at = NULL,
                updated_at = NOW()
            WHERE id = $1
              AND state = 'running'
              AND claim_token = $2
            "#,
        )
        .bind(job_id)
        .bind(claim_token)
        .bind(error)
        .bind(backoff_secs)
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
        Ok(result.rows_affected() == 1)
    }

    /// Hand a claimed job back without charging an attempt: being saturated is a
    /// fact about this pod, and [`Self::fail`] would burn one of three tries.
    pub async fn release(&self, job_id: Uuid, claim_token: Uuid) -> Result<bool> {
        let result = sqlx::query(
            r#"
            UPDATE scan_queue
            SET state = 'pending',
                claimed_by = NULL,
                claim_token = NULL,
                claim_expires_at = NULL,
                updated_at = NOW()
            WHERE id = $1
              AND state = 'running'
              AND claim_token = $2
            "#,
        )
        .bind(job_id)
        .bind(claim_token)
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
        Ok(result.rows_affected() == 1)
    }

    /// Drop terminal rows past `retain_secs`. Kept only for an operator to read
    /// `last_error`, and no other queue here grows without a sweep.
    pub async fn purge_failed(&self, retain_secs: f64) -> Result<u64> {
        let result = sqlx::query(
            "DELETE FROM scan_queue \
             WHERE state = 'failed' AND updated_at < NOW() - make_interval(secs => $1)",
        )
        .bind(retain_secs)
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
        Ok(result.rows_affected())
    }

    /// Retire a job that can never succeed. Unlike [`Self::fail`], an
    /// undecodable payload or an over-cap object gains nothing from retries, so
    /// it spends its attempts immediately.
    pub async fn mark_terminal(
        &self,
        job_id: Uuid,
        claim_token: Uuid,
        error: &str,
    ) -> Result<bool> {
        let result = sqlx::query(
            r#"
            UPDATE scan_queue
            SET state = CASE WHEN requeue THEN 'pending' ELSE 'failed' END,
                attempts = CASE WHEN requeue THEN 0 ELSE max_attempts END,
                next_attempt_at = NOW(),
                requeue = false,
                last_error = $3,
                claimed_by = NULL,
                claim_token = NULL,
                claim_expires_at = NULL,
                updated_at = NOW()
            WHERE id = $1
              AND state = 'running'
              AND claim_token = $2
            "#,
        )
        .bind(job_id)
        .bind(claim_token)
        .bind(error)
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
        Ok(result.rows_affected() == 1)
    }

    /// Requeue work abandoned by a crashed replica, charging the lost attempt so a
    /// job that kills its worker cannot spin forever. Safe from every replica.
    pub async fn recover_expired_claims(&self, backoff_secs: f64) -> Result<u64> {
        let result = sqlx::query(
            r#"
            UPDATE scan_queue
            SET attempts = CASE WHEN requeue THEN 0 ELSE attempts + 1 END,
                state = CASE
                    WHEN requeue OR attempts + 1 < max_attempts THEN 'pending'
                    ELSE 'failed'
                END,
                requeue = false,
                last_error = COALESCE(last_error, 'claim expired; worker vanished mid-scan'),
                next_attempt_at = NOW() + make_interval(secs => $1),
                claimed_by = NULL,
                claim_token = NULL,
                claim_expires_at = NULL,
                updated_at = NOW()
            WHERE state = 'running'
              AND (claim_expires_at IS NULL OR claim_expires_at <= NOW())
            "#,
        )
        .bind(backoff_secs)
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
        Ok(result.rows_affected())
    }

    /// One page of live queue rows. A completed job is deleted, so never history.
    pub async fn list_jobs(
        &self,
        state_filter: Option<&str>,
        kind_filter: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<ScanQueueJobRow>, i64)> {
        use sqlx::Row;
        let rows = sqlx::query(
            r#"
            SELECT
                id, kind, state, priority, attempts, max_attempts,
                repository_id, cache_path, digest, artifact_id,
                last_error, claimed_by, created_at, updated_at, next_attempt_at,
                claim_expires_at,
                COUNT(*) OVER () AS total
            FROM scan_queue
            WHERE ($1::text IS NULL OR state = $1)
              AND ($2::text IS NULL OR kind = $2)
            ORDER BY
                -- Running first, then what is due soonest at the highest band:
                -- the order an operator triaging a backlog wants.
                CASE state WHEN 'running' THEN 0 WHEN 'pending' THEN 1 ELSE 2 END,
                priority DESC,
                created_at
            LIMIT $3 OFFSET $4
            "#,
        )
        .bind(state_filter)
        .bind(kind_filter)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        let total: i64 = match rows.first() {
            Some(r) => r.try_get("total").unwrap_or(0),
            // Past the last page the window has no row to ride on, so count
            // separately rather than report an empty queue.
            None if offset > 0 => sqlx::query_scalar(
                "SELECT COUNT(*) FROM scan_queue \
                 WHERE ($1::text IS NULL OR state = $1) AND ($2::text IS NULL OR kind = $2)",
            )
            .bind(state_filter)
            .bind(kind_filter)
            .fetch_one(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?,
            None => 0,
        };
        let items = rows
            .iter()
            .map(|r| ScanQueueJobRow {
                id: r.get("id"),
                kind: r.get("kind"),
                state: r.get("state"),
                priority: r.get("priority"),
                attempts: r.get("attempts"),
                max_attempts: r.get("max_attempts"),
                repository_id: r.try_get("repository_id").ok().flatten(),
                target: r.try_get("cache_path").ok().flatten(),
                digest: r.try_get("digest").ok().flatten(),
                artifact_id: r.try_get("artifact_id").ok().flatten(),
                last_error: r.try_get("last_error").ok().flatten(),
                claimed_by: r.try_get("claimed_by").ok().flatten(),
                created_at: r.get("created_at"),
                next_attempt_at: r.get("next_attempt_at"),
                claim_expires_at: r.try_get("claim_expires_at").ok().flatten(),
            })
            .collect();
        Ok((items, total))
    }

    /// Distinct workers holding a live (unexpired) claim.
    ///
    /// A lapsed claim is not a consumer: `recover_expired_claims` is about to
    /// hand that row back, and counting the dead replica would overstate
    /// capacity exactly when a worker has vanished, which is when the number
    /// matters most.
    pub async fn consumers(&self) -> Result<i64> {
        sqlx::query_scalar::<_, i64>(
            r#"
            SELECT COUNT(DISTINCT claimed_by)::BIGINT
            FROM scan_queue
            WHERE claimed_by IS NOT NULL
              AND claim_expires_at IS NOT NULL
              AND claim_expires_at > NOW()
            "#,
        )
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))
    }

    /// Depth per `(kind, state)` plus the oldest due job's age. Depth alone cannot
    /// tell a draining queue from a stuck one.
    pub async fn depth(&self) -> Result<Vec<ScanQueueDepth>> {
        sqlx::query_as::<_, ScanQueueDepth>(
            r#"
            SELECT
                kind,
                state,
                COUNT(*)::BIGINT AS jobs,
                MAX(CASE
                    WHEN state = 'pending' AND next_attempt_at <= NOW()
                    THEN EXTRACT(EPOCH FROM (NOW() - created_at))
                END)::DOUBLE PRECISION AS oldest_pending_secs
            FROM scan_queue
            GROUP BY kind, state
            "#,
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))
    }
}

#[cfg(ak_test_shard = "services-2")]
#[cfg(test)]
mod tests {
    use super::*;

    /// An unknown kind decodes to `None`, not a defaulted variant: running a
    /// job as the wrong kind scans the wrong thing.
    #[test]
    fn unknown_kind_decodes_to_none() {
        assert_eq!(
            ScanJobKind::from_db("proxy_file"),
            Some(ScanJobKind::ProxyFile)
        );
        assert_eq!(
            ScanJobKind::from_db("hosted_artifact"),
            Some(ScanJobKind::HostedArtifact)
        );
        assert_eq!(ScanJobKind::from_db("quantum_scan"), None);
        assert_eq!(ScanJobKind::from_db(""), None);
    }

    /// A rename of the stored token would orphan every queued job of that kind.
    #[test]
    fn kind_round_trips_through_its_stored_token() {
        for kind in ScanJobKind::ALL {
            assert_eq!(ScanJobKind::from_db(kind.as_str()), Some(kind));
        }
    }

    fn job_with_attempts(attempts: i32, max_attempts: i32) -> ScanJob {
        ScanJob {
            id: Uuid::new_v4(),
            kind: "proxy_file".to_string(),
            priority: PRIORITY_BACKFILL,
            repository_id: Some(Uuid::new_v4()),
            cache_path: Some("simple/click/click-8.0.0-py3-none-any.whl".to_string()),
            digest: Some("deadbeef".to_string()),
            content_type: Some("application/zip".to_string()),
            size_bytes: Some(4096),
            expected_ecosystem: None,
            expected_name: None,
            expected_version: None,
            artifact_id: None,
            prepared: None,
            bypass_dedup: false,
            attempts,
            max_attempts,
            created_at: Utc::now(),
        }
    }

    /// Mirrors the CASE in `fail`. Off by one means never retrying, or forever.
    #[test]
    fn retry_boundary_matches_the_sql_case() {
        assert!(job_with_attempts(0, 3).will_retry_after_failure());
        assert!(job_with_attempts(1, 3).will_retry_after_failure());
        // Third attempt is the last one: 2 + 1 == max, so terminal.
        assert!(!job_with_attempts(2, 3).will_retry_after_failure());
        assert!(!job_with_attempts(3, 3).will_retry_after_failure());
        // A job configured for a single attempt is terminal on its first failure.
        assert!(!job_with_attempts(0, 1).will_retry_after_failure());
    }

    // ── DB-backed queue semantics ───────────────────────────────────────────
    //
    // `claim` and `recover_expired_claims` are unfiltered by design, so two of
    // these at once would steal each other's jobs. Pinned to the `db-serial`
    // nextest group, which is also what makes the `DELETE FROM scan_queue`
    // below safe and the claim-order assertions exact.

    /// Skips cleanly with no `DATABASE_URL`, panics under
    /// `AK_TESTS_REQUIRE_DB` rather than reporting a green that proved nothing.
    async fn try_pool() -> Option<sqlx::PgPool> {
        crate::testing::try_pool_with(3).await
    }

    /// Fresh repo plus an empty queue, so claim order is exact.
    async fn fresh_queue(pool: &sqlx::PgPool) -> Uuid {
        sqlx::query("DELETE FROM scan_queue")
            .execute(pool)
            .await
            .expect("clear queue");
        let id = Uuid::new_v4();
        let key = format!("scan-queue-test-{id}");
        sqlx::query(
            "INSERT INTO repositories (id, key, name, storage_path, repo_type, format) \
             VALUES ($1, $2, $2, $3, 'local', 'cargo')",
        )
        .bind(id)
        .bind(&key)
        .bind(format!("/tmp/scan-queue-test/{id}"))
        .execute(pool)
        .await
        .expect("seed repository");
        id
    }

    /// Rows cascade from the repository, so dropping it is the cleanup.
    async fn drop_repo(pool: &sqlx::PgPool, repo_id: Uuid) {
        sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(repo_id)
            .execute(pool)
            .await
            .expect("cleanup repository");
    }

    async fn pending_count(pool: &sqlx::PgPool, digest: &str) -> i64 {
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM scan_queue WHERE digest = $1")
            .bind(digest)
            .fetch_one(pool)
            .await
            .expect("count")
    }

    /// A consumer is a worker holding a LIVE claim. A lapsed claim belongs to
    /// a replica that vanished, and counting it would overstate capacity at
    /// exactly the moment a worker died, which is when the number matters.
    #[tokio::test]
    async fn consumers_counts_distinct_live_claimants_only() {
        let Some(pool) = try_pool().await else { return };
        let repo = fresh_queue(&pool).await;
        let q = ScanQueue::new(pool.clone());

        for d in ["cons01", "cons02", "cons03"] {
            q.enqueue_proxy_file(
                repo,
                &format!("c/{d}.crate"),
                d,
                None,
                10,
                None,
                PRIORITY_BACKFILL,
            )
            .await
            .expect("enqueue");
        }
        assert_eq!(
            q.consumers().await.expect("count"),
            0,
            "nothing claimed yet"
        );

        // Two jobs to worker-a, one to worker-b: two distinct consumers.
        q.claim(2, "worker-a", 300.0).await.expect("claim a");
        q.claim(1, "worker-b", 300.0).await.expect("claim b");
        assert_eq!(q.consumers().await.expect("count"), 2);

        // Expire worker-a's claims: it is no longer a consumer.
        sqlx::query(
            "UPDATE scan_queue SET claim_expires_at = NOW() - INTERVAL '1 minute'
             WHERE claimed_by = 'worker-a' AND digest = ANY($1)",
        )
        .bind(vec![
            "cons01".to_string(),
            "cons02".to_string(),
            "cons03".to_string(),
        ])
        .execute(&pool)
        .await
        .expect("expire");
        assert_eq!(
            q.consumers().await.expect("count"),
            1,
            "a lapsed claim is not a live consumer"
        );

        drop_repo(&pool, repo).await;
    }

    /// A page past the last row still reports the real total, so a pager that
    /// overshoots (rows drained between two requests) can step back.
    #[tokio::test]
    async fn list_jobs_reports_the_total_past_the_last_page() {
        let Some(pool) = try_pool().await else { return };
        let repo = fresh_queue(&pool).await;
        let q = ScanQueue::new(pool.clone());
        for d in ["page01", "page02", "page03"] {
            q.enqueue_proxy_file(
                repo,
                &format!("c/{d}.crate"),
                d,
                None,
                10,
                None,
                PRIORITY_BACKFILL,
            )
            .await
            .expect("enqueue");
        }
        let (items, total) = q.list_jobs(None, None, 2, 0).await.expect("page 1");
        assert_eq!((items.len(), total), (2, 3));
        let (items, total) = q.list_jobs(None, None, 2, 10).await.expect("past end");
        assert_eq!((items.len(), total), (0, 3));
        let (items, total) = q
            .list_jobs(Some("failed"), None, 2, 10)
            .await
            .expect("filtered, past end");
        assert_eq!((items.len(), total), (0, 0));
        drop_repo(&pool, repo).await;
    }

    /// The burst that started all of this: repeat pulls of one crate must
    /// queue ONE job. Without the index a 1049-crate fetch queues ~4000.
    #[tokio::test]
    async fn enqueue_dedupes_a_burst_of_the_same_digest() {
        let Some(pool) = try_pool().await else { return };
        let repo = fresh_queue(&pool).await;
        let q = ScanQueue::new(pool.clone());

        let mut inserted = 0;
        for _ in 0..4 {
            if q.enqueue_proxy_file(
                repo,
                "crates/serde-1.0.crate",
                "burst01",
                None,
                100,
                None,
                PRIORITY_BACKFILL,
            )
            .await
            .expect("enqueue")
            {
                inserted += 1;
            }
        }
        assert_eq!(inserted, 1, "only the first enqueue of a digest inserts");
        assert_eq!(pending_count(&pool, "burst01").await, 1);

        drop_repo(&pool, repo).await;
    }

    /// A fail-closed pull that lands on a digest already queued as backfill
    /// must RAISE the existing job's band, not dedup into it silently: a client
    /// is parked on this one, and at priority 50 it waits behind every backfill
    /// job in the queue. `ON CONFLICT DO NOTHING` left it at 50.
    #[tokio::test]
    async fn a_waiting_client_raises_the_priority_of_a_queued_job() {
        let Some(pool) = try_pool().await else { return };
        let repo = fresh_queue(&pool).await;
        let q = ScanQueue::new(pool.clone());

        assert!(
            q.enqueue_proxy_file(
                repo,
                "a/x.crate",
                "prio01",
                None,
                10,
                None,
                PRIORITY_BACKFILL
            )
            .await
            .expect("backfill enqueue"),
            "first enqueue of a digest inserts"
        );
        assert!(
            !q.enqueue_proxy_file(
                repo,
                "a/x.crate",
                "prio01",
                None,
                10,
                None,
                PRIORITY_CLIENT_WAITING
            )
            .await
            .expect("fail-closed enqueue"),
            "still one job for the digest, so this reports no insert"
        );

        let priority =
            sqlx::query_scalar::<_, i16>("SELECT priority FROM scan_queue WHERE digest = 'prio01'")
                .fetch_one(&pool)
                .await
                .expect("read priority");
        assert_eq!(
            priority, PRIORITY_CLIENT_WAITING,
            "the waiting client's band must win"
        );
        assert_eq!(pending_count(&pool, "prio01").await, 1, "still deduped");

        // And it only ever goes up: backfill must not demote a job someone is
        // already blocked on.
        q.enqueue_proxy_file(repo, "a/x.crate", "prio01", None, 10, None, PRIORITY_HOSTED)
            .await
            .expect("late low-priority enqueue");
        let priority =
            sqlx::query_scalar::<_, i16>("SELECT priority FROM scan_queue WHERE digest = 'prio01'")
                .fetch_one(&pool)
                .await
                .expect("read priority again");
        assert_eq!(priority, PRIORITY_CLIENT_WAITING, "GREATEST never demotes");

        drop_repo(&pool, repo).await;
    }

    /// `release` exists because `fail` charges an attempt. A worker that could
    /// not start the job at all must not spend a third of its budget.
    #[tokio::test]
    async fn release_returns_a_job_without_charging_an_attempt() {
        let Some(pool) = try_pool().await else { return };
        let repo = fresh_queue(&pool).await;
        let q = ScanQueue::new(pool.clone());
        q.enqueue_proxy_file(repo, "rel", "rel01", None, 1, None, PRIORITY_BACKFILL)
            .await
            .expect("enqueue");

        let claimed = q.claim(1, "workerA", CLAIM_TTL_SECS).await.expect("claim");
        assert_eq!(claimed.len(), 1);
        let job = &claimed[0];
        assert!(
            q.release(job.id, job.claim_token()).await.expect("release"),
            "the claim holder can release"
        );

        let (state, attempts) =
            sqlx::query_as::<_, (String, i32)>("SELECT state, attempts FROM scan_queue")
                .fetch_one(&pool)
                .await
                .expect("read row");
        assert_eq!(state, "pending", "back on the queue immediately");
        assert_eq!(attempts, 0, "and untouched: fail would have made this 1");

        // Claimable again, by anyone.
        let again = q
            .claim(1, "workerB", CLAIM_TTL_SECS)
            .await
            .expect("reclaim");
        assert_eq!(again.len(), 1);

        drop_repo(&pool, repo).await;
    }

    /// Exactly one worker gets a job, for any interleaving: the CTE flips
    /// `pending -> running` in the statement that selects it.
    #[tokio::test]
    async fn claim_hands_a_job_to_exactly_one_worker() {
        let Some(pool) = try_pool().await else { return };
        let repo = fresh_queue(&pool).await;
        let q = ScanQueue::new(pool.clone());
        q.enqueue_proxy_file(repo, "solo", "solo01", None, 1, None, PRIORITY_BACKFILL)
            .await
            .expect("enqueue");

        let (a, b) = tokio::join!(
            q.claim(4, "workerA", CLAIM_TTL_SECS),
            q.claim(4, "workerB", CLAIM_TTL_SECS)
        );
        let a = a.expect("claim A");
        let b = b.expect("claim B");
        assert_eq!(
            a.len() + b.len(),
            1,
            "exactly one worker may hold a job; got A={} B={}",
            a.len(),
            b.len()
        );

        // And the winner holds a real token, which every finalizer predicates on.
        let winner = a.into_iter().chain(b).next().expect("a winner");
        assert_ne!(winner.claim_token(), Uuid::nil());
        assert!(matches!(winner.job_kind(), Some(ScanJobKind::ProxyFile)));

        drop_repo(&pool, repo).await;
    }

    /// With more pending than slots, the highest-priority jobs are the ones
    /// taken.
    ///
    /// Claiming ONE AT A TIME is the point: an earlier version claimed the
    /// whole backlog and passed with `priority DESC` deleted, because the outer
    /// `SELECT` re-sorts whatever the CTE picked.
    #[tokio::test]
    async fn claim_selects_the_highest_priority_jobs_first() {
        let Some(pool) = try_pool().await else { return };
        let repo = fresh_queue(&pool).await;
        let q = ScanQueue::new(pool.clone());

        // Inserted worst-first so insertion order cannot be what passes this.
        q.enqueue_proxy_file(repo, "c", "hosted01", None, 1, None, PRIORITY_HOSTED)
            .await
            .expect("enqueue hosted-priority");
        q.enqueue_proxy_file(repo, "a", "backfill1", None, 1, None, PRIORITY_BACKFILL)
            .await
            .expect("enqueue backfill");
        q.enqueue_proxy_file(
            repo,
            "b",
            "waiting01",
            None,
            1,
            None,
            PRIORITY_CLIENT_WAITING,
        )
        .await
        .expect("enqueue client-waiting");

        let mut picked = Vec::new();
        for _ in 0..3 {
            let job = q
                .claim(1, "w", CLAIM_TTL_SECS)
                .await
                .expect("claim")
                .pop()
                .expect("a job is due");
            picked.push(job.digest.clone().unwrap_or_default());
        }
        assert_eq!(
            picked,
            vec!["waiting01", "backfill1", "hosted01"],
            "each single-slot claim must take the highest-priority job left"
        );

        drop_repo(&pool, repo).await;
    }

    /// A worker whose claim lapsed must not retire the new owner's job.
    #[tokio::test]
    async fn finalizers_are_token_guarded() {
        let Some(pool) = try_pool().await else { return };
        let repo = fresh_queue(&pool).await;
        let q = ScanQueue::new(pool.clone());
        q.enqueue_proxy_file(repo, "fenced", "fenced01", None, 1, None, PRIORITY_BACKFILL)
            .await
            .expect("enqueue");
        let job = q
            .claim(1, "w", CLAIM_TTL_SECS)
            .await
            .expect("claim")
            .pop()
            .expect("one job");

        assert!(
            !q.complete(job.id, Uuid::new_v4()).await.expect("complete"),
            "a stale token must not retire the job"
        );
        assert!(
            !q.fail(job.id, Uuid::new_v4(), "stale", 0.0)
                .await
                .expect("fail"),
            "a stale token must not fail the job"
        );
        assert_eq!(pending_count(&pool, "fenced01").await, 1, "job still there");

        assert!(
            q.complete(job.id, job.claim_token())
                .await
                .expect("complete"),
            "the real token retires it"
        );
        assert_eq!(
            pending_count(&pool, "fenced01").await,
            0,
            "a retired job is deleted; the verdict row is the durable record"
        );

        drop_repo(&pool, repo).await;
    }

    /// Retries until attempts run out, then terminal. The terminal row must
    /// not block a re-pull, or one bad scan poisons a digest forever.
    #[tokio::test]
    async fn fail_retries_then_goes_terminal_and_frees_the_digest() {
        let Some(pool) = try_pool().await else { return };
        let repo = fresh_queue(&pool).await;
        let q = ScanQueue::new(pool.clone());
        q.enqueue_proxy_file(repo, "flaky", "flaky001", None, 1, None, PRIORITY_BACKFILL)
            .await
            .expect("enqueue");

        // Attempts 1 and 2 return it to `pending` (due immediately, so the
        // next claim can see it).
        for attempt in 1..=2 {
            let job = q
                .claim(1, "w", CLAIM_TTL_SECS)
                .await
                .expect("claim")
                .pop()
                .unwrap_or_else(|| panic!("job should be claimable on attempt {attempt}"));
            assert!(job.will_retry_after_failure(), "attempt {attempt} retries");
            assert!(q
                .fail(job.id, job.claim_token(), "boom", 0.0)
                .await
                .expect("fail"));
        }

        // The third failure is terminal.
        let job = q
            .claim(1, "w", CLAIM_TTL_SECS)
            .await
            .expect("claim")
            .pop()
            .expect("third attempt");
        assert!(!job.will_retry_after_failure(), "third failure is terminal");
        assert!(q
            .fail(job.id, job.claim_token(), "boom", 0.0)
            .await
            .expect("fail"));

        let state: String =
            sqlx::query_scalar("SELECT state FROM scan_queue WHERE digest = 'flaky001'")
                .fetch_one(&pool)
                .await
                .expect("state");
        assert_eq!(state, "failed");
        assert!(
            q.claim(1, "w", CLAIM_TTL_SECS)
                .await
                .expect("claim")
                .is_empty(),
            "a terminal job must not be claimable again"
        );

        // The dedup indexes exclude `failed`, so a re-pull queues afresh.
        assert!(
            q.enqueue_proxy_file(repo, "flaky", "flaky001", None, 1, None, PRIORITY_BACKFILL)
                .await
                .expect("re-enqueue"),
            "a failed row must not poison the digest forever"
        );

        drop_repo(&pool, repo).await;
    }

    /// A pod evicted mid-scan leaves a `running` row nobody will finish. The
    /// sweep returns it and charges the attempt, so a job that kills its worker
    /// cannot spin forever.
    #[tokio::test]
    async fn expired_claims_recover_with_the_attempt_charged() {
        let Some(pool) = try_pool().await else { return };
        let repo = fresh_queue(&pool).await;
        let q = ScanQueue::new(pool.clone());
        q.enqueue_proxy_file(repo, "orphan", "orphan01", None, 1, None, PRIORITY_BACKFILL)
            .await
            .expect("enqueue");
        let job = q
            .claim(1, "doomed-pod", CLAIM_TTL_SECS)
            .await
            .expect("claim")
            .pop()
            .expect("one job");

        // The pod dies: nothing heartbeats the claim, so it lapses.
        sqlx::query(
            "UPDATE scan_queue SET claim_expires_at = NOW() - INTERVAL '1 second' WHERE id = $1",
        )
        .bind(job.id)
        .execute(&pool)
        .await
        .expect("expire the claim");

        assert_eq!(
            q.recover_expired_claims(0.0).await.expect("recover"),
            1,
            "the lapsed claim is swept back"
        );
        let recovered = q
            .claim(1, "healthy-pod", CLAIM_TTL_SECS)
            .await
            .expect("claim")
            .pop()
            .expect("recovered job is claimable");
        assert_eq!(recovered.attempts, 1, "the lost attempt is charged");
        assert_ne!(
            recovered.claim_token(),
            job.claim_token(),
            "the new owner holds a fresh token, fencing the dead one"
        );

        drop_repo(&pool, repo).await;
    }

    /// The security-relevant one. If the #3003 identity does not survive, the
    /// worker scans unpinned, grype grades nothing, and `clean` gets recorded
    /// for a component it never looked at.
    #[tokio::test]
    async fn the_expected_component_survives_the_round_trip() {
        use crate::services::scanner_service::{ComponentEcosystem, ExpectedComponent};
        let Some(pool) = try_pool().await else { return };
        let repo = fresh_queue(&pool).await;
        let q = ScanQueue::new(pool.clone());

        let expected = ExpectedComponent::new(ComponentEcosystem::Python, "click", "8.0.0");
        q.enqueue_proxy_file(
            repo,
            "simple/click/click-8.0.0-py3-none-any.whl",
            "ident001",
            Some("application/zip"),
            4096,
            Some(&expected),
            PRIORITY_CLIENT_WAITING,
        )
        .await
        .expect("enqueue");

        let job = q
            .claim(1, "w", CLAIM_TTL_SECS)
            .await
            .expect("claim")
            .pop()
            .expect("one job");
        assert_eq!(
            job.expected_component().expect("decodes"),
            Some(expected),
            "the pin the request asserted must reach the worker intact"
        );
        assert_eq!(job.content_type.as_deref(), Some("application/zip"));
        assert_eq!(job.size_bytes, Some(4096));

        drop_repo(&pool, repo).await;
    }

    /// No identity is legitimate for formats that assert no coordinate.
    #[tokio::test]
    async fn an_absent_expected_component_decodes_to_none() {
        let Some(pool) = try_pool().await else { return };
        let repo = fresh_queue(&pool).await;
        let q = ScanQueue::new(pool.clone());
        q.enqueue_proxy_file(
            repo,
            "generic/blob.bin",
            "noident1",
            None,
            1,
            None,
            PRIORITY_BACKFILL,
        )
        .await
        .expect("enqueue");
        let job = q
            .claim(1, "w", CLAIM_TTL_SECS)
            .await
            .expect("claim")
            .pop()
            .expect("one job");
        assert_eq!(job.expected_component().expect("decodes"), None);

        drop_repo(&pool, repo).await;
    }

    /// The worker must finalize the placeholder rows the API already handed
    /// its caller, not allocate its own and orphan them.
    #[tokio::test]
    async fn a_hosted_job_carries_the_prepared_placeholder_map() {
        let Some(pool) = try_pool().await else { return };
        let repo = fresh_queue(&pool).await;
        let artifact_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO artifacts (id, repository_id, path, name, size_bytes, \
             checksum_sha256, content_type, storage_key) \
             VALUES ($1, $2, 'p/a.jar', 'a.jar', 1, 'abc', 'application/java-archive', 'k')",
        )
        .bind(artifact_id)
        .bind(repo)
        .execute(&pool)
        .await
        .expect("seed artifact");

        let q = ScanQueue::new(pool.clone());
        let scan_result_id = Uuid::new_v4();
        let prepared = serde_json::json!({ "grype": scan_result_id });
        q.enqueue_hosted_artifact(artifact_id, &prepared, true, PRIORITY_HOSTED)
            .await
            .expect("enqueue");

        let job = q
            .claim(1, "w", CLAIM_TTL_SECS)
            .await
            .expect("claim")
            .pop()
            .expect("one job");
        assert!(matches!(job.job_kind(), Some(ScanJobKind::HostedArtifact)));
        assert_eq!(job.artifact_id, Some(artifact_id));
        let decoded: std::collections::HashMap<String, Uuid> =
            serde_json::from_value(job.prepared.clone().expect("prepared")).expect("decodes");
        assert_eq!(decoded.get("grype"), Some(&scan_result_id));
        assert!(
            job.bypass_dedup,
            "a forced rescan stays forced on the worker"
        );

        drop_repo(&pool, repo).await;
    }

    /// #5946: an image job is one per (repository, digest). The same digest
    /// in another repository is its own job (findings are per artifact row),
    /// and a proxy_file job of that digest keeps its fleet-wide dedup.
    #[tokio::test]
    async fn hosted_image_dedups_per_repository_and_digest() {
        let Some(pool) = try_pool().await else { return };
        let repo_a = fresh_queue(&pool).await;
        let repo_b = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO repositories (id, key, name, storage_path, repo_type, format) \
             VALUES ($1, $2, $2, $3, 'local', 'docker')",
        )
        .bind(repo_b)
        .bind(format!("scan-queue-test-{repo_b}"))
        .bind(format!("/tmp/scan-queue-test/{repo_b}"))
        .execute(&pool)
        .await
        .expect("seed second repository");
        let q = ScanQueue::new(pool.clone());

        assert!(q
            .enqueue_hosted_image(repo_a, "img01", PRIORITY_HOSTED)
            .await
            .expect("first"));
        assert!(
            !q.enqueue_hosted_image(repo_a, "img01", PRIORITY_HOSTED)
                .await
                .expect("again"),
            "the same manifest in the same repository dedups"
        );
        assert!(
            q.enqueue_hosted_image(repo_b, "img01", PRIORITY_HOSTED)
                .await
                .expect("other repo"),
            "another repository's push of the digest is its own job"
        );
        assert!(
            q.enqueue_proxy_file(repo_a, "x", "img01", None, 1, None, PRIORITY_BACKFILL)
                .await
                .expect("proxy"),
            "a proxy_file job of the digest is unaffected"
        );
        assert_eq!(pending_count(&pool, "img01").await, 3);

        drop_repo(&pool, repo_a).await;
        drop_repo(&pool, repo_b).await;
    }

    /// #5946: a push that lands while its job RUNS cannot be dropped, the
    /// worker listed the rows before it. Completing the job sends it back to
    /// `pending` with a fresh attempt budget; completing that one retires it.
    #[tokio::test]
    async fn an_enqueue_on_a_running_hosted_job_runs_it_again() {
        let Some(pool) = try_pool().await else { return };
        let repo = fresh_queue(&pool).await;
        let q = ScanQueue::new(pool.clone());
        q.enqueue_hosted_image(repo, "again01", PRIORITY_HOSTED)
            .await
            .expect("enqueue");
        let job = q
            .claim(1, "w", CLAIM_TTL_SECS)
            .await
            .expect("claim")
            .pop()
            .expect("one job");
        assert!(matches!(job.job_kind(), Some(ScanJobKind::HostedImage)));

        assert!(
            !q.enqueue_hosted_image(repo, "again01", PRIORITY_HOSTED)
                .await
                .expect("push while running"),
            "still one row for the key"
        );
        assert!(q
            .complete(job.id, job.claim_token())
            .await
            .expect("complete"));
        let (state, attempts, requeue) = sqlx::query_as::<_, (String, i32, bool)>(
            "SELECT state, attempts, requeue FROM scan_queue WHERE digest = 'again01'",
        )
        .fetch_one(&pool)
        .await
        .expect("row kept");
        assert_eq!(
            (state.as_str(), attempts, requeue),
            ("pending", 0, false),
            "the job must run again for the push that arrived mid-scan"
        );

        let again = q
            .claim(1, "w", CLAIM_TTL_SECS)
            .await
            .expect("claim")
            .pop()
            .expect("due again");
        assert_eq!(again.id, job.id);
        assert!(q
            .complete(again.id, again.claim_token())
            .await
            .expect("complete"));
        assert_eq!(pending_count(&pool, "again01").await, 0, "now retired");

        drop_repo(&pool, repo).await;
    }

    /// #5946 review (A1): a push that lands during the LAST attempt must not be
    /// lost when that attempt fails, is retired as unrunnable, or dies with
    /// its worker. Each finalizer sends a `requeue`-marked job back to
    /// `pending` with a fresh budget instead of leaving it `failed`.
    #[tokio::test]
    async fn a_push_during_the_last_attempt_survives_every_finalizer() {
        let Some(pool) = try_pool().await else { return };
        for finalizer in ["fail", "mark_terminal", "recover_expired_claims"] {
            let repo = fresh_queue(&pool).await;
            let q = ScanQueue::new(pool.clone());
            q.enqueue_hosted_image(repo, "last01", PRIORITY_HOSTED)
                .await
                .expect("enqueue");
            // Two attempts already spent: this claim is the last one.
            sqlx::query("UPDATE scan_queue SET attempts = max_attempts - 1")
                .execute(&pool)
                .await
                .expect("spend attempts");
            let job = q
                .claim(1, "w", CLAIM_TTL_SECS)
                .await
                .expect("claim")
                .pop()
                .expect("one job");
            assert!(!job.will_retry_after_failure(), "this is the last attempt");
            assert!(!q
                .enqueue_hosted_image(repo, "last01", PRIORITY_HOSTED)
                .await
                .expect("push while running"));

            match finalizer {
                "fail" => {
                    assert!(q
                        .fail(job.id, job.claim_token(), "boom", 0.0)
                        .await
                        .expect("fail"));
                }
                "mark_terminal" => {
                    assert!(q
                        .mark_terminal(job.id, job.claim_token(), "unrunnable")
                        .await
                        .expect("terminal"));
                }
                _ => {
                    sqlx::query(
                        "UPDATE scan_queue SET claim_expires_at = NOW() - INTERVAL '1 second'",
                    )
                    .execute(&pool)
                    .await
                    .expect("lapse the claim");
                    assert_eq!(q.recover_expired_claims(0.0).await.expect("recover"), 1);
                }
            }

            let (state, attempts, requeue) = sqlx::query_as::<_, (String, i32, bool)>(
                "SELECT state, attempts, requeue FROM scan_queue WHERE digest = 'last01'",
            )
            .fetch_one(&pool)
            .await
            .expect("row kept");
            assert_eq!(
                (state.as_str(), attempts, requeue),
                ("pending", 0, false),
                "{finalizer}: the push that arrived mid-scan must still be scanned"
            );
            assert!(
                !q.claim(1, "w", CLAIM_TTL_SECS)
                    .await
                    .expect("claim again")
                    .is_empty(),
                "{finalizer}: and it is due"
            );
            drop_repo(&pool, repo).await;
        }
    }

    /// #5946 review (A2): the enqueue side and the worker agree on what an
    /// OCI manifest row is. A row stored with a leading `/` is queued as a
    /// `hosted_image` job AND found by the worker's row query; before, the
    /// worker's `LIKE 'v2/...'` missed it and the job scanned nothing.
    #[tokio::test]
    async fn the_enqueue_and_the_worker_agree_on_manifest_rows() {
        let Some(pool) = try_pool().await else { return };
        let repo = fresh_queue(&pool).await;
        // `artifacts.checksum_sha256` is CHAR(64): real-length digests, so the
        // value read back is the value written.
        let (slash01, plain01, file01) = ("a".repeat(64), "b".repeat(64), "c".repeat(64));
        let seed = |path: &'static str, digest: String| {
            let pool = pool.clone();
            async move {
                let id = Uuid::new_v4();
                sqlx::query(
                    "INSERT INTO artifacts (id, repository_id, path, name, size_bytes, \
                     checksum_sha256, content_type, storage_key) \
                     VALUES ($1, $2, $3, 'n', 1, $4, 'application/octet-stream', $3)",
                )
                .bind(id)
                .bind(repo)
                .bind(path)
                .bind(digest)
                .execute(&pool)
                .await
                .expect("seed artifact");
                id
            }
        };
        let slashed = seed("/v2/img/manifests/1.0", slash01.clone()).await;
        let plain = seed("v2/img/manifests/1.1", plain01.clone()).await;
        let file = seed("pkg/file-1.0.tgz", file01.clone()).await;
        for id in [slashed, plain, file] {
            crate::services::scanner_service::enqueue_scan_on_upload(&pool, repo, id)
                .await
                .expect("enqueue");
        }
        let jobs: Vec<(String, Option<String>, Option<Uuid>)> = sqlx::query_as(
            "SELECT kind, digest, artifact_id FROM scan_queue ORDER BY kind, digest",
        )
        .fetch_all(&pool)
        .await
        .expect("jobs");
        assert_eq!(
            jobs,
            vec![
                ("hosted_image".to_string(), Some(slash01.clone()), None),
                ("hosted_image".to_string(), Some(plain01.clone()), None),
                ("hosted_upload".to_string(), None, Some(file)),
            ]
        );
        for (digest, id) in [(&slash01, slashed), (&plain01, plain)] {
            let rows: Vec<Uuid> = sqlx::query_scalar(HOSTED_IMAGE_ROWS_SQL)
                .bind(repo)
                .bind(digest)
                .fetch_all(&pool)
                .await
                .expect("worker rows");
            assert_eq!(rows, vec![id], "the worker must find the {digest} row");
        }
        drop_repo(&pool, repo).await;
    }

    /// #5946: one `hosted_upload` job per artifact, and its own kind, so a
    /// `POST /security/scan` job for the artifact is not merged into it.
    #[tokio::test]
    async fn hosted_upload_dedups_per_artifact() {
        let Some(pool) = try_pool().await else { return };
        let repo = fresh_queue(&pool).await;
        let artifact_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO artifacts (id, repository_id, path, name, size_bytes, \
             checksum_sha256, content_type, storage_key) \
             VALUES ($1, $2, 'p/u.jar', 'u.jar', 1, 'abc', 'application/java-archive', 'k')",
        )
        .bind(artifact_id)
        .bind(repo)
        .execute(&pool)
        .await
        .expect("seed artifact");
        let q = ScanQueue::new(pool.clone());

        assert!(q
            .enqueue_hosted_upload(artifact_id, PRIORITY_HOSTED)
            .await
            .expect("first"));
        assert!(!q
            .enqueue_hosted_upload(artifact_id, PRIORITY_HOSTED)
            .await
            .expect("again"));
        assert!(q
            .enqueue_hosted_artifact(
                artifact_id,
                &serde_json::json!({ "grype": Uuid::new_v4() }),
                false,
                PRIORITY_HOSTED
            )
            .await
            .expect("hosted_artifact"));
        let kinds: Vec<String> =
            sqlx::query_scalar("SELECT kind FROM scan_queue WHERE artifact_id = $1 ORDER BY kind")
                .bind(artifact_id)
                .fetch_all(&pool)
                .await
                .expect("kinds");
        assert_eq!(kinds, vec!["hosted_artifact", "hosted_upload"]);

        drop_repo(&pool, repo).await;
    }

    /// The scaling signal: the head-of-line age must actually be populated,
    /// since depth alone cannot tell draining from wedged.
    #[tokio::test]
    async fn depth_reports_pending_jobs_and_head_of_line_age() {
        let Some(pool) = try_pool().await else { return };
        let repo = fresh_queue(&pool).await;
        let q = ScanQueue::new(pool.clone());
        q.enqueue_proxy_file(repo, "d1", "depth001", None, 1, None, PRIORITY_BACKFILL)
            .await
            .expect("enqueue");

        let rows = q.depth().await.expect("depth");
        let pending = rows
            .iter()
            .find(|r| r.kind == "proxy_file" && r.state == "pending")
            .expect("a pending proxy_file bucket");
        assert_eq!(pending.jobs, 1);
        assert!(
            pending.oldest_pending_secs.is_some(),
            "a due pending job must report a head-of-line age"
        );

        drop_repo(&pool, repo).await;
    }
}
