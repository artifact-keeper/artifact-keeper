//! Peer instance management service.
//!
//! Handles peer instance registration, health monitoring, and sync coordination.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{AppError, Result};

/// Select all peer subscriptions (with their optional artifact filter) that are
/// eligible to receive a push of a newly uploaded artifact in the repository.
const PUSH_MIRROR_SUBSCRIPTIONS_SQL: &str = r#"
    SELECT prs.peer_instance_id, sp.artifact_filter
    FROM peer_repo_subscriptions prs
    LEFT JOIN sync_policies sp ON sp.id = prs.policy_id
    WHERE prs.repository_id = $1
      AND prs.sync_enabled = true
      AND prs.replication_mode::text IN ('push', 'mirror')
    "#;

/// A restore supersedes the delete task that took the artifact out of the
/// trash. Unlike [`REARM_SUPERSEDED_PUSH_SQL`], this does not wait for a
/// checksum or timestamp change: the peer may have applied the delete before
/// the restore reached this instance, so a finished push must go out again.
const QUEUE_RESTORED_PUSH_SQL: &str = r#"
    INSERT INTO sync_tasks (peer_instance_id, artifact_id, priority, task_type)
    VALUES ($1, $2, 0, 'push')
    ON CONFLICT (peer_instance_id, artifact_id, task_type)
    DO UPDATE SET
        status = 'pending',
        priority = GREATEST(sync_tasks.priority, 0),
        retry_count = 0,
        error_message = NULL,
        started_at = NULL,
        completed_at = NULL,
        claimed_by = NULL,
        claim_token = NULL,
        claim_expires_at = NULL
    -- An in-flight push is left alone: it is already delivering the artifact.
    -- Known gap: if a delete for the same peer is also in flight, the push and
    -- the delete race and their order on the peer is not guaranteed. That
    -- needs three overlapping operations (in-flight push, in-flight delete and
    -- the restore), so it is not handled here.
    WHERE sync_tasks.status <> 'in_progress'
    "#;

/// Cancel the delete tasks a restore supersedes, for the peers `$2` the
/// restore re-pushes to. A delete for any other peer stays: it may have been
/// queued because the peer dropped out of a sync policy's scope (the same
/// `(peer, artifact, 'delete')` row as the trash delete), or its subscription
/// was disabled or removed, and that peer gets no push to replace it. A worker
/// that already claimed a delete is left alone: its push is queued as well and
/// delivered after the in-flight delete finishes.
///
/// A delete is matched by its artifact, or by its address when its artifact
/// row is gone (#5624): a purged artifact that held the restored one's path
/// left a delete addressed to the key of repository `$3` and path `$4`, and
/// the push queued here replaces the peer's copy anyway. Matched by key, not
/// repository id: the peer addresses repositories by key, and a repository
/// deleted and re-created under the same key has a new id.
const CANCEL_SUPERSEDED_DELETE_TASKS_SQL: &str = r#"
    UPDATE sync_tasks
    SET status = 'cancelled',
        completed_at = NOW(),
        error_message = 'superseded by artifact restore'
    WHERE peer_instance_id = ANY($2)
      AND task_type = 'delete'
      AND status IN ('pending', 'failed')
      AND (
          artifact_id = $1
          OR (
              artifact_id IS NULL
              AND target_repository_key = (SELECT key FROM repositories WHERE id = $3)
              AND target_path = $4
          )
      )
    "#;

/// Fill in the peer address of the delete tasks already queued for the
/// artifacts `$1` of repository `$2` (key `$3`) that do not carry one yet (a
/// task queued before migration 340, or by an older replica), so they still
/// reach the peer once the row is gone (#5624). Scoped by peer so the
/// `(peer_instance_id, artifact_id, task_type)` index serves it.
const ADDRESS_QUEUED_DELETE_TASKS_SQL: &str = r#"
    UPDATE sync_tasks st
    SET target_repository_id = $2,
        target_repository_key = $3,
        target_path = a.path
    FROM artifacts a
    WHERE st.peer_instance_id = ANY(SELECT id FROM peer_instances WHERE is_local = false)
      AND st.artifact_id = ANY($1)
      AND st.task_type = 'delete'
      AND st.target_path IS NULL
      AND a.id = st.artifact_id
    "#;

/// Queue an addressed delete for every artifact `$1` of repository `$2` (key
/// `$3`) to every push/mirror subscriber, before the rows are hard-deleted
/// (#5624). A finished delete of a trashed artifact is kept (the peer already
/// removed it); any other delete that is not in flight is re-armed.
const QUEUE_REMOVAL_DELETE_TASKS_SQL: &str = r#"
    INSERT INTO sync_tasks (
        peer_instance_id, artifact_id, task_type, status, priority,
        target_repository_id, target_repository_key, target_path
    )
    SELECT prs.peer_instance_id, a.id, 'delete', 'pending', 0, $2, $3, a.path
    FROM artifacts a
    JOIN peer_repo_subscriptions prs ON prs.repository_id = a.repository_id
    JOIN peer_instances pi ON pi.id = prs.peer_instance_id
    WHERE a.id = ANY($1)
      AND a.repository_id = $2
      AND pi.is_local = false
      AND prs.sync_enabled = true
      AND prs.replication_mode::text IN ('push', 'mirror')
    ON CONFLICT (peer_instance_id, artifact_id, task_type) DO UPDATE SET
        status = 'pending',
        retry_count = 0,
        error_message = NULL,
        started_at = NULL,
        completed_at = NULL,
        claimed_by = NULL,
        claim_token = NULL,
        claim_expires_at = NULL,
        target_repository_id = EXCLUDED.target_repository_id,
        target_repository_key = EXCLUDED.target_repository_key,
        target_path = EXCLUDED.target_path
    WHERE sync_tasks.status <> 'in_progress'
      AND (
          sync_tasks.status <> 'completed'
          OR EXISTS (
              SELECT 1 FROM artifacts x
              WHERE x.id = sync_tasks.artifact_id AND x.is_deleted = false
          )
      )
    "#;

/// Queue one pending sync task per artifact of repository `$2` for peer `$1`,
/// skipping every artifact that already has a push task for that peer (the
/// unique `(peer_instance_id, artifact_id, task_type)`), and return how many
/// were queued. The work of a whole-repository pass: the run-now route and the
/// scheduled `mirror` job (#5342) share it.
const QUEUE_REPOSITORY_SYNC_TASKS_SQL: &str = r#"
    WITH inserted AS (
        INSERT INTO sync_tasks (peer_instance_id, artifact_id, priority)
        SELECT $1, a.id, 100
        FROM artifacts a
        WHERE a.repository_id = $2
        ON CONFLICT (peer_instance_id, artifact_id, task_type) DO NOTHING
        RETURNING id
    )
    SELECT COUNT(*)::bigint FROM inserted
    "#;

/// Where a `mirror` subscription's `replication_schedule` stands at a given
/// instant (#5342).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MirrorScheduleState {
    /// No schedule: the subscription gets upload-time tasks only.
    Unscheduled,
    /// The stored expression does not parse as cron.
    Invalid,
    /// The first occurrence after the last pass is still in the future.
    NotDue,
    /// Never replicated, or an occurrence has passed since the last pass.
    Due,
}

/// Whether a scheduled `mirror` pass is due at `now` (#5342). The schedule is
/// standard 5-field cron (or 6/7 fields with seconds / year), in UTC. It is
/// due when the subscription has never completed a pass, or when the first
/// occurrence after `last_replicated_at` is at or before `now`; a run of
/// missed occurrences (downtime, the upstream-jobs switch) is one pass, not
/// a backlog.
pub fn mirror_schedule_state(
    schedule: Option<&str>,
    last_replicated_at: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> MirrorScheduleState {
    let Some(expr) = schedule.map(str::trim).filter(|s| !s.is_empty()) else {
        return MirrorScheduleState::Unscheduled;
    };
    let Some(cron) = parse_replication_schedule(expr) else {
        return MirrorScheduleState::Invalid;
    };
    let Some(last) = last_replicated_at else {
        return MirrorScheduleState::Due;
    };
    match cron.after(&last).next() {
        Some(next) if next <= now => MirrorScheduleState::Due,
        _ => MirrorScheduleState::NotDue,
    }
}

fn parse_replication_schedule(expr: &str) -> Option<cron::Schedule> {
    crate::services::scheduler_service::parse_cron_schedule(
        &crate::services::scheduler_service::normalize_cron_expression(expr),
    )
}

/// Refuse a `replication_schedule` that is not valid cron (#5342): it would
/// be stored and never fire.
fn validate_replication_schedule(schedule: Option<&str>) -> Result<()> {
    match schedule.map(str::trim).filter(|s| !s.is_empty()) {
        Some(expr) if parse_replication_schedule(expr).is_none() => {
            Err(AppError::Validation(format!(
                "invalid replication_schedule '{expr}': expected a cron expression such as \
                 '0 */6 * * *' (UTC)"
            )))
        }
        _ => Ok(()),
    }
}

/// Totals of one [`PeerInstanceService::run_due_mirror_passes`] tick.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct MirrorPassSummary {
    /// Subscriptions whose schedule was due.
    pub due: usize,
    /// Passes that completed (and advanced `last_replicated_at`).
    pub passes: usize,
    /// Sync tasks those passes queued.
    pub tasks_queued: i64,
    /// Subscriptions (or peers) whose pass failed; retried next tick.
    pub failed: usize,
}

pub struct PublishedArtifact<'a> {
    pub id: Uuid,
    pub repository_id: Uuid,
    pub path: &'a str,
    pub size_bytes: i64,
    pub created_at: DateTime<Utc>,
}

const REARM_SUPERSEDED_PUSH_SQL: &str = r#"
    UPDATE sync_tasks st
    SET status = 'pending',
        retry_count = 0,
        error_message = NULL,
        started_at = NULL,
        completed_at = NULL,
        claimed_by = NULL,
        claim_token = NULL,
        claim_expires_at = NULL
    FROM artifacts a
    JOIN repositories r ON r.id = a.repository_id
    WHERE st.id = $1
      AND st.task_type = 'push'
      AND st.status IN ('completed', 'failed', 'cancelled')
      AND a.id = st.artifact_id
      AND a.is_deleted = false
      AND (
          (
              r.versioning_enabled
              AND r.format::text IN ('generic', 'mlmodel')
              AND a.checksum_sha256 IS DISTINCT FROM $2::bpchar
          )
          OR EXISTS (
              SELECT 1
              FROM sync_tasks d
              WHERE d.peer_instance_id = st.peer_instance_id
                AND d.artifact_id = st.artifact_id
                AND d.task_type = 'delete'
                AND (
                    d.status IN ('pending', 'in_progress')
                    OR (d.status <> 'cancelled' AND d.completed_at > st.completed_at)
                )
          )
          -- #4792/#4889: format metadata may be attached after the upload is
          -- already queued (a pacman signature or conda attestation, or the
          -- NuGet/PyPI/Debian/RPM documents written after finalize). Re-deliver
          -- whenever a finished push carried a different document, not just
          -- for the two formats that first exposed the race. `$3` is what the
          -- push carried (JSON `null` for none); SQL NULL means the caller
          -- cannot say, and is left to the checks above so a plain re-queue
          -- does not fan out unchanged metadata.
          OR EXISTS (
              SELECT 1
              FROM artifact_metadata am
              WHERE am.artifact_id = a.id
                AND (
                    -- Pacman's file list is compared on neither side: the
                    -- claim merges `pacman_file_lists` into what it sends, and
                    -- a row written by a pre-#4424 replica during a rolling
                    -- upgrade can still hold `files` in the document itself.
                    -- Comparing one stripped side with one unstripped side
                    -- would re-arm that package after every push, forever.
                    (
                        $3::jsonb IS NOT NULL
                        AND (
                            CASE WHEN r.format::text = 'pacman' AND jsonb_typeof(am.metadata) = 'object'
                                 THEN am.metadata - 'files'
                                 ELSE am.metadata
                            END
                        ) IS DISTINCT FROM (
                            CASE WHEN r.format::text = 'pacman' AND jsonb_typeof($3::jsonb) = 'object'
                                 THEN $3::jsonb - 'files'
                                 ELSE $3::jsonb
                            END
                        )
                    )
                    -- A re-queue with an unknown payload keeps the narrower
                    -- #4792 rule: only the late pacman/conda fields justify a
                    -- second delivery.
                    OR (
                        $3::jsonb IS NULL
                        AND (
                            (r.format::text = 'pacman' AND am.metadata ? 'pgpsig')
                            OR (r.format::text = 'conda' AND am.metadata ? 'attestation')
                        )
                    )
                )
          )
          -- #4889: protobuf rewrites its `_labels` index in place. The path is
          -- a mutable pointer, so a label move after a finished push has to be
          -- re-delivered even though the repository is not versioned.
          OR (
              r.format::text = 'protobuf'
              AND a.path ~ '/_labels$'
              AND a.updated_at > COALESCE(st.completed_at, st.created_at)
          )
      )
"#;

/// Peer instance status
#[derive(Debug, Clone, Copy, PartialEq, sqlx::Type)]
#[sqlx(type_name = "instance_status", rename_all = "lowercase")]
pub enum InstanceStatus {
    Online,
    Offline,
    Syncing,
    Degraded,
}

/// Replication mode for peer replication policies.
#[derive(Debug, Clone, Copy, PartialEq, sqlx::Type)]
#[sqlx(type_name = "replication_mode", rename_all = "lowercase")]
pub enum ReplicationMode {
    Push,
    Pull,
    Mirror,
    None,
}

/// Message of the 400 a `pull` subscription or sync policy is refused with
/// (#5293).
pub const PULL_REPLICATION_NOT_IMPLEMENTED: &str =
    "pull replication is not implemented: no sync task is ever created for a `pull` \
     subscription. Subscribe this repository to the receiving peer on the instance that \
     holds it, with `push` or `mirror` (each new artifact is sent as it is uploaded; \
     POST /api/v1/peers/{id}/repositories/{repo_id}/sync sends the whole repository)";

impl ReplicationMode {
    /// The mode a subscription gets when the caller names none (#5293). It was
    /// `pull`, which no task producer ever selects, so an omitted mode created a
    /// subscription that silently never moved a byte; sync policies already
    /// defaulted to `push`.
    pub const DEFAULT: ReplicationMode = ReplicationMode::Push;

    /// The mode as stored in the `replication_mode` enum.
    pub fn as_str(self) -> &'static str {
        match self {
            ReplicationMode::Push => "push",
            ReplicationMode::Pull => "pull",
            ReplicationMode::Mirror => "mirror",
            ReplicationMode::None => "none",
        }
    }

    /// Whether anything ever creates sync tasks for a subscription in this
    /// mode: `push` and `mirror` both get one per new artifact from the upload
    /// hook (`PUSH_MIRROR_SUBSCRIPTIONS_SQL`), and a `mirror` subscription with
    /// a `replication_schedule` also gets a whole-repository pass each time it
    /// is due (`run_due_mirror_passes`, #5342). `none` is the explicit
    /// "subscribed, do not replicate" mode, and `pull` has no producer at all.
    pub fn produces_sync_tasks(self) -> bool {
        matches!(self, ReplicationMode::Push | ReplicationMode::Mirror)
    }

    /// The mode to store for a subscription request: an omitted mode is
    /// [`Self::DEFAULT`], and `pull` is refused with
    /// [`PULL_REPLICATION_NOT_IMPLEMENTED`] instead of being stored as a
    /// subscription that never replicates (#5293).
    pub fn for_new_subscription(mode: Option<ReplicationMode>) -> Result<ReplicationMode> {
        match mode.unwrap_or(Self::DEFAULT) {
            ReplicationMode::Pull => Err(AppError::Validation(
                PULL_REPLICATION_NOT_IMPLEMENTED.to_string(),
            )),
            other => Ok(other),
        }
    }
}

/// Whether a stored subscription is actually replicated, as reported in the
/// subscription API's `effective` field (#5293): `active` when it is enabled
/// and its mode has a task producer, `inactive` otherwise. A `pull` row
/// written before `pull` was refused reports `inactive`.
pub fn subscription_effective_state(
    sync_enabled: bool,
    replication_mode: Option<&str>,
) -> &'static str {
    let replicates = matches!(replication_mode, Some("push") | Some("mirror"));
    if sync_enabled && replicates {
        "active"
    } else {
        "inactive"
    }
}

/// Name, once per boot, every peer subscription and sync policy that still
/// uses `pull` (#5293). Those rows were accepted before `pull` was refused and
/// have never replicated anything; they are left unchanged so the operator
/// can pick `push` or `mirror` deliberately. Returns the
/// `(kind, description)` pairs it warned about.
pub async fn warn_inactive_pull_replication(db: &PgPool) -> Vec<(String, String)> {
    let subscriptions: Vec<(String, String)> = sqlx::query_as(
        "SELECT p.name, r.key \
         FROM peer_repo_subscriptions s \
         JOIN peer_instances p ON p.id = s.peer_instance_id \
         JOIN repositories r ON r.id = s.repository_id \
         WHERE s.replication_mode::text = 'pull' \
         ORDER BY p.name, r.key",
    )
    .fetch_all(db)
    .await
    .unwrap_or_default();
    let policies: Vec<(String,)> = sqlx::query_as(
        "SELECT name FROM sync_policies WHERE replication_mode = 'pull' ORDER BY name",
    )
    .fetch_all(db)
    .await
    .unwrap_or_default();

    let mut warned = Vec::new();
    for (peer, repo) in subscriptions {
        tracing::warn!(
            peer = %peer,
            repository = %repo,
            "peer subscription uses replication_mode 'pull', which is not implemented: it has \
             never replicated anything (#5293). Re-subscribe with `push` or `mirror` \
             (POST /api/v1/peers/{{id}}/repositories); the stored row has been left unchanged."
        );
        warned.push(("subscription".to_string(), format!("{peer}/{repo}")));
    }
    for (policy,) in policies {
        tracing::warn!(
            policy = %policy,
            "sync policy uses replication_mode 'pull', which is not implemented: the \
             subscriptions it creates never replicate anything (#5293). Change it to `push` \
             or `mirror` (PUT /api/v1/sync-policies/{{id}}); the stored policy has been left \
             unchanged."
        );
        warned.push(("policy".to_string(), policy));
    }
    warned
}

/// A repository with a mirror replication policy.
#[derive(Debug)]
pub struct MirrorRepo {
    pub repo_id: Uuid,
    pub schedule: Option<String>,
    pub last_replicated_at: Option<DateTime<Utc>>,
}

impl std::fmt::Display for InstanceStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InstanceStatus::Online => write!(f, "online"),
            InstanceStatus::Offline => write!(f, "offline"),
            InstanceStatus::Syncing => write!(f, "syncing"),
            InstanceStatus::Degraded => write!(f, "degraded"),
        }
    }
}

/// Peer instance model
#[derive(Debug)]
pub struct PeerInstance {
    pub id: Uuid,
    pub name: String,
    pub endpoint_url: String,
    pub status: InstanceStatus,
    pub region: Option<String>,
    pub cache_size_bytes: i64,
    pub cache_used_bytes: i64,
    pub last_heartbeat_at: Option<DateTime<Utc>>,
    pub last_sync_at: Option<DateTime<Utc>>,
    pub sync_filter: Option<serde_json::Value>,
    pub max_bandwidth_bps: Option<i64>,
    pub sync_window_start: Option<chrono::NaiveTime>,
    pub sync_window_end: Option<chrono::NaiveTime>,
    pub sync_window_timezone: Option<String>,
    pub concurrent_transfers_limit: Option<i32>,
    pub active_transfers: i32,
    pub backoff_until: Option<DateTime<Utc>>,
    pub consecutive_failures: i32,
    pub bytes_transferred_total: i64,
    pub transfer_failures_total: i32,
    pub api_key: String,
    pub is_local: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Request to register a peer instance
#[derive(Debug)]
pub struct RegisterPeerInstanceRequest {
    pub name: String,
    pub endpoint_url: String,
    pub region: Option<String>,
    pub cache_size_bytes: i64,
    pub sync_filter: Option<serde_json::Value>,
    pub api_key: String,
}

/// PostgreSQL SQLSTATE for a foreign-key violation.
const PG_FOREIGN_KEY_VIOLATION: &str = "23503";

/// FK constraint that fires when `repository_id` does not reference an existing
/// row in `repositories`.
const PEER_REPO_SUBSCRIPTION_REPO_FK: &str = "peer_repo_subscriptions_repository_id_fkey";

/// FK constraint that fires when `peer_instance_id` does not reference an
/// existing row in `peer_instances`.
const PEER_REPO_SUBSCRIPTION_PEER_FK: &str = "peer_repo_subscriptions_peer_instance_id_fkey";

/// Map an `INSERT`/`UPSERT` error from `peer_repo_subscriptions` to an
/// [`AppError`].
///
/// A foreign-key violation means the supplied `repository_id` or
/// `peer_instance_id` does not exist; this is a client error and must surface
/// as [`AppError::NotFound`] (HTTP 404) rather than an opaque
/// [`AppError::Database`] (HTTP 500). All other database errors fall through to
/// [`AppError::Database`].
fn map_assign_repository_error(err: sqlx::Error) -> AppError {
    if let sqlx::Error::Database(db_err) = &err {
        if db_err.code().as_deref() == Some(PG_FOREIGN_KEY_VIOLATION) {
            match db_err.constraint() {
                Some(PEER_REPO_SUBSCRIPTION_REPO_FK) => {
                    return AppError::NotFound("Repository not found".to_string());
                }
                Some(PEER_REPO_SUBSCRIPTION_PEER_FK) => {
                    return AppError::NotFound("Peer instance not found".to_string());
                }
                _ => {}
            }
        }
    }
    AppError::Database(err.to_string())
}

/// Peer instance service
pub struct PeerInstanceService {
    db: PgPool,
}

impl PeerInstanceService {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    /// Register a new peer instance
    pub async fn register(&self, req: RegisterPeerInstanceRequest) -> Result<PeerInstance> {
        let node = sqlx::query_as!(
            PeerInstance,
            r#"
            INSERT INTO peer_instances (name, endpoint_url, region, cache_size_bytes, sync_filter, api_key)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING
                id, name, endpoint_url,
                status as "status: InstanceStatus",
                region, cache_size_bytes, cache_used_bytes,
                last_heartbeat_at, last_sync_at, sync_filter,
                max_bandwidth_bps, sync_window_start, sync_window_end,
                sync_window_timezone, concurrent_transfers_limit,
                active_transfers, backoff_until, consecutive_failures,
                bytes_transferred_total, transfer_failures_total,
                api_key, is_local,
                created_at, updated_at
            "#,
            req.name,
            req.endpoint_url,
            req.region,
            req.cache_size_bytes,
            req.sync_filter,
            req.api_key
        )
        .fetch_one(&self.db)
        .await
        .map_err(|e| {
            if e.to_string().contains("duplicate key") {
                AppError::Conflict(format!("Peer instance '{}' already exists", req.name))
            } else {
                AppError::Database(e.to_string())
            }
        })?;

        Ok(node)
    }

    /// Reconcile the `is_local` row in `peer_instances` with the current
    /// `PEER_INSTANCE_NAME` / `PEER_PUBLIC_ENDPOINT` configuration (#2832).
    ///
    /// The row is seeded at first boot, but env changes after that must land
    /// on it too — the same env-vs-persisted-state contract
    /// `peer_instance_identity` already honors — or the Peers UI shows the
    /// stale first-boot name/endpoint forever. Updating in place (matched by
    /// `is_local`, not by name) preserves the row's id and its repository
    /// assignments across a rename; the insert path only runs when no local
    /// row exists yet.
    ///
    /// Runtime (non-macro) queries so no offline `.sqlx` prepare is needed.
    pub async fn reconcile_local_instance(
        &self,
        name: &str,
        endpoint_url: &str,
        api_key: &str,
    ) -> Result<()> {
        let updated = sqlx::query(
            r#"
            UPDATE peer_instances
            SET name = $1,
                endpoint_url = $2,
                api_key = $3,
                status = 'online',
                updated_at = NOW()
            WHERE is_local = true
            "#,
        )
        .bind(name)
        .bind(endpoint_url)
        .bind(api_key)
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        if updated.rows_affected() > 0 {
            return Ok(());
        }

        // First boot: no local row exists yet. The name-conflict arm adopts a
        // pre-existing row of the same name as local rather than duplicating it.
        sqlx::query(
            r#"
            INSERT INTO peer_instances (name, endpoint_url, status, api_key, is_local)
            VALUES ($1, $2, 'online', $3, true)
            ON CONFLICT (name) DO UPDATE SET
                endpoint_url = EXCLUDED.endpoint_url,
                api_key = EXCLUDED.api_key,
                status = 'online',
                is_local = true,
                updated_at = NOW()
            "#,
        )
        .bind(name)
        .bind(endpoint_url)
        .bind(api_key)
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(())
    }

    /// Get the local peer instance
    pub async fn get_local_instance(&self) -> Result<PeerInstance> {
        let node = sqlx::query_as!(
            PeerInstance,
            r#"
            SELECT
                id, name, endpoint_url,
                status as "status: InstanceStatus",
                region, cache_size_bytes, cache_used_bytes,
                last_heartbeat_at, last_sync_at, sync_filter,
                max_bandwidth_bps, sync_window_start, sync_window_end,
                sync_window_timezone, concurrent_transfers_limit,
                active_transfers, backoff_until, consecutive_failures,
                bytes_transferred_total, transfer_failures_total,
                api_key, is_local,
                created_at, updated_at
            FROM peer_instances
            WHERE is_local = true
            LIMIT 1
            "#,
        )
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .ok_or_else(|| AppError::NotFound("Local peer instance not found".to_string()))?;

        Ok(node)
    }

    /// Get a peer instance by ID
    pub async fn get_by_id(&self, id: Uuid) -> Result<PeerInstance> {
        let node = sqlx::query_as!(
            PeerInstance,
            r#"
            SELECT
                id, name, endpoint_url,
                status as "status: InstanceStatus",
                region, cache_size_bytes, cache_used_bytes,
                last_heartbeat_at, last_sync_at, sync_filter,
                max_bandwidth_bps, sync_window_start, sync_window_end,
                sync_window_timezone, concurrent_transfers_limit,
                active_transfers, backoff_until, consecutive_failures,
                bytes_transferred_total, transfer_failures_total,
                api_key, is_local,
                created_at, updated_at
            FROM peer_instances
            WHERE id = $1
            "#,
            id
        )
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .ok_or_else(|| AppError::NotFound("Peer instance not found".to_string()))?;

        Ok(node)
    }

    /// Get a peer instance by name
    pub async fn get_by_name(&self, name: &str) -> Result<PeerInstance> {
        let node = sqlx::query_as!(
            PeerInstance,
            r#"
            SELECT
                id, name, endpoint_url,
                status as "status: InstanceStatus",
                region, cache_size_bytes, cache_used_bytes,
                last_heartbeat_at, last_sync_at, sync_filter,
                max_bandwidth_bps, sync_window_start, sync_window_end,
                sync_window_timezone, concurrent_transfers_limit,
                active_transfers, backoff_until, consecutive_failures,
                bytes_transferred_total, transfer_failures_total,
                api_key, is_local,
                created_at, updated_at
            FROM peer_instances
            WHERE name = $1
            "#,
            name
        )
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .ok_or_else(|| AppError::NotFound("Peer instance not found".to_string()))?;

        Ok(node)
    }

    /// List all peer instances
    pub async fn list(
        &self,
        status_filter: Option<InstanceStatus>,
        region_filter: Option<&str>,
        offset: i64,
        limit: i64,
    ) -> Result<(Vec<PeerInstance>, i64)> {
        let nodes = sqlx::query_as!(
            PeerInstance,
            r#"
            SELECT
                id, name, endpoint_url,
                status as "status: InstanceStatus",
                region, cache_size_bytes, cache_used_bytes,
                last_heartbeat_at, last_sync_at, sync_filter,
                max_bandwidth_bps, sync_window_start, sync_window_end,
                sync_window_timezone, concurrent_transfers_limit,
                active_transfers, backoff_until, consecutive_failures,
                bytes_transferred_total, transfer_failures_total,
                api_key, is_local,
                created_at, updated_at
            FROM peer_instances
            WHERE ($1::instance_status IS NULL OR status = $1)
              AND ($2::text IS NULL OR region = $2)
            ORDER BY name
            OFFSET $3
            LIMIT $4
            "#,
            status_filter as Option<InstanceStatus>,
            region_filter,
            offset,
            limit
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        let total = sqlx::query_scalar!(
            r#"
            SELECT COUNT(*) as "count!"
            FROM peer_instances
            WHERE ($1::instance_status IS NULL OR status = $1)
              AND ($2::text IS NULL OR region = $2)
            "#,
            status_filter as Option<InstanceStatus>,
            region_filter
        )
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok((nodes, total))
    }

    /// Update heartbeat from peer instance
    pub async fn heartbeat(
        &self,
        node_id: Uuid,
        cache_used_bytes: i64,
        status: Option<InstanceStatus>,
    ) -> Result<()> {
        let new_status = status.unwrap_or(InstanceStatus::Online);

        sqlx::query!(
            r#"
            UPDATE peer_instances
            SET
                last_heartbeat_at = NOW(),
                cache_used_bytes = $2,
                status = $3,
                updated_at = NOW()
            WHERE id = $1
            "#,
            node_id,
            cache_used_bytes,
            new_status as InstanceStatus
        )
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(())
    }

    /// Update sync status
    pub async fn update_sync_status(&self, node_id: Uuid, completed: bool) -> Result<()> {
        let status = if completed {
            InstanceStatus::Online
        } else {
            InstanceStatus::Syncing
        };

        let query = if completed {
            sqlx::query!(
                r#"
                UPDATE peer_instances
                SET status = $2, last_sync_at = NOW(), updated_at = NOW()
                WHERE id = $1
                "#,
                node_id,
                status as InstanceStatus
            )
        } else {
            sqlx::query!(
                r#"
                UPDATE peer_instances
                SET status = $2, updated_at = NOW()
                WHERE id = $1
                "#,
                node_id,
                status as InstanceStatus
            )
        };

        query
            .execute(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(())
    }

    /// Unregister a peer instance
    pub async fn unregister(&self, id: Uuid) -> Result<()> {
        let result = sqlx::query!("DELETE FROM peer_instances WHERE id = $1", id)
            .execute(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound("Peer instance not found".to_string()));
        }

        Ok(())
    }

    /// Assign repository to peer instance (subscribe).
    ///
    /// Persists per-subscription `replication_mode`, `replication_schedule`
    /// (cron), and `replication_filter` (JSON: `{"include_patterns": [...],
    /// "exclude_patterns": [...]}`). The filter is read by the sync worker
    /// when dispatching tasks (see `matches_replication_filter`); leaving
    /// it unset means "replicate everything".
    #[allow(clippy::too_many_arguments)]
    pub async fn assign_repository(
        &self,
        peer_instance_id: Uuid,
        repository_id: Uuid,
        sync_enabled: bool,
        replication_mode: Option<ReplicationMode>,
        replication_schedule: Option<String>,
        replication_filter: Option<serde_json::Value>,
    ) -> Result<()> {
        // `peer_repo_subscriptions.replication_mode` is NOT NULL. A caller that
        // omits the mode must not produce a constraint violation surfaced as an
        // opaque 500 -- fall back to the same default the column declares
        // (`'push'` since #5293). `pull` is refused here, at the one writer of
        // a hand-made subscription, rather than stored and never acted on.
        let replication_mode = ReplicationMode::for_new_subscription(replication_mode)?;
        validate_replication_schedule(replication_schedule.as_deref())?;
        sqlx::query!(
            r#"
            INSERT INTO peer_repo_subscriptions
                (peer_instance_id, repository_id, sync_enabled, replication_mode, replication_schedule, replication_filter)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (peer_instance_id, repository_id) DO UPDATE SET
                sync_enabled = $3,
                replication_mode = $4,
                replication_schedule = $5,
                replication_filter = $6
            "#,
            peer_instance_id,
            repository_id,
            sync_enabled,
            replication_mode as ReplicationMode,
            replication_schedule,
            replication_filter
        )
        .execute(&self.db)
        .await
        .map_err(map_assign_repository_error)?;

        Ok(())
    }

    /// Get full subscription details (mode, schedule, filter) for a single
    /// (peer, repo) pair. Returns `NotFound` if no subscription exists.
    pub async fn get_subscription(
        &self,
        peer_instance_id: Uuid,
        repository_id: Uuid,
    ) -> Result<crate::models::peer_instance::PeerRepoSubscription> {
        let sub = sqlx::query_as!(
            crate::models::peer_instance::PeerRepoSubscription,
            r#"
            SELECT
                id, peer_instance_id, repository_id, sync_enabled,
                replication_mode::text as replication_mode,
                replication_schedule,
                replication_filter,
                last_replicated_at,
                created_at
            FROM peer_repo_subscriptions
            WHERE peer_instance_id = $1 AND repository_id = $2
            "#,
            peer_instance_id,
            repository_id,
        )
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .ok_or_else(|| AppError::NotFound("Subscription not found".to_string()))?;

        Ok(sub)
    }

    /// Queue sync tasks for every artifact in a subscribed repository.
    /// Used by the "run now" endpoint to kick a whole-repository pass
    /// immediately instead of waiting for a `mirror` subscription's schedule.
    /// Returns the number of tasks queued.
    pub async fn run_subscription_now(
        &self,
        peer_instance_id: Uuid,
        repository_id: Uuid,
    ) -> Result<i64> {
        // Confirm the subscription exists first so we return 404 cleanly.
        let _ = self
            .get_subscription(peer_instance_id, repository_id)
            .await?;

        let inserted: i64 = sqlx::query_scalar(QUEUE_REPOSITORY_SYNC_TASKS_SQL)
            .bind(peer_instance_id)
            .bind(repository_id)
            .fetch_one(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        // A run-now pass is a completed whole-repository pass: stamping it
        // means a `mirror` schedule next fires at its first occurrence after
        // this run rather than repeating the same work (#5342).
        let _ = sqlx::query!(
            "UPDATE peer_repo_subscriptions SET last_replicated_at = NOW() WHERE peer_instance_id = $1 AND repository_id = $2",
            peer_instance_id,
            repository_id,
        )
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(inserted)
    }

    /// One scheduled pass of a `mirror` subscription (#5342): queue the
    /// repository's artifacts the peer has no task for (the work of
    /// [`Self::run_subscription_now`]) and stamp `last_replicated_at = now`.
    ///
    /// Both happen in one transaction, so `last_replicated_at` advances only
    /// when the pass completes: a failed insert leaves the stamp where it was
    /// and the schedule is still due on the next tick. The stamp is written
    /// first and only if it still equals `expected_last` (what the caller
    /// read when it decided the pass was due), which holds the row until
    /// commit; a replica or run-now that got there first makes this return
    /// `Ok(None)` without queueing anything. `Ok(Some(n))` is a completed
    /// pass that queued `n` tasks.
    pub async fn run_mirror_pass(
        &self,
        peer_instance_id: Uuid,
        repository_id: Uuid,
        expected_last: Option<DateTime<Utc>>,
        now: DateTime<Utc>,
    ) -> Result<Option<i64>> {
        let db_err = |e: sqlx::Error| AppError::Database(e.to_string());
        let mut tx = self.db.begin().await.map_err(db_err)?;
        let claimed = sqlx::query(
            r#"
            UPDATE peer_repo_subscriptions
            SET last_replicated_at = $3
            WHERE peer_instance_id = $1
              AND repository_id = $2
              AND sync_enabled = true
              AND replication_mode::text = 'mirror'
              AND last_replicated_at IS NOT DISTINCT FROM $4
            "#,
        )
        .bind(peer_instance_id)
        .bind(repository_id)
        .bind(now)
        .bind(expected_last)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?
        .rows_affected();
        if claimed == 0 {
            return Ok(None);
        }
        let queued: i64 = sqlx::query_scalar(QUEUE_REPOSITORY_SYNC_TASKS_SQL)
            .bind(peer_instance_id)
            .bind(repository_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(db_err)?;
        tx.commit().await.map_err(db_err)?;
        Ok(Some(queued))
    }

    /// The scheduled `mirror` job (#5342): for every enabled `mirror`
    /// subscription with a `replication_schedule` that is due at `now`, run
    /// one [`Self::run_mirror_pass`]. A failure on one subscription is logged
    /// and counted; the others still run.
    pub async fn run_due_mirror_passes(&self, now: DateTime<Utc>) -> Result<MirrorPassSummary> {
        let peers: Vec<Uuid> = sqlx::query_scalar(
            "SELECT DISTINCT peer_instance_id FROM peer_repo_subscriptions \
             WHERE sync_enabled = true AND replication_mode::text = 'mirror' \
               AND replication_schedule IS NOT NULL",
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        let mut summary = MirrorPassSummary::default();
        for peer_id in peers {
            let repos = match self.get_repos_for_mirror_sync(peer_id).await {
                Ok(repos) => repos,
                Err(e) => {
                    tracing::warn!(peer = %peer_id, "mirror schedule: listing subscriptions failed: {e}");
                    summary.failed += 1;
                    continue;
                }
            };
            for repo in repos {
                match mirror_schedule_state(repo.schedule.as_deref(), repo.last_replicated_at, now)
                {
                    MirrorScheduleState::Due => {}
                    MirrorScheduleState::Invalid => {
                        tracing::warn!(
                            peer = %peer_id,
                            repository = %repo.repo_id,
                            schedule = repo.schedule.as_deref().unwrap_or_default(),
                            "mirror subscription has an invalid replication_schedule; no \
                             scheduled pass runs until it is corrected"
                        );
                        continue;
                    }
                    MirrorScheduleState::Unscheduled | MirrorScheduleState::NotDue => continue,
                }
                summary.due += 1;
                match self
                    .run_mirror_pass(peer_id, repo.repo_id, repo.last_replicated_at, now)
                    .await
                {
                    Ok(Some(queued)) => {
                        summary.passes += 1;
                        summary.tasks_queued += queued;
                    }
                    Ok(None) => {}
                    Err(e) => {
                        tracing::warn!(
                            peer = %peer_id,
                            repository = %repo.repo_id,
                            "scheduled mirror pass failed, retried on the next tick: {e}"
                        );
                        summary.failed += 1;
                    }
                }
            }
        }
        Ok(summary)
    }

    /// Remove repository subscription from peer instance
    pub async fn unassign_repository(
        &self,
        peer_instance_id: Uuid,
        repository_id: Uuid,
    ) -> Result<()> {
        let result = sqlx::query!(
            "DELETE FROM peer_repo_subscriptions WHERE peer_instance_id = $1 AND repository_id = $2",
            peer_instance_id,
            repository_id
        )
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound("Subscription not found".to_string()));
        }

        Ok(())
    }

    /// List the sync-enabled subscription rows for a peer instance, with
    /// replication_mode. Replaces the ids-only `get_assigned_repositories`:
    /// same row set (`sync_enabled = true` — a disabled assignment is not one
    /// this peer syncs), but carrying the mode so callers can render the real
    /// direction instead of guessing. Uses a runtime query (not the `query_as!`
    /// macro) so it needs no offline SQLx cache entry, mirroring
    /// `principal_must_change_password` in `api/middleware/auth.rs`.
    pub async fn list_subscriptions(
        &self,
        peer_instance_id: Uuid,
    ) -> Result<Vec<crate::models::peer_instance::PeerRepoSubscription>> {
        let subs = sqlx::query_as::<_, crate::models::peer_instance::PeerRepoSubscription>(
            r#"
            SELECT
                id, peer_instance_id, repository_id, sync_enabled,
                replication_mode::text as replication_mode,
                replication_schedule,
                replication_filter,
                last_replicated_at,
                created_at
            FROM peer_repo_subscriptions
            WHERE peer_instance_id = $1 AND sync_enabled = true
            ORDER BY created_at, id
            "#,
        )
        .bind(peer_instance_id)
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(subs)
    }

    /// Mark stale nodes as offline
    pub async fn mark_stale_offline(&self, stale_threshold_minutes: i32) -> Result<u64> {
        let result = sqlx::query!(
            r#"
            UPDATE peer_instances
            SET status = 'offline'
            WHERE status = 'online'
              AND last_heartbeat_at < NOW() - make_interval(mins => $1)
            "#,
            stale_threshold_minutes
        )
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(result.rows_affected())
    }

    /// Queue sync task for an artifact
    pub async fn queue_sync_task(
        &self,
        peer_instance_id: Uuid,
        artifact_id: Uuid,
        priority: i32,
    ) -> Result<Uuid> {
        let id: Uuid = sqlx::query_scalar(
            r#"
            INSERT INTO sync_tasks (peer_instance_id, artifact_id, priority)
            VALUES ($1, $2, $3)
            ON CONFLICT (peer_instance_id, artifact_id, task_type) DO UPDATE SET priority = GREATEST(sync_tasks.priority, $3)
            RETURNING id
            "#,
        )
        .bind(peer_instance_id)
        .bind(artifact_id)
        .bind(priority)
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        self.rearm_superseded_push(id, None, None).await?;

        Ok(id)
    }

    /// The peers an upload-time push of `artifact` should go to: every enabled
    /// push/mirror subscription whose policy filter still accepts it.
    async fn push_sync_peers<'e, E>(
        executor: E,
        artifact: &PublishedArtifact<'_>,
    ) -> std::result::Result<Vec<Uuid>, sqlx::Error>
    where
        E: sqlx::Executor<'e, Database = sqlx::Postgres>,
    {
        #[derive(sqlx::FromRow)]
        struct SubWithFilter {
            peer_instance_id: Uuid,
            artifact_filter: Option<serde_json::Value>,
        }

        let subscriptions: Vec<SubWithFilter> = sqlx::query_as(PUSH_MIRROR_SUBSCRIPTIONS_SQL)
            .bind(artifact.repository_id)
            .fetch_all(executor)
            .await?;

        Ok(subscriptions
            .into_iter()
            .filter_map(|sub| {
                let filter: crate::services::sync_policy_service::ArtifactFilter = sub
                    .artifact_filter
                    .as_ref()
                    .and_then(|v| serde_json::from_value(v.clone()).ok())
                    .unwrap_or_default();

                if !filter.matches(artifact.path, artifact.size_bytes, artifact.created_at) {
                    tracing::debug!(
                        "Artifact {} filtered out for peer {} by policy artifact_filter",
                        artifact.id,
                        sub.peer_instance_id,
                    );
                    return None;
                }
                Some(sub.peer_instance_id)
            })
            .collect())
    }

    pub async fn queue_push_sync_tasks(&self, artifact: &PublishedArtifact<'_>) -> usize {
        let peers = match Self::push_sync_peers(&self.db, artifact).await {
            Ok(peers) => peers,
            Err(e) => {
                tracing::warn!(
                    "Failed to query peer subscriptions for repo {} artifact {}: {}",
                    artifact.repository_id,
                    artifact.id,
                    e
                );
                return 0;
            }
        };

        let mut queued = 0usize;
        for peer_id in peers {
            match self.queue_sync_task(peer_id, artifact.id, 0).await {
                Ok(_) => queued += 1,
                Err(e) => tracing::warn!(
                    "Failed to queue sync task for peer {} artifact {}: {}",
                    peer_id,
                    artifact.id,
                    e
                ),
            }
        }
        if queued > 0 {
            tracing::info!(
                "Queued sync tasks for artifact {} to {} peer(s)",
                artifact.id,
                queued
            );
        }
        queued
    }

    /// Replicate a just-restored artifact: queue a push to every eligible
    /// peer, forcing a finished push back to `pending`, and cancel those
    /// peers' delete tasks the restore supersedes (#5505). Deletes for peers
    /// outside the push set still run.
    ///
    /// Runs on the caller's connection so the restore and its replication side
    /// effects commit together: a crash cannot leave the restored artifact live
    /// with a pending delete that still takes it off a peer.
    pub async fn queue_restored_artifact_sync_tasks(
        conn: &mut sqlx::PgConnection,
        artifact: &PublishedArtifact<'_>,
    ) -> Result<usize> {
        let peers = Self::push_sync_peers(&mut *conn, artifact)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
        sqlx::query(CANCEL_SUPERSEDED_DELETE_TASKS_SQL)
            .bind(artifact.id)
            .bind(&peers)
            .bind(artifact.repository_id)
            .bind(artifact.path)
            .execute(&mut *conn)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        let mut queued = 0usize;
        for peer_id in peers {
            let result = sqlx::query(QUEUE_RESTORED_PUSH_SQL)
                .bind(peer_id)
                .bind(artifact.id)
                .execute(&mut *conn)
                .await
                .map_err(|e| AppError::Database(e.to_string()))?;
            if result.rows_affected() == 1 {
                queued += 1;
            }
        }
        if queued > 0 {
            tracing::info!(
                "Queued restore pushes for artifact {} to {} peer(s)",
                artifact.id,
                queued
            );
        }
        Ok(queued)
    }

    /// Make sure the peers lose `artifact_ids` (rows of repository
    /// `repository_id`, addressed on the peers as `repository_key`) when the
    /// caller hard-deletes them in the same transaction (#5624): queue an
    /// addressed delete per push/mirror subscriber, and address the deletes
    /// already queued for other peers (a policy-scoped delete, say). The
    /// tasks outlive the rows (`ON DELETE SET NULL`), so the sync worker
    /// delivers them after the rows are gone. Returns the tasks queued or
    /// re-armed.
    pub async fn queue_deletes_before_removal(
        conn: &mut sqlx::PgConnection,
        repository_id: Uuid,
        repository_key: &str,
        artifact_ids: &[Uuid],
    ) -> Result<u64> {
        if artifact_ids.is_empty() {
            return Ok(0);
        }
        sqlx::query(ADDRESS_QUEUED_DELETE_TASKS_SQL)
            .bind(artifact_ids)
            .bind(repository_id)
            .bind(repository_key)
            .execute(&mut *conn)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
        let queued = sqlx::query(QUEUE_REMOVAL_DELETE_TASKS_SQL)
            .bind(artifact_ids)
            .bind(repository_id)
            .bind(repository_key)
            .execute(&mut *conn)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?
            .rows_affected();
        Ok(queued)
    }

    /// Put a finished push task back to `pending` when the artifact it
    /// delivered has since changed. `sent_checksum` and `sent_metadata`
    /// describe what the finished push carried (its content checksum and
    /// metadata document, JSON `null` for none); `None` means unknown, as for
    /// a re-queue, which then re-arms whenever the artifact could differ.
    pub async fn rearm_superseded_push(
        &self,
        task_id: Uuid,
        sent_checksum: Option<&str>,
        sent_metadata: Option<&serde_json::Value>,
    ) -> Result<bool> {
        let result = sqlx::query(REARM_SUPERSEDED_PUSH_SQL)
            .bind(task_id)
            .bind(sent_checksum)
            .bind(sent_metadata)
            .execute(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
        Ok(result.rows_affected() == 1)
    }

    /// Get pending sync tasks for a peer instance
    pub async fn get_pending_sync_tasks(
        &self,
        peer_instance_id: Uuid,
        limit: i64,
    ) -> Result<Vec<SyncTask>> {
        let tasks = sqlx::query_as!(
            SyncTask,
            r#"
            SELECT
                st.id, st.peer_instance_id, st.artifact_id as "artifact_id!",
                st.status as "status: SyncStatus",
                st.priority, st.bytes_transferred, st.error_message,
                st.started_at, st.completed_at, st.created_at,
                a.storage_key, a.size_bytes as artifact_size
            FROM sync_tasks st
            JOIN artifacts a ON a.id = st.artifact_id
            WHERE st.peer_instance_id = $1
              AND st.status = 'pending'
            ORDER BY st.priority DESC, st.created_at
            LIMIT $2
            "#,
            peer_instance_id,
            limit
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(tasks)
    }

    /// Update sync task status
    pub async fn update_sync_task(
        &self,
        task_id: Uuid,
        status: SyncStatus,
        bytes_transferred: Option<i64>,
        error_message: Option<&str>,
    ) -> Result<()> {
        let started_at = if status == SyncStatus::InProgress {
            Some(Utc::now())
        } else {
            None
        };

        let completed_at = if matches!(
            status,
            SyncStatus::Completed | SyncStatus::Failed | SyncStatus::Cancelled
        ) {
            Some(Utc::now())
        } else {
            None
        };

        sqlx::query!(
            r#"
            UPDATE sync_tasks
            SET
                status = $2,
                bytes_transferred = COALESCE($3, bytes_transferred),
                error_message = $4,
                started_at = COALESCE($5, started_at),
                completed_at = COALESCE($6, completed_at)
            WHERE id = $1
            "#,
            task_id,
            status as SyncStatus,
            bytes_transferred,
            error_message,
            started_at,
            completed_at
        )
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(())
    }

    /// Update the replication mode for a repository.
    pub async fn update_replication_mode(
        &self,
        peer_instance_id: Uuid,
        repo_id: Uuid,
        mode: ReplicationMode,
    ) -> Result<()> {
        let result = sqlx::query!(
            r#"
            UPDATE peer_repo_subscriptions
            SET replication_mode = $3
            WHERE peer_instance_id = $1 AND repository_id = $2
            "#,
            peer_instance_id,
            repo_id,
            mode as ReplicationMode
        )
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound("Subscription not found".to_string()));
        }

        Ok(())
    }

    /// Get repositories that require push sync for a given peer instance.
    ///
    /// Returns repo IDs where the effective replication mode (subscription override or
    /// repository default) is `push` and sync is enabled.
    pub async fn get_repos_for_push_sync(&self, peer_instance_id: Uuid) -> Result<Vec<Uuid>> {
        let repos = sqlx::query_scalar!(
            r#"
            SELECT prs.repository_id
            FROM peer_repo_subscriptions prs
            JOIN repositories r ON r.id = prs.repository_id
            WHERE prs.peer_instance_id = $1
              AND prs.sync_enabled = true
              AND prs.replication_mode = 'push'
            "#,
            peer_instance_id
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(repos)
    }

    /// Get repositories with mirror replication for a given peer instance.
    ///
    /// Returns repo metadata including the cron schedule and last replication
    /// timestamp so callers can determine which repos are due for sync.
    pub async fn get_repos_for_mirror_sync(
        &self,
        peer_instance_id: Uuid,
    ) -> Result<Vec<MirrorRepo>> {
        let repos = sqlx::query_as!(
            MirrorRepo,
            r#"
            SELECT
                prs.repository_id as repo_id,
                prs.replication_schedule as schedule,
                prs.last_replicated_at
            FROM peer_repo_subscriptions prs
            JOIN repositories r ON r.id = prs.repository_id
            WHERE prs.peer_instance_id = $1
              AND prs.sync_enabled = true
              AND prs.replication_mode = 'mirror'
            "#,
            peer_instance_id
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(repos)
    }

    /// Register a peer bidirectionally.
    ///
    /// 1. Registers the peer locally (calls self.register())
    /// 2. POSTs an announcement to the remote peer's `/api/v1/peers/announce` endpoint
    pub async fn register_peer_bidirectional(
        &self,
        req: RegisterPeerInstanceRequest,
        local_name: &str,
        local_endpoint_url: &str,
        local_api_key: &str,
    ) -> Result<PeerInstance> {
        let remote_endpoint = req.endpoint_url.clone();

        // Register the peer locally
        let peer = self.register(req).await?;

        // Announce ourselves to the remote peer
        let client = crate::services::http_client::default_client();
        let announce_url = format!(
            "{}/api/v1/peers/announce",
            remote_endpoint.trim_end_matches('/')
        );

        let local_instance = self.get_local_instance().await.ok();
        let local_id = local_instance.map(|i| i.id);

        let announcement = serde_json::json!({
            "peer_id": local_id,
            "name": local_name,
            "endpoint_url": local_endpoint_url,
            "api_key": local_api_key,
        });

        client
            .post(&announce_url)
            .json(&announcement)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("Failed to announce to remote peer: {}", e)))?;

        Ok(peer)
    }
}

/// Sync task status
#[derive(Debug, Clone, Copy, PartialEq, sqlx::Type)]
#[sqlx(type_name = "sync_status", rename_all = "snake_case")]
pub enum SyncStatus {
    Pending,
    InProgress,
    Completed,
    Failed,
    Cancelled,
}

/// Sync task model
#[derive(Debug)]
pub struct SyncTask {
    pub id: Uuid,
    pub peer_instance_id: Uuid,
    pub artifact_id: Uuid,
    pub status: SyncStatus,
    pub priority: i32,
    pub bytes_transferred: i64,
    pub error_message: Option<String>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub storage_key: String,
    pub artifact_size: i64,
}

#[cfg(ak_test_shard = "services-1")]
#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn test_push_mirror_subscriptions_sql_filters_enabled_push_mirror() {
        let sql = PUSH_MIRROR_SUBSCRIPTIONS_SQL;
        assert!(sql.contains("FROM peer_repo_subscriptions prs"));
        assert!(sql.contains("LEFT JOIN sync_policies sp"));
        assert!(sql.contains("prs.sync_enabled = true"));
        assert!(sql.contains("replication_mode::text IN ('push', 'mirror')"));
    }

    /// Tier-2 (skips without DATABASE_URL): the `is_local` peer row must
    /// follow PEER_INSTANCE_NAME / PEER_PUBLIC_ENDPOINT on every boot, in
    /// place — same row id, no duplicate row — not only at first boot (#2832).
    #[tokio::test]
    async fn local_peer_row_reconciles_with_env_on_every_boot() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let svc = PeerInstanceService::new(pool.clone());

        // Snapshot any pre-existing local row so the shared test database is
        // left exactly as found.
        let existing: Option<(Uuid, String, String, Option<String>)> = sqlx::query_as(
            "SELECT id, name, endpoint_url, api_key FROM peer_instances WHERE is_local = true",
        )
        .fetch_optional(&pool)
        .await
        .expect("snapshot local row");

        let suffix = Uuid::new_v4();
        let first_name = format!("reconcile-first-{suffix}");
        let second_name = format!("reconcile-second-{suffix}");

        if existing.is_none() {
            // First boot: the reconcile seeds the local row.
            svc.reconcile_local_instance(&first_name, "http://first:8080", "key-1")
                .await
                .expect("first-boot reconcile seeds the local row");
        }

        let (before_id, _): (Uuid, String) =
            sqlx::query_as("SELECT id, name FROM peer_instances WHERE is_local = true")
                .fetch_one(&pool)
                .await
                .expect("one local row exists");

        // A later boot with changed env must update the SAME row.
        svc.reconcile_local_instance(&second_name, "http://second:9090", "key-2")
            .await
            .expect("reconcile with changed env");

        let rows: Vec<(Uuid, String, String)> = sqlx::query_as(
            "SELECT id, name, endpoint_url FROM peer_instances WHERE is_local = true",
        )
        .fetch_all(&pool)
        .await
        .expect("re-read local rows");
        assert_eq!(
            rows.len(),
            1,
            "reconcile must never duplicate the local row"
        );
        let (after_id, after_name, after_endpoint) = &rows[0];
        assert_eq!(
            *after_id, before_id,
            "the local row keeps its id (and repository assignments) across a rename"
        );
        assert_eq!(after_name, &second_name);
        assert_eq!(after_endpoint, "http://second:9090");

        // Restore the database to its pre-test state.
        match existing {
            Some((id, name, endpoint_url, api_key)) => {
                sqlx::query(
                    "UPDATE peer_instances SET name = $2, endpoint_url = $3, api_key = $4 \
                     WHERE id = $1",
                )
                .bind(id)
                .bind(name)
                .bind(endpoint_url)
                .bind(api_key)
                .execute(&pool)
                .await
                .expect("restore snapshot");
            }
            None => {
                sqlx::query("DELETE FROM peer_instances WHERE id = $1")
                    .bind(before_id)
                    .execute(&pool)
                    .await
                    .expect("remove seeded test row");
            }
        }
    }

    /// DB-backed: a queued sync task must surface a populated `created_at`
    /// through `get_pending_sync_tasks`, so callers can tell a freshly
    /// scheduled task from a stale queue entry. (Backs the replication-schedule
    /// e2e check, which keys on task timestamp recency.)
    ///
    /// Requires a migrated PostgreSQL at `DATABASE_URL`. Run with:
    ///   DATABASE_URL=postgres://... cargo test --lib \
    ///     services::peer_instance_service::tests::pending_task_exposes_created_at -- --ignored
    #[tokio::test]
    #[ignore]
    async fn pending_task_exposes_created_at() {
        let url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
        let db = sqlx::PgPool::connect(&url).await.unwrap();

        let suffix = Uuid::new_v4();
        // Minimal repo.
        let repo_id: Uuid = sqlx::query_scalar(
            "INSERT INTO repositories (key, name, format, repo_type, storage_path) \
             VALUES ($1, $1, 'generic', 'local', $1) RETURNING id",
        )
        .bind(format!("ptask-repo-{suffix}"))
        .fetch_one(&db)
        .await
        .unwrap();

        // Minimal artifact in that repo.
        let artifact_id: Uuid = sqlx::query_scalar(
            "INSERT INTO artifacts (repository_id, name, path, storage_key, size_bytes, \
             content_type, checksum_sha256) \
             VALUES ($1, 'marker.txt', 'sched/marker.txt', $2, 12, 'text/plain', $3) RETURNING id",
        )
        .bind(repo_id)
        .bind(format!("storage/{suffix}"))
        .bind(format!("{:064x}", 1))
        .fetch_one(&db)
        .await
        .unwrap();

        // Non-local online peer.
        let svc = PeerInstanceService::new(db.clone());
        let peer = svc
            .register(RegisterPeerInstanceRequest {
                name: format!("ptask-peer-{suffix}"),
                endpoint_url: "http://127.0.0.1:65535".to_string(),
                region: None,
                cache_size_bytes: 0,
                sync_filter: None,
                api_key: "k".to_string(),
            })
            .await
            .unwrap();

        let before = chrono::Utc::now() - chrono::Duration::seconds(5);
        svc.queue_sync_task(peer.id, artifact_id, 0).await.unwrap();

        let tasks = svc.get_pending_sync_tasks(peer.id, 50).await.unwrap();
        assert_eq!(tasks.len(), 1, "queued task must be listed");
        assert!(
            tasks[0].created_at >= before,
            "created_at must be populated and recent (got {})",
            tasks[0].created_at
        );

        // Cleanup (FK cascade order).
        sqlx::query("DELETE FROM sync_tasks WHERE peer_instance_id = $1")
            .bind(peer.id)
            .execute(&db)
            .await
            .unwrap();
        sqlx::query("DELETE FROM peer_instances WHERE id = $1")
            .bind(peer.id)
            .execute(&db)
            .await
            .unwrap();
        sqlx::query("DELETE FROM artifacts WHERE id = $1")
            .bind(artifact_id)
            .execute(&db)
            .await
            .unwrap();
        sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(repo_id)
            .execute(&db)
            .await
            .unwrap();
    }

    /// Connect to the test database when `DATABASE_URL` is set and reachable;
    /// otherwise return `None` so `cargo test --lib` still passes without a
    /// running Postgres. Fails loud under `AK_TESTS_REQUIRE_DB` (#4801).
    async fn test_pool() -> Option<sqlx::PgPool> {
        crate::testing::try_pool_with(5).await
    }

    async fn insert_test_repo(pool: &sqlx::PgPool, suffix: &Uuid) -> Uuid {
        sqlx::query_scalar(
            "INSERT INTO repositories (key, name, format, repo_type, storage_path) \
             VALUES ($1, $1, 'generic', 'local', $1) RETURNING id",
        )
        .bind(format!("assign-repo-{suffix}"))
        .fetch_one(pool)
        .await
        .unwrap()
    }

    async fn register_test_peer(svc: &PeerInstanceService, suffix: &Uuid) -> Uuid {
        svc.register(RegisterPeerInstanceRequest {
            name: format!("assign-peer-{suffix}"),
            endpoint_url: "http://127.0.0.1:65535".to_string(),
            region: None,
            cache_size_bytes: 0,
            sync_filter: None,
            api_key: "k".to_string(),
        })
        .await
        .unwrap()
        .id
    }

    async fn insert_test_artifact(pool: &sqlx::PgPool, repo_id: Uuid, path: &str) -> Uuid {
        sqlx::query_scalar(
            "INSERT INTO artifacts \
             (repository_id, path, name, size_bytes, checksum_sha256, content_type, storage_key) \
             VALUES ($1, $2, $2, 1, 'sha', 'application/octet-stream', $2) RETURNING id",
        )
        .bind(repo_id)
        .bind(path)
        .fetch_one(pool)
        .await
        .unwrap()
    }

    async fn queued_push_peers(pool: &sqlx::PgPool, artifact_id: Uuid) -> Vec<Uuid> {
        sqlx::query_scalar(
            "SELECT peer_instance_id FROM sync_tasks \
             WHERE artifact_id = $1 AND task_type = 'push' ORDER BY peer_instance_id",
        )
        .bind(artifact_id)
        .fetch_all(pool)
        .await
        .unwrap()
    }

    fn published<'a>(id: Uuid, repository_id: Uuid, path: &'a str) -> PublishedArtifact<'a> {
        PublishedArtifact {
            id,
            repository_id,
            path,
            size_bytes: 1,
            created_at: Utc::now(),
        }
    }

    #[tokio::test]
    async fn queue_push_sync_tasks_targets_enabled_push_and_mirror_subscriptions() {
        let Some(pool) = crate::api::handlers::test_db_helpers::try_pool().await else {
            return;
        };
        let svc = PeerInstanceService::new(pool.clone());
        let repo_id = insert_test_repo(&pool, &Uuid::new_v4()).await;

        let mut peers = Vec::new();
        for (mode, enabled) in [
            (ReplicationMode::Push, true),
            (ReplicationMode::Mirror, true),
            (ReplicationMode::None, true),
            (ReplicationMode::Push, false),
        ] {
            let peer_id = register_test_peer(&svc, &Uuid::new_v4()).await;
            svc.assign_repository(peer_id, repo_id, enabled, Some(mode), None, None)
                .await
                .unwrap();
            peers.push(peer_id);
        }
        // A `pull` row stored before `pull` was refused (#5293) gets no task.
        let legacy_pull_peer = register_test_peer(&svc, &Uuid::new_v4()).await;
        insert_legacy_pull_subscription(&pool, legacy_pull_peer, repo_id).await;
        peers.push(legacy_pull_peer);

        let path = "pkg/1.0.0/pkg-1.0.0.tgz";
        let artifact_id = insert_test_artifact(&pool, repo_id, path).await;
        let artifact = published(artifact_id, repo_id, path);

        assert_eq!(svc.queue_push_sync_tasks(&artifact).await, 2);
        assert_eq!(svc.queue_push_sync_tasks(&artifact).await, 2);
        let mut expected = vec![peers[0], peers[1]];
        expected.sort();
        assert_eq!(queued_push_peers(&pool, artifact_id).await, expected);

        for peer_id in peers {
            cleanup_assign(&pool, peer_id, repo_id).await;
        }
    }

    #[tokio::test]
    async fn queue_push_sync_tasks_skips_artifacts_excluded_by_policy_filter() {
        let Some(pool) = crate::api::handlers::test_db_helpers::try_pool().await else {
            return;
        };
        let svc = PeerInstanceService::new(pool.clone());
        let suffix = Uuid::new_v4();
        let repo_id = insert_test_repo(&pool, &suffix).await;
        let peer_id = register_test_peer(&svc, &suffix).await;
        svc.assign_repository(
            peer_id,
            repo_id,
            true,
            Some(ReplicationMode::Push),
            None,
            None,
        )
        .await
        .unwrap();
        let policy_id: Uuid = sqlx::query_scalar(
            "INSERT INTO sync_policies \
             (name, repo_selector, peer_selector, artifact_filter, precedence) \
             VALUES ($1, $2, $3, $4, 0) RETURNING id",
        )
        .bind(format!("exclude-tgz-{suffix}"))
        .bind(serde_json::json!({ "match_repos": [repo_id] }))
        .bind(serde_json::json!({ "match_peers": [peer_id] }))
        .bind(serde_json::json!({ "exclude_paths": ["*.tgz"] }))
        .fetch_one(&pool)
        .await
        .unwrap();
        sqlx::query(
            "UPDATE peer_repo_subscriptions SET policy_id = $1 \
             WHERE peer_instance_id = $2 AND repository_id = $3",
        )
        .bind(policy_id)
        .bind(peer_id)
        .bind(repo_id)
        .execute(&pool)
        .await
        .unwrap();

        let excluded_path = "pkg/1.0.0/pkg-1.0.0.tgz";
        let included_path = "pkg/1.0.0/pkg-1.0.0.mod";
        let excluded = insert_test_artifact(&pool, repo_id, excluded_path).await;
        let included = insert_test_artifact(&pool, repo_id, included_path).await;

        assert_eq!(
            svc.queue_push_sync_tasks(&published(excluded, repo_id, excluded_path))
                .await,
            0
        );
        assert_eq!(
            svc.queue_push_sync_tasks(&published(included, repo_id, included_path))
                .await,
            1
        );
        assert!(queued_push_peers(&pool, excluded).await.is_empty());
        assert_eq!(queued_push_peers(&pool, included).await, vec![peer_id]);

        cleanup_assign(&pool, peer_id, repo_id).await;
        sqlx::query("DELETE FROM sync_policies WHERE id = $1")
            .bind(policy_id)
            .execute(&pool)
            .await
            .ok();
    }

    /// Store a `pull` subscription directly, as one written before `pull`
    /// was refused at the API (#5293) would be.
    async fn insert_legacy_pull_subscription(pool: &sqlx::PgPool, peer_id: Uuid, repo_id: Uuid) {
        sqlx::query(
            "INSERT INTO peer_repo_subscriptions \
                 (peer_instance_id, repository_id, sync_enabled, replication_mode) \
             VALUES ($1, $2, true, 'pull')",
        )
        .bind(peer_id)
        .bind(repo_id)
        .execute(pool)
        .await
        .unwrap();
    }

    /// #5293: every mode a new subscription can be created with has a task
    /// producer, except `none`, the explicit "do not replicate" mode. `pull`
    /// had none and is refused; an omitted mode is `push`.
    #[test]
    fn every_accepted_subscription_mode_replicates_or_is_none() {
        for mode in [
            ReplicationMode::Push,
            ReplicationMode::Pull,
            ReplicationMode::Mirror,
            ReplicationMode::None,
        ] {
            match ReplicationMode::for_new_subscription(Some(mode)) {
                Ok(stored) => {
                    assert_eq!(stored, mode);
                    assert!(
                        mode.produces_sync_tasks() || mode == ReplicationMode::None,
                        "{mode:?} is accepted but nothing creates sync tasks for it"
                    );
                }
                Err(AppError::Validation(msg)) => {
                    assert_eq!(mode, ReplicationMode::Pull);
                    assert_eq!(msg, PULL_REPLICATION_NOT_IMPLEMENTED);
                }
                Err(other) => panic!("{mode:?}: unexpected error {other:?}"),
            }
        }
        assert_eq!(
            ReplicationMode::for_new_subscription(None).unwrap(),
            ReplicationMode::Push
        );
        assert_eq!(ReplicationMode::DEFAULT, ReplicationMode::Push);
        // The producers' SQL selects exactly the modes `produces_sync_tasks`
        // names, so the two cannot drift apart unnoticed.
        let produced: Vec<&str> = [
            ReplicationMode::Push,
            ReplicationMode::Pull,
            ReplicationMode::Mirror,
            ReplicationMode::None,
        ]
        .into_iter()
        .filter(|m| m.produces_sync_tasks())
        .map(ReplicationMode::as_str)
        .collect();
        assert_eq!(produced, ["push", "mirror"]);
        assert!(PUSH_MIRROR_SUBSCRIPTIONS_SQL.contains("IN ('push', 'mirror')"));
    }

    #[test]
    fn subscription_effective_state_reports_rows_that_never_replicate() {
        assert_eq!(subscription_effective_state(true, Some("push")), "active");
        assert_eq!(subscription_effective_state(true, Some("mirror")), "active");
        assert_eq!(subscription_effective_state(true, Some("pull")), "inactive");
        assert_eq!(subscription_effective_state(true, Some("none")), "inactive");
        assert_eq!(
            subscription_effective_state(false, Some("push")),
            "inactive"
        );
        assert_eq!(subscription_effective_state(true, None), "inactive");
    }

    /// DB-backed (#5293): `pull` is refused before anything is written, the
    /// column default is `push`, and a legacy `pull` row gets no task from
    /// either producer and is named by the boot-time warning.
    #[tokio::test]
    async fn pull_subscriptions_are_refused_and_legacy_rows_are_reported() {
        let Some(pool) = test_pool().await else {
            return;
        };
        let suffix = Uuid::new_v4();
        let svc = PeerInstanceService::new(pool.clone());
        let peer_id = register_test_peer(&svc, &suffix).await;
        let repo_id = insert_test_repo(&pool, &suffix).await;

        let err = svc
            .assign_repository(
                peer_id,
                repo_id,
                true,
                Some(ReplicationMode::Pull),
                None,
                None,
            )
            .await
            .expect_err("pull must be refused");
        assert!(matches!(err, AppError::Validation(_)), "{err:?}");
        assert!(matches!(
            svc.get_subscription(peer_id, repo_id).await,
            Err(AppError::NotFound(_))
        ));

        // The column default agrees with the API default (migration 330).
        sqlx::query(
            "INSERT INTO peer_repo_subscriptions (peer_instance_id, repository_id) VALUES ($1, $2)",
        )
        .bind(peer_id)
        .bind(repo_id)
        .execute(&pool)
        .await
        .unwrap();
        let sub = svc.get_subscription(peer_id, repo_id).await.unwrap();
        assert_eq!(sub.replication_mode.as_deref(), Some("push"));
        sqlx::query("DELETE FROM peer_repo_subscriptions WHERE peer_instance_id = $1")
            .bind(peer_id)
            .execute(&pool)
            .await
            .unwrap();

        insert_legacy_pull_subscription(&pool, peer_id, repo_id).await;
        assert!(svc
            .get_repos_for_push_sync(peer_id)
            .await
            .unwrap()
            .is_empty());
        assert!(svc
            .get_repos_for_mirror_sync(peer_id)
            .await
            .unwrap()
            .is_empty());
        let sub = svc.get_subscription(peer_id, repo_id).await.unwrap();
        assert_eq!(
            subscription_effective_state(sub.sync_enabled, sub.replication_mode.as_deref()),
            "inactive"
        );
        let peer_name: String = sqlx::query_scalar("SELECT name FROM peer_instances WHERE id = $1")
            .bind(peer_id)
            .fetch_one(&pool)
            .await
            .unwrap();
        let repo_key: String = sqlx::query_scalar("SELECT key FROM repositories WHERE id = $1")
            .bind(repo_id)
            .fetch_one(&pool)
            .await
            .unwrap();
        let warned = warn_inactive_pull_replication(&pool).await;
        assert!(
            warned.contains(&(
                "subscription".to_string(),
                format!("{peer_name}/{repo_key}")
            )),
            "{warned:?}"
        );

        cleanup_assign(&pool, peer_id, repo_id).await;
    }

    async fn cleanup_assign(pool: &sqlx::PgPool, peer_id: Uuid, repo_id: Uuid) {
        // peer_repo_subscriptions cascades from both peer and repo deletes.
        sqlx::query("DELETE FROM peer_instances WHERE id = $1")
            .bind(peer_id)
            .execute(pool)
            .await
            .ok();
        sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(repo_id)
            .execute(pool)
            .await
            .ok();
    }

    /// DB-backed regression for the 1.2.2 federation fix: assigning a valid
    /// repository to a peer with NO `replication_mode` supplied must succeed
    /// and persist a subscription. Previously this wrote a NULL into the NOT
    /// NULL `replication_mode` column and surfaced as an opaque 500
    /// DATABASE_ERROR for every such call. The default is `push` since #5293:
    /// it was `pull`, which never replicated anything.
    #[tokio::test]
    async fn assign_repository_without_mode_defaults_to_push_and_persists() {
        let Some(pool) = test_pool().await else {
            return;
        };
        let suffix = Uuid::new_v4();
        let svc = PeerInstanceService::new(pool.clone());
        let peer_id = register_test_peer(&svc, &suffix).await;
        let repo_id = insert_test_repo(&pool, &suffix).await;

        // No replication_mode -> must NOT error.
        svc.assign_repository(peer_id, repo_id, true, None, None, None)
            .await
            .expect("assignment without replication_mode must succeed");

        // Persisted with the default, a mode that replicates.
        let sub = svc.get_subscription(peer_id, repo_id).await.unwrap();
        assert_eq!(sub.repository_id, repo_id);
        assert_eq!(sub.replication_mode.as_deref(), Some("push"));
        assert_eq!(
            subscription_effective_state(sub.sync_enabled, sub.replication_mode.as_deref()),
            "active"
        );
        assert!(sub.sync_enabled);

        // Idempotent upsert: a second assign with an explicit mode updates,
        // not errors.
        svc.assign_repository(
            peer_id,
            repo_id,
            true,
            Some(ReplicationMode::Mirror),
            None,
            None,
        )
        .await
        .expect("re-assign (upsert) must succeed");
        let sub2 = svc.get_subscription(peer_id, repo_id).await.unwrap();
        assert_eq!(sub2.replication_mode.as_deref(), Some("mirror"));
        assert_eq!(
            sub2.id, sub.id,
            "upsert must reuse the same subscription row"
        );

        cleanup_assign(&pool, peer_id, repo_id).await;
    }

    /// DB-backed: `list_subscriptions` must carry the persisted replication
    /// mode, not just the repository id.
    #[tokio::test]
    async fn list_subscriptions_returns_rows_with_replication_mode() {
        let Some(pool) = test_pool().await else {
            return;
        };
        let suffix = Uuid::new_v4();
        let svc = PeerInstanceService::new(pool.clone());
        let peer_id = register_test_peer(&svc, &suffix).await;
        let repo_id = insert_test_repo(&pool, &suffix).await;

        svc.assign_repository(
            peer_id,
            repo_id,
            true,
            Some(ReplicationMode::Push),
            None,
            None,
        )
        .await
        .expect("assignment must succeed");

        // list_subscriptions must carry the real mode (not just the id) so the
        // dashboard renders the true direction instead of defaulting to "pull".
        let subs = svc.list_subscriptions(peer_id).await.unwrap();
        let sub = subs
            .iter()
            .find(|s| s.repository_id == repo_id)
            .expect("assigned repo must be listed");
        assert_eq!(sub.replication_mode.as_deref(), Some("push"));
        assert!(sub.sync_enabled);

        cleanup_assign(&pool, peer_id, repo_id).await;
    }

    /// DB-backed: assigning a non-existent repository must map the FK violation
    /// to NotFound (404), not an opaque 500 DATABASE_ERROR.
    #[tokio::test]
    async fn assign_repository_with_missing_repo_returns_not_found() {
        let Some(pool) = test_pool().await else {
            return;
        };
        let suffix = Uuid::new_v4();
        let svc = PeerInstanceService::new(pool.clone());
        let peer_id = register_test_peer(&svc, &suffix).await;
        let bogus_repo = Uuid::new_v4();

        let err = svc
            .assign_repository(
                peer_id,
                bogus_repo,
                true,
                Some(ReplicationMode::Push),
                None,
                None,
            )
            .await
            .expect_err("assigning a non-existent repo must error");
        assert!(
            matches!(err, AppError::NotFound(_)),
            "expected NotFound for missing repository, got {err:?}"
        );

        // Cleanup peer (no subscription was created).
        sqlx::query("DELETE FROM peer_instances WHERE id = $1")
            .bind(peer_id)
            .execute(&pool)
            .await
            .ok();
    }

    /// DB-backed regression: `list_subscriptions` backs the assigned-repos
    /// endpoint, which has always meant "repos this peer syncs". A subscription
    /// assigned with `sync_enabled = false` is a supported way to park an
    /// assignment, and it must stay out of the list.
    #[tokio::test]
    async fn list_subscriptions_omits_sync_disabled_rows() {
        let Some(pool) = test_pool().await else {
            return;
        };
        let svc = PeerInstanceService::new(pool.clone());
        let peer_suffix = Uuid::new_v4();
        let peer_id = register_test_peer(&svc, &peer_suffix).await;
        let enabled_repo = insert_test_repo(&pool, &Uuid::new_v4()).await;
        let disabled_repo = insert_test_repo(&pool, &Uuid::new_v4()).await;

        svc.assign_repository(
            peer_id,
            enabled_repo,
            true,
            Some(ReplicationMode::Push),
            None,
            None,
        )
        .await
        .expect("enabled assignment must succeed");
        svc.assign_repository(
            peer_id,
            disabled_repo,
            false,
            Some(ReplicationMode::Push),
            None,
            None,
        )
        .await
        .expect("disabled assignment must succeed");

        let subs = svc.list_subscriptions(peer_id).await.unwrap();
        let listed: Vec<Uuid> = subs.iter().map(|s| s.repository_id).collect();
        assert!(
            listed.contains(&enabled_repo),
            "sync-enabled subscription must be listed, got {listed:?}"
        );
        assert!(
            !listed.contains(&disabled_repo),
            "sync_enabled = false subscription must not be listed, got {listed:?}"
        );
        assert!(
            subs.iter().all(|s| s.sync_enabled),
            "every listed subscription must be sync-enabled"
        );

        cleanup_assign(&pool, peer_id, enabled_repo).await;
        sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(disabled_repo)
            .execute(&pool)
            .await
            .ok();
    }

    // -----------------------------------------------------------------------
    // Pure helper functions (moved from module scope — test-only)
    // -----------------------------------------------------------------------

    fn derive_sync_status(completed: bool) -> InstanceStatus {
        if completed {
            InstanceStatus::Online
        } else {
            InstanceStatus::Syncing
        }
    }

    fn resolve_heartbeat_status(status: Option<InstanceStatus>) -> InstanceStatus {
        status.unwrap_or(InstanceStatus::Online)
    }

    fn cache_utilization_pct(cache_size_bytes: i64, cache_used_bytes: i64) -> f64 {
        if cache_size_bytes <= 0 {
            0.0
        } else {
            (cache_used_bytes as f64 / cache_size_bytes as f64) * 100.0
        }
    }

    fn is_heartbeat_stale(
        last_heartbeat_at: Option<DateTime<Utc>>,
        now: DateTime<Utc>,
        stale_threshold_minutes: i64,
    ) -> bool {
        match last_heartbeat_at {
            Some(hb) => (now - hb).num_minutes() >= stale_threshold_minutes,
            None => true,
        }
    }

    fn is_in_backoff(backoff_until: Option<DateTime<Utc>>, now: DateTime<Utc>) -> bool {
        backoff_until.is_some_and(|bu| now < bu)
    }

    fn has_transfer_capacity(
        active_transfers: i32,
        concurrent_transfers_limit: Option<i32>,
    ) -> bool {
        match concurrent_transfers_limit {
            Some(limit) => active_transfers < limit,
            None => true,
        }
    }

    fn transfer_success_rate(bytes_transferred_total: i64, transfer_failures_total: i32) -> f64 {
        let _total_attempts = bytes_transferred_total.max(1) as f64;
        if transfer_failures_total == 0 {
            1.0
        } else {
            let failure_rate =
                transfer_failures_total as f64 / (transfer_failures_total as f64 + 1.0);
            1.0 - failure_rate
        }
    }

    fn build_announce_url(remote_endpoint: &str) -> String {
        format!(
            "{}/api/v1/peers/announce",
            remote_endpoint.trim_end_matches('/')
        )
    }

    fn sync_task_started_at(status: SyncStatus, now: DateTime<Utc>) -> Option<DateTime<Utc>> {
        if status == SyncStatus::InProgress {
            Some(now)
        } else {
            None
        }
    }

    fn sync_task_completed_at(status: SyncStatus, now: DateTime<Utc>) -> Option<DateTime<Utc>> {
        if matches!(
            status,
            SyncStatus::Completed | SyncStatus::Failed | SyncStatus::Cancelled
        ) {
            Some(now)
        } else {
            None
        }
    }

    // ===================================================================
    // InstanceStatus Display
    // ===================================================================

    #[test]
    fn test_instance_status_display_online() {
        assert_eq!(InstanceStatus::Online.to_string(), "online");
    }

    #[test]
    fn test_instance_status_display_offline() {
        assert_eq!(InstanceStatus::Offline.to_string(), "offline");
    }

    #[test]
    fn test_instance_status_display_syncing() {
        assert_eq!(InstanceStatus::Syncing.to_string(), "syncing");
    }

    #[test]
    fn test_instance_status_display_degraded() {
        assert_eq!(InstanceStatus::Degraded.to_string(), "degraded");
    }

    #[test]
    fn test_instance_status_equality() {
        assert_eq!(InstanceStatus::Online, InstanceStatus::Online);
        assert_ne!(InstanceStatus::Online, InstanceStatus::Offline);
    }

    #[test]
    fn test_instance_status_clone_copy() {
        let s = InstanceStatus::Syncing;
        let s2 = s;
        let s3 = s;
        assert_eq!(s, s2);
        assert_eq!(s, s3);
    }

    // ===================================================================
    // ReplicationMode / SyncStatus
    // ===================================================================

    #[test]
    fn test_replication_mode_equality() {
        assert_eq!(ReplicationMode::Push, ReplicationMode::Push);
        assert_ne!(ReplicationMode::Push, ReplicationMode::Pull);
    }

    #[test]
    fn test_sync_status_equality() {
        assert_eq!(SyncStatus::Pending, SyncStatus::Pending);
        assert_ne!(SyncStatus::Pending, SyncStatus::Completed);
    }

    // ===================================================================
    // derive_sync_status
    // ===================================================================

    #[test]
    fn test_derive_sync_status_completed() {
        assert_eq!(derive_sync_status(true), InstanceStatus::Online);
    }

    #[test]
    fn test_derive_sync_status_not_completed() {
        assert_eq!(derive_sync_status(false), InstanceStatus::Syncing);
    }

    // ===================================================================
    // resolve_heartbeat_status
    // ===================================================================

    #[test]
    fn test_resolve_heartbeat_status_none() {
        assert_eq!(resolve_heartbeat_status(None), InstanceStatus::Online);
    }

    #[test]
    fn test_resolve_heartbeat_status_some_degraded() {
        assert_eq!(
            resolve_heartbeat_status(Some(InstanceStatus::Degraded)),
            InstanceStatus::Degraded
        );
    }

    #[test]
    fn test_resolve_heartbeat_status_some_syncing() {
        assert_eq!(
            resolve_heartbeat_status(Some(InstanceStatus::Syncing)),
            InstanceStatus::Syncing
        );
    }

    #[test]
    fn test_resolve_heartbeat_status_some_offline() {
        assert_eq!(
            resolve_heartbeat_status(Some(InstanceStatus::Offline)),
            InstanceStatus::Offline
        );
    }

    #[test]
    fn test_resolve_heartbeat_status_some_online() {
        assert_eq!(
            resolve_heartbeat_status(Some(InstanceStatus::Online)),
            InstanceStatus::Online
        );
    }

    // ===================================================================
    // cache_utilization_pct
    // ===================================================================

    #[test]
    fn test_cache_utilization_pct_zero_size() {
        assert!((cache_utilization_pct(0, 0) - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_cache_utilization_pct_negative_size() {
        assert!((cache_utilization_pct(-1, 100) - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_cache_utilization_pct_half_used() {
        assert!((cache_utilization_pct(1000, 500) - 50.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_cache_utilization_pct_fully_used() {
        assert!((cache_utilization_pct(1000, 1000) - 100.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_cache_utilization_pct_empty() {
        assert!((cache_utilization_pct(1000, 0) - 0.0).abs() < f64::EPSILON);
    }

    // ===================================================================
    // is_heartbeat_stale
    // ===================================================================

    #[test]
    fn test_is_heartbeat_stale_no_heartbeat() {
        let now = Utc::now();
        assert!(is_heartbeat_stale(None, now, 5));
    }

    #[test]
    fn test_is_heartbeat_stale_recent() {
        let now = Utc::now();
        let recent = now - Duration::minutes(2);
        assert!(!is_heartbeat_stale(Some(recent), now, 5));
    }

    #[test]
    fn test_is_heartbeat_stale_exactly_threshold() {
        let now = Utc::now();
        let exactly = now - Duration::minutes(5);
        assert!(is_heartbeat_stale(Some(exactly), now, 5));
    }

    #[test]
    fn test_is_heartbeat_stale_old() {
        let now = Utc::now();
        let old = now - Duration::minutes(60);
        assert!(is_heartbeat_stale(Some(old), now, 5));
    }

    #[test]
    fn test_is_heartbeat_stale_zero_threshold() {
        let now = Utc::now();
        // Any heartbeat in the past is stale with 0 threshold
        let hb = now - Duration::seconds(1);
        assert!(is_heartbeat_stale(Some(hb), now, 0));
    }

    // ===================================================================
    // is_in_backoff
    // ===================================================================

    #[test]
    fn test_is_in_backoff_none() {
        assert!(!is_in_backoff(None, Utc::now()));
    }

    #[test]
    fn test_is_in_backoff_future() {
        let now = Utc::now();
        let future = now + Duration::minutes(10);
        assert!(is_in_backoff(Some(future), now));
    }

    #[test]
    fn test_is_in_backoff_past() {
        let now = Utc::now();
        let past = now - Duration::minutes(10);
        assert!(!is_in_backoff(Some(past), now));
    }

    #[test]
    fn test_is_in_backoff_exact_now() {
        let now = Utc::now();
        assert!(!is_in_backoff(Some(now), now));
    }

    // ===================================================================
    // has_transfer_capacity
    // ===================================================================

    #[test]
    fn test_has_transfer_capacity_no_limit() {
        assert!(has_transfer_capacity(100, None));
    }

    #[test]
    fn test_has_transfer_capacity_under_limit() {
        assert!(has_transfer_capacity(2, Some(4)));
    }

    #[test]
    fn test_has_transfer_capacity_at_limit() {
        assert!(!has_transfer_capacity(4, Some(4)));
    }

    #[test]
    fn test_has_transfer_capacity_over_limit() {
        assert!(!has_transfer_capacity(5, Some(4)));
    }

    #[test]
    fn test_has_transfer_capacity_zero_active() {
        assert!(has_transfer_capacity(0, Some(1)));
    }

    // ===================================================================
    // transfer_success_rate
    // ===================================================================

    #[test]
    fn test_transfer_success_rate_no_failures() {
        assert!((transfer_success_rate(1000, 0) - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_transfer_success_rate_some_failures() {
        let rate = transfer_success_rate(1000, 1);
        assert!(rate > 0.0);
        assert!(rate < 1.0);
    }

    #[test]
    fn test_transfer_success_rate_many_failures() {
        let rate = transfer_success_rate(1000, 99);
        assert!(rate > 0.0);
        assert!(rate < 0.05);
    }

    #[test]
    fn test_transfer_success_rate_zero_bytes() {
        let rate = transfer_success_rate(0, 0);
        assert!((rate - 1.0).abs() < f64::EPSILON);
    }

    // ===================================================================
    // build_announce_url
    // ===================================================================

    #[test]
    fn test_build_announce_url_simple() {
        assert_eq!(
            build_announce_url("https://peer.example.com"),
            "https://peer.example.com/api/v1/peers/announce"
        );
    }

    #[test]
    fn test_build_announce_url_trailing_slash() {
        assert_eq!(
            build_announce_url("https://peer.example.com/"),
            "https://peer.example.com/api/v1/peers/announce"
        );
    }

    #[test]
    fn test_build_announce_url_multiple_trailing_slashes() {
        // trim_end_matches removes ALL trailing matching chars
        assert_eq!(
            build_announce_url("https://peer.example.com///"),
            "https://peer.example.com/api/v1/peers/announce"
        );
    }

    #[test]
    fn test_build_announce_url_with_port() {
        assert_eq!(
            build_announce_url("http://localhost:8080"),
            "http://localhost:8080/api/v1/peers/announce"
        );
    }

    #[test]
    fn test_build_announce_url_with_path() {
        assert_eq!(
            build_announce_url("https://peer.example.com/prefix"),
            "https://peer.example.com/prefix/api/v1/peers/announce"
        );
    }

    // ===================================================================
    // sync_task_started_at
    // ===================================================================

    #[test]
    fn test_sync_task_started_at_in_progress() {
        let now = Utc::now();
        let result = sync_task_started_at(SyncStatus::InProgress, now);
        assert_eq!(result, Some(now));
    }

    #[test]
    fn test_sync_task_started_at_pending() {
        let now = Utc::now();
        assert!(sync_task_started_at(SyncStatus::Pending, now).is_none());
    }

    #[test]
    fn test_sync_task_started_at_completed() {
        let now = Utc::now();
        assert!(sync_task_started_at(SyncStatus::Completed, now).is_none());
    }

    #[test]
    fn test_sync_task_started_at_failed() {
        let now = Utc::now();
        assert!(sync_task_started_at(SyncStatus::Failed, now).is_none());
    }

    #[test]
    fn test_sync_task_started_at_cancelled() {
        let now = Utc::now();
        assert!(sync_task_started_at(SyncStatus::Cancelled, now).is_none());
    }

    // ===================================================================
    // sync_task_completed_at
    // ===================================================================

    #[test]
    fn test_sync_task_completed_at_completed() {
        let now = Utc::now();
        assert_eq!(
            sync_task_completed_at(SyncStatus::Completed, now),
            Some(now)
        );
    }

    #[test]
    fn test_sync_task_completed_at_failed() {
        let now = Utc::now();
        assert_eq!(sync_task_completed_at(SyncStatus::Failed, now), Some(now));
    }

    #[test]
    fn test_sync_task_completed_at_cancelled() {
        let now = Utc::now();
        assert_eq!(
            sync_task_completed_at(SyncStatus::Cancelled, now),
            Some(now)
        );
    }

    #[test]
    fn test_sync_task_completed_at_pending() {
        let now = Utc::now();
        assert!(sync_task_completed_at(SyncStatus::Pending, now).is_none());
    }

    #[test]
    fn test_sync_task_completed_at_in_progress() {
        let now = Utc::now();
        assert!(sync_task_completed_at(SyncStatus::InProgress, now).is_none());
    }

    // ===================================================================
    // Existing struct construction tests
    // ===================================================================

    #[test]
    fn test_register_peer_instance_request_construction() {
        let req = RegisterPeerInstanceRequest {
            name: "peer-1".to_string(),
            endpoint_url: "https://peer1.example.com".to_string(),
            region: Some("us-east-1".to_string()),
            cache_size_bytes: 10 * 1024 * 1024 * 1024,
            sync_filter: Some(serde_json::json!({"formats": ["maven", "docker"]})),
            api_key: "secret-key".to_string(),
        };
        assert_eq!(req.name, "peer-1");
        assert_eq!(req.cache_size_bytes, 10_737_418_240);
    }

    #[test]
    fn test_peer_instance_construction() {
        let now = Utc::now();
        let peer = PeerInstance {
            id: Uuid::new_v4(),
            name: "peer-node".to_string(),
            endpoint_url: "https://node.example.com".to_string(),
            status: InstanceStatus::Online,
            region: Some("eu-west-1".to_string()),
            cache_size_bytes: 5_000_000_000,
            cache_used_bytes: 1_000_000_000,
            last_heartbeat_at: Some(now),
            last_sync_at: None,
            sync_filter: None,
            max_bandwidth_bps: Some(100_000_000),
            sync_window_start: None,
            sync_window_end: None,
            sync_window_timezone: None,
            concurrent_transfers_limit: Some(4),
            active_transfers: 0,
            backoff_until: None,
            consecutive_failures: 0,
            bytes_transferred_total: 0,
            transfer_failures_total: 0,
            api_key: "key".to_string(),
            is_local: false,
            created_at: now,
            updated_at: now,
        };
        assert_eq!(peer.name, "peer-node");
        assert_eq!(peer.status, InstanceStatus::Online);
        assert!(!peer.is_local);
    }

    #[test]
    fn test_sync_task_construction() {
        let now = Utc::now();
        let task = SyncTask {
            id: Uuid::new_v4(),
            peer_instance_id: Uuid::new_v4(),
            artifact_id: Uuid::new_v4(),
            status: SyncStatus::Pending,
            priority: 5,
            bytes_transferred: 0,
            error_message: None,
            started_at: None,
            completed_at: None,
            created_at: now,
            storage_key: "repos/maven/com/example/1.0/artifact.jar".to_string(),
            artifact_size: 1024 * 1024,
        };
        assert_eq!(task.status, SyncStatus::Pending);
        assert_eq!(task.priority, 5);
    }

    #[test]
    fn test_mirror_repo_construction() {
        let repo = MirrorRepo {
            repo_id: Uuid::new_v4(),
            schedule: Some("0 */6 * * *".to_string()),
            last_replicated_at: Some(Utc::now()),
        };
        assert!(repo.schedule.is_some());
    }

    fn at(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    /// #5342: when a scheduled `mirror` pass is due.
    #[test]
    fn mirror_schedule_state_follows_the_cron_after_the_last_pass() {
        use MirrorScheduleState::*;
        let last = Some(at("2026-01-01T03:00:00Z"));
        let cases = [
            (None, last, "2026-01-05T00:00:00Z", Unscheduled),
            (Some("  "), last, "2026-01-05T00:00:00Z", Unscheduled),
            (Some("not cron"), last, "2026-01-05T00:00:00Z", Invalid),
            // Never replicated: due at once.
            (Some("0 3 * * *"), None, "2026-01-01T00:00:00Z", Due),
            (Some("0 3 * * *"), last, "2026-01-02T02:59:59Z", NotDue),
            (Some("0 3 * * *"), last, "2026-01-02T03:00:00Z", Due),
            // Several missed occurrences are one pass, still due.
            (Some("0 3 * * *"), last, "2026-01-09T12:00:00Z", Due),
            // 6-field (with seconds) is accepted as-is.
            (Some("0 0 */6 * * *"), last, "2026-01-01T05:59:59Z", NotDue),
            (Some("0 0 */6 * * *"), last, "2026-01-01T06:00:00Z", Due),
        ];
        for (schedule, last, now, want) in cases {
            assert_eq!(
                mirror_schedule_state(schedule, last, at(now)),
                want,
                "{schedule:?} last={last:?} now={now}"
            );
        }
    }

    #[test]
    fn replication_schedule_validation_refuses_only_bad_cron() {
        assert!(validate_replication_schedule(None).is_ok());
        assert!(validate_replication_schedule(Some("")).is_ok());
        assert!(validate_replication_schedule(Some("0 */6 * * *")).is_ok());
        assert!(validate_replication_schedule(Some("0 0 3 * * *")).is_ok());
        let err = validate_replication_schedule(Some("every day")).unwrap_err();
        assert!(
            matches!(&err, AppError::Validation(m) if m.contains("every day")),
            "{err:?}"
        );
    }

    /// DB-backed (#5342): an invalid cron is refused before anything is
    /// written instead of being stored and never firing.
    #[tokio::test]
    async fn assign_repository_refuses_an_invalid_replication_schedule() {
        let Some(pool) = test_pool().await else {
            return;
        };
        let suffix = Uuid::new_v4();
        let svc = PeerInstanceService::new(pool.clone());
        let peer_id = register_test_peer(&svc, &suffix).await;
        let repo_id = insert_test_repo(&pool, &suffix).await;
        let err = svc
            .assign_repository(
                peer_id,
                repo_id,
                true,
                Some(ReplicationMode::Mirror),
                Some("61 * * * *".to_string()),
                None,
            )
            .await
            .expect_err("invalid cron must be refused");
        assert!(matches!(err, AppError::Validation(_)), "{err:?}");
        assert!(matches!(
            svc.get_subscription(peer_id, repo_id).await,
            Err(AppError::NotFound(_))
        ));
        let _ = sqlx::query("DELETE FROM peer_instances WHERE id = $1")
            .bind(peer_id)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(repo_id)
            .execute(&pool)
            .await;
    }

    async fn completed_push_fixture(
        pool: &sqlx::PgPool,
        svc: &PeerInstanceService,
        versioning_enabled: bool,
    ) -> (Uuid, Uuid, Uuid, Uuid) {
        let suffix = Uuid::new_v4();
        let repo_id = insert_test_repo(pool, &suffix).await;
        sqlx::query("UPDATE repositories SET versioning_enabled = $2 WHERE id = $1")
            .bind(repo_id)
            .bind(versioning_enabled)
            .execute(pool)
            .await
            .unwrap();
        let peer_id = register_test_peer(svc, &suffix).await;
        let artifact_id: Uuid = sqlx::query_scalar(
            "INSERT INTO artifacts (repository_id, path, name, size_bytes, checksum_sha256, \
             content_type, storage_key) \
             VALUES ($1, 'ansible-master.tar.gz', 'ansible-master.tar.gz', 1, $2, \
             'application/gzip', $3) RETURNING id",
        )
        .bind(repo_id)
        .bind(format!("{:064x}", 1))
        .bind(format!("rearm/{suffix}"))
        .fetch_one(pool)
        .await
        .unwrap();
        let task_id = svc.queue_sync_task(peer_id, artifact_id, 0).await.unwrap();
        sqlx::query(
            "UPDATE sync_tasks SET status = 'completed', completed_at = NOW() - INTERVAL '1 hour', \
             retry_count = 2, error_message = 'old' WHERE id = $1",
        )
        .bind(task_id)
        .execute(pool)
        .await
        .unwrap();
        (repo_id, peer_id, artifact_id, task_id)
    }

    async fn push_task_state(pool: &sqlx::PgPool, task_id: Uuid) -> (String, i32, Option<Uuid>) {
        sqlx::query_as(
            "SELECT status::TEXT, retry_count, claim_token FROM sync_tasks WHERE id = $1",
        )
        .bind(task_id)
        .fetch_one(pool)
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn queue_sync_task_requeues_completed_push_after_versioned_reupload() {
        let Some(pool) = crate::api::handlers::test_db_helpers::try_pool().await else {
            return;
        };
        let svc = PeerInstanceService::new(pool.clone());
        let (repo_id, peer_id, artifact_id, task_id) =
            completed_push_fixture(&pool, &svc, true).await;

        assert_eq!(
            svc.queue_sync_task(peer_id, artifact_id, 0).await.unwrap(),
            task_id
        );

        let pending: Vec<Uuid> = svc
            .get_pending_sync_tasks(peer_id, 10)
            .await
            .unwrap()
            .iter()
            .map(|t| t.id)
            .collect();
        assert_eq!(pending, vec![task_id]);
        assert_eq!(
            push_task_state(&pool, task_id).await,
            ("pending".to_string(), 0, None)
        );
        cleanup_assign(&pool, peer_id, repo_id).await;
    }

    #[tokio::test]
    async fn queue_sync_task_requeues_completed_push_after_delete_and_reupload() {
        let Some(pool) = crate::api::handlers::test_db_helpers::try_pool().await else {
            return;
        };
        let svc = PeerInstanceService::new(pool.clone());
        let (repo_id, peer_id, artifact_id, task_id) =
            completed_push_fixture(&pool, &svc, false).await;
        sqlx::query(
            "INSERT INTO sync_tasks (peer_instance_id, artifact_id, task_type, status, completed_at) \
             VALUES ($1, $2, 'delete', 'completed', NOW() - INTERVAL '30 minutes')",
        )
        .bind(peer_id)
        .bind(artifact_id)
        .execute(&pool)
        .await
        .unwrap();

        svc.queue_sync_task(peer_id, artifact_id, 0).await.unwrap();
        assert_eq!(
            push_task_state(&pool, task_id).await,
            ("pending".to_string(), 0, None)
        );

        sqlx::query(
            "UPDATE sync_tasks SET status = 'completed', completed_at = NOW() WHERE id = $1",
        )
        .bind(task_id)
        .execute(&pool)
        .await
        .unwrap();
        assert!(!svc
            .rearm_superseded_push(task_id, Some(&format!("{:064x}", 1)), None)
            .await
            .unwrap());
        cleanup_assign(&pool, peer_id, repo_id).await;
    }

    /// #4792: a pacman signature lives in the package's metadata. A push that
    /// finished without it is re-armed once the package is signed; a push that
    /// carried it (with or without the merged file list), or an unsigned
    /// package, is left alone.
    #[tokio::test]
    async fn rearm_redelivers_pacman_package_signed_after_its_push_4792() {
        let Some(pool) = crate::api::handlers::test_db_helpers::try_pool().await else {
            return;
        };
        let svc = PeerInstanceService::new(pool.clone());
        let (repo_id, peer_id, artifact_id, task_id) =
            completed_push_fixture(&pool, &svc, false).await;
        sqlx::query("UPDATE repositories SET format = 'pacman' WHERE id = $1")
            .bind(repo_id)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO artifact_metadata (artifact_id, format, metadata) \
             VALUES ($1, 'pacman', '{\"filename\": \"x\"}')",
        )
        .bind(artifact_id)
        .execute(&pool)
        .await
        .unwrap();
        let checksum = format!("{:064x}", 1);

        let unsigned = serde_json::json!({ "filename": "x" });
        let signed = serde_json::json!({ "filename": "x", "pgpsig": "AAE=" });
        // As the claim sends it: the file list merged into the document.
        let signed_with_files =
            serde_json::json!({ "filename": "x", "pgpsig": "AAE=", "files": ["usr/"] });

        // Unsigned: nothing to re-deliver.
        assert!(!svc
            .rearm_superseded_push(task_id, Some(&checksum), Some(&unsigned))
            .await
            .unwrap());
        svc.queue_sync_task(peer_id, artifact_id, 0).await.unwrap();
        assert_eq!(push_task_state(&pool, task_id).await.0, "completed");

        sqlx::query(
            "UPDATE artifact_metadata SET metadata = metadata || '{\"pgpsig\": \"AAE=\"}' \
             WHERE artifact_id = $1",
        )
        .bind(artifact_id)
        .execute(&pool)
        .await
        .unwrap();

        // The delivered copy already carried the signature.
        for sent in [&signed, &signed_with_files] {
            assert!(!svc
                .rearm_superseded_push(task_id, Some(&checksum), Some(sent))
                .await
                .unwrap());
        }
        // It went out unsigned (signature attached while in flight).
        assert!(svc
            .rearm_superseded_push(task_id, Some(&checksum), Some(&unsigned))
            .await
            .unwrap());
        assert_eq!(
            push_task_state(&pool, task_id).await,
            ("pending".to_string(), 0, None)
        );

        // A re-queue after the signature is attached re-arms a finished push.
        sqlx::query(
            "UPDATE sync_tasks SET status = 'completed', completed_at = NOW() WHERE id = $1",
        )
        .bind(task_id)
        .execute(&pool)
        .await
        .unwrap();
        svc.queue_sync_task(peer_id, artifact_id, 0).await.unwrap();
        assert_eq!(push_task_state(&pool, task_id).await.0, "pending");

        // #4889: a document that still holds its file list (written by a
        // pre-#4424 replica during a rolling upgrade) is sent as stored. With
        // the re-arm now applying to every pacman push, comparing it against
        // a stripped copy would re-queue the package after every delivery.
        let legacy = serde_json::json!({ "filename": "x", "pgpsig": "AAE=", "files": ["usr/"] });
        sqlx::query("UPDATE artifact_metadata SET metadata = $2 WHERE artifact_id = $1")
            .bind(artifact_id)
            .bind(&legacy)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "UPDATE sync_tasks SET status = 'completed', completed_at = NOW() WHERE id = $1",
        )
        .bind(task_id)
        .execute(&pool)
        .await
        .unwrap();
        assert!(
            !svc.rearm_superseded_push(task_id, Some(&checksum), Some(&legacy))
                .await
                .unwrap(),
            "an unchanged pacman document with an inline file list must not loop"
        );

        sqlx::query("DELETE FROM artifact_metadata WHERE artifact_id = $1")
            .bind(artifact_id)
            .execute(&pool)
            .await
            .unwrap();
        cleanup_assign(&pool, peer_id, repo_id).await;
    }

    /// #4889: NuGet, PyPI, Debian and nested-layout RPM used to write their
    /// `artifact_metadata` after the push was queued. A worker that finished
    /// the transfer in that window must be re-armed once the document lands,
    /// not only for pacman/conda. Fails on `main` for all four formats.
    #[tokio::test]
    async fn rearm_redelivers_format_metadata_written_after_push_4889() {
        let Some(pool) = crate::api::handlers::test_db_helpers::try_pool().await else {
            return;
        };
        let svc = PeerInstanceService::new(pool.clone());
        let checksum = format!("{:064x}", 1);

        for format in ["nuget", "pypi", "debian", "rpm"] {
            let (repo_id, peer_id, artifact_id, task_id) =
                completed_push_fixture(&pool, &svc, false).await;
            sqlx::query("UPDATE repositories SET format = $2::repository_format WHERE id = $1")
                .bind(repo_id)
                .bind(format)
                .execute(&pool)
                .await
                .unwrap();

            // Nothing was attached when the push finished.
            let no_metadata = serde_json::Value::Null;
            assert!(!svc
                .rearm_superseded_push(task_id, Some(&checksum), Some(&no_metadata))
                .await
                .unwrap());

            // The handler writes metadata immediately after queueing.
            let metadata = serde_json::json!({ "format": format, "late": true });
            sqlx::query(
                "INSERT INTO artifact_metadata (artifact_id, format, metadata) \
                 VALUES ($1, $2, $3)",
            )
            .bind(artifact_id)
            .bind(format)
            .bind(&metadata)
            .execute(&pool)
            .await
            .unwrap();
            assert!(
                svc.rearm_superseded_push(task_id, Some(&checksum), Some(&no_metadata))
                    .await
                    .unwrap(),
                "{format} metadata written after the push must trigger a redelivery"
            );
            assert_eq!(push_task_state(&pool, task_id).await.0, "pending");

            // The redelivery carries the document; it must not loop forever.
            sqlx::query(
                "UPDATE sync_tasks SET status = 'completed', completed_at = NOW() WHERE id = $1",
            )
            .bind(task_id)
            .execute(&pool)
            .await
            .unwrap();
            assert!(!svc
                .rearm_superseded_push(task_id, Some(&checksum), Some(&metadata))
                .await
                .unwrap());

            cleanup_assign(&pool, peer_id, repo_id).await;
        }
    }

    /// #4889: a completed push of the protobuf `_labels` index must be
    /// redelivered when a later label move rewrites the row in place. The
    /// format is not versioned, so the checksum rule above cannot see it; the
    /// path-specific `updated_at` check does. Fails on `main`.
    #[tokio::test]
    async fn queue_sync_task_rearms_completed_protobuf_labels_push_4889() {
        let Some(pool) = crate::api::handlers::test_db_helpers::try_pool().await else {
            return;
        };
        let svc = PeerInstanceService::new(pool.clone());
        let (repo_id, peer_id, artifact_id, task_id) =
            completed_push_fixture(&pool, &svc, false).await;
        sqlx::query("UPDATE repositories SET format = 'protobuf' WHERE id = $1")
            .bind(repo_id)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "UPDATE artifacts SET path = 'modules/acme/widgets/_labels', \
             updated_at = NOW() - INTERVAL '2 hours' WHERE id = $1",
        )
        .bind(artifact_id)
        .execute(&pool)
        .await
        .unwrap();

        // The index has not moved since the finished push.
        svc.queue_sync_task(peer_id, artifact_id, 0).await.unwrap();
        assert_eq!(push_task_state(&pool, task_id).await.0, "completed");

        // A label move rewrites the row (and its checksum) in place.
        sqlx::query("UPDATE artifacts SET checksum_sha256 = $2, updated_at = NOW() WHERE id = $1")
            .bind(artifact_id)
            .bind(format!("{:064x}", 2))
            .execute(&pool)
            .await
            .unwrap();
        svc.queue_sync_task(peer_id, artifact_id, 0).await.unwrap();
        assert_eq!(
            push_task_state(&pool, task_id).await,
            ("pending".to_string(), 0, None),
            "the moved label index must be sent again"
        );

        cleanup_assign(&pool, peer_id, repo_id).await;
    }

    #[tokio::test]
    async fn queue_sync_task_keeps_completed_push_on_unversioned_reupload() {
        let Some(pool) = crate::api::handlers::test_db_helpers::try_pool().await else {
            return;
        };
        let svc = PeerInstanceService::new(pool.clone());
        let (repo_id, peer_id, artifact_id, task_id) =
            completed_push_fixture(&pool, &svc, false).await;

        svc.queue_sync_task(peer_id, artifact_id, 0).await.unwrap();

        assert_eq!(
            push_task_state(&pool, task_id).await,
            ("completed".to_string(), 2, None)
        );
        cleanup_assign(&pool, peer_id, repo_id).await;
    }

    #[tokio::test]
    async fn queue_sync_task_leaves_claimed_push_alone() {
        let Some(pool) = crate::api::handlers::test_db_helpers::try_pool().await else {
            return;
        };
        let svc = PeerInstanceService::new(pool.clone());
        let (repo_id, peer_id, artifact_id, task_id) =
            completed_push_fixture(&pool, &svc, true).await;
        let token = Uuid::new_v4();
        sqlx::query(
            "UPDATE sync_tasks SET status = 'in_progress', claim_token = $2, claimed_by = 'worker-a', \
             claim_expires_at = NOW() + INTERVAL '1 minute' WHERE id = $1",
        )
        .bind(task_id)
        .bind(token)
        .execute(&pool)
        .await
        .unwrap();

        assert_eq!(
            svc.queue_sync_task(peer_id, artifact_id, 0).await.unwrap(),
            task_id
        );
        assert_eq!(
            push_task_state(&pool, task_id).await,
            ("in_progress".to_string(), 2, Some(token))
        );
        cleanup_assign(&pool, peer_id, repo_id).await;
    }
}
