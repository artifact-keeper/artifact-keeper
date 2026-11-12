//! A process-wide cache of the current [`PolicySnapshot`].
//!
//! The snapshot is rebuilt lazily when it has been invalidated or is older than
//! its TTL. One build runs at a time, in its own task: callers wait on it and
//! may give up, but a caller that gives up never cancels the build, so a build
//! slower than any caller's patience still completes and serves the next one.
//!
//! Invalidation is a generation counter read before a build starts. A change
//! committed while a build runs keeps that build's result from being stored:
//! the callers already waiting on it get it, and the next caller rebuilds. A snapshot older
//! than the TTL is never returned, even when rebuilding fails: the caller gets
//! [`SnapshotUnavailable`] instead.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use futures::future::{BoxFuture, FutureExt, Shared};
use metrics::counter;
use sqlx::PgPool;

use super::resource_index::read_resource_index;
use super::snapshot::PolicySnapshot;
use crate::services::iam_legacy_projection::{
    begin_snapshot, project_legacy_state, read_database_state, read_sso_config,
};

/// The longest a snapshot may be used after it was built.
pub const SNAPSHOT_TTL: Duration = Duration::from_secs(30);

/// Builds one snapshot. Injected so tests can count, fail or block builds.
pub type BuildFn = Arc<
    dyn Fn() -> Pin<Box<dyn Future<Output = Result<PolicySnapshot, String>> + Send>> + Send + Sync,
>;

/// No snapshot younger than the TTL is available.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotUnavailable {
    pub reason: String,
}

type BuildResult = Result<Arc<PolicySnapshot>, SnapshotUnavailable>;
type InFlight = Shared<BoxFuture<'static, BuildResult>>;

struct Built {
    snapshot: Arc<PolicySnapshot>,
    built_at: Instant,
    generation: u64,
}

pub struct SnapshotProvider {
    build: BuildFn,
    ttl: Duration,
    current: RwLock<Option<Built>>,
    generation: AtomicU64,
    in_flight: Mutex<Option<InFlight>>,
}

/// Clears the in-flight build when its task ends, however it ends.
struct ClearInFlight(Arc<SnapshotProvider>);

impl Drop for ClearInFlight {
    fn drop(&mut self) {
        *self.0.in_flight.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }
}

impl SnapshotProvider {
    pub fn new(build: BuildFn) -> SnapshotProvider {
        Self::with_ttl(build, SNAPSHOT_TTL)
    }

    pub fn with_ttl(build: BuildFn, ttl: Duration) -> SnapshotProvider {
        SnapshotProvider {
            build,
            ttl,
            current: RwLock::new(None),
            generation: AtomicU64::new(0),
            in_flight: Mutex::new(None),
        }
    }

    /// The provider over the legacy authorization state in `pool`.
    pub fn for_database(pool: PgPool) -> SnapshotProvider {
        Self::new(Arc::new(move || {
            let pool = pool.clone();
            Box::pin(async move { build_from_database(&pool).await.map_err(|e| e.to_string()) })
        }))
    }

    /// Mark the held snapshot stale. Cheap and synchronous.
    pub fn invalidate(&self) {
        self.generation.fetch_add(1, Ordering::SeqCst);
    }

    /// The current invalidation generation (for tests and diagnostics).
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::SeqCst)
    }

    /// A fresh snapshot: the held one when it is current and within the TTL,
    /// otherwise the result of the build in flight, started if none is.
    pub async fn current(self: &Arc<Self>) -> BuildResult {
        if let Some(snapshot) = self.fresh() {
            return Ok(snapshot);
        }
        let build = {
            let mut in_flight = self.in_flight.lock().unwrap_or_else(|e| e.into_inner());
            // A build may have finished while this caller took the lock.
            if let Some(snapshot) = self.fresh() {
                return Ok(snapshot);
            }
            in_flight.get_or_insert_with(|| self.start_build()).clone()
        };
        build.await
    }

    fn start_build(self: &Arc<Self>) -> InFlight {
        let this = self.clone();
        let task = tokio::spawn(async move {
            let _clear = ClearInFlight(this.clone());
            this.run_build().await
        });
        async move {
            task.await.unwrap_or_else(|e| {
                Err(SnapshotUnavailable {
                    reason: format!("snapshot build task failed: {e}"),
                })
            })
        }
        .boxed()
        .shared()
    }

    async fn run_build(&self) -> BuildResult {
        let generation = self.generation();
        let started = Instant::now();
        match (self.build)().await {
            Ok(snapshot) => {
                let snapshot = Arc::new(snapshot);
                if self.generation() == generation {
                    *self.current.write().unwrap_or_else(|e| e.into_inner()) = Some(Built {
                        snapshot: snapshot.clone(),
                        built_at: started,
                        generation,
                    });
                    counter!("ak_iam_snapshot_builds_total", "result" => "ok").increment(1);
                } else {
                    // Authorization data changed while the build read it. The
                    // callers already waiting asked about requests answered
                    // before the change and get this snapshot; it is not kept,
                    // so the next caller rebuilds.
                    counter!("ak_iam_snapshot_builds_total", "result" => "superseded").increment(1);
                }
                Ok(snapshot)
            }
            Err(reason) => {
                counter!("ak_iam_snapshot_builds_total", "result" => "error").increment(1);
                tracing::warn!(%reason, "IAM policy snapshot build failed");
                Err(SnapshotUnavailable { reason })
            }
        }
    }

    fn fresh(&self) -> Option<Arc<PolicySnapshot>> {
        let held = self.current.read().unwrap_or_else(|e| e.into_inner());
        held.as_ref()
            .filter(|b| b.generation == self.generation() && b.built_at.elapsed() < self.ttl)
            .map(|b| b.snapshot.clone())
    }
}

/// Build a snapshot from the legacy state and the resource index, read in one
/// repeatable-read, read-only transaction.
pub async fn build_from_database(pool: &PgPool) -> Result<PolicySnapshot, sqlx::Error> {
    let mut tx = begin_snapshot(pool).await?;
    let mut state = read_database_state(&mut tx).await?;
    state.sso = read_sso_config(&mut tx).await?;
    let resources = read_resource_index(&mut tx).await?;
    tx.rollback().await?;
    let projection = project_legacy_state(&state);
    Ok(PolicySnapshot::from_projection(&projection, resources))
}

#[cfg(ak_test_shard = "services-1")]
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    use crate::models::repository::RepositoryVisibility;
    use crate::services::iam_decision::snapshot::RepositoryFacts;
    use uuid::Uuid;

    /// A build that counts calls, tags each snapshot with the call number (as
    /// a repository id), optionally fails, and optionally waits on a gate.
    struct Probe {
        calls: Arc<AtomicUsize>,
        fail: Arc<std::sync::atomic::AtomicBool>,
        gate: Arc<tokio::sync::Semaphore>,
    }

    fn probe() -> (Probe, BuildFn) {
        let calls = Arc::new(AtomicUsize::new(0));
        let fail = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let gate = Arc::new(tokio::sync::Semaphore::new(1_000));
        let p = Probe {
            calls: calls.clone(),
            fail: fail.clone(),
            gate: gate.clone(),
        };
        let build: BuildFn = Arc::new(move || {
            let (calls, fail, gate) = (calls.clone(), fail.clone(), gate.clone());
            Box::pin(async move {
                let n = calls.fetch_add(1, Ordering::SeqCst) + 1;
                gate.acquire().await.unwrap().forget();
                if fail.load(Ordering::SeqCst) {
                    return Err("boom".to_string());
                }
                let mut s = PolicySnapshot::default();
                s.resources_mut().repositories.insert(
                    Uuid::from_u128(n as u128),
                    RepositoryFacts {
                        project: None,
                        visibility: RepositoryVisibility::Private,
                    },
                );
                Ok(s)
            })
        });
        (p, build)
    }

    fn tag(s: &PolicySnapshot) -> u128 {
        s.resources().repositories.keys().next().unwrap().as_u128()
    }

    #[tokio::test]
    async fn concurrent_callers_build_once() {
        let (p, build) = probe();
        let provider = Arc::new(SnapshotProvider::new(build));
        let handles: Vec<_> = (0..16)
            .map(|_| {
                let provider = provider.clone();
                tokio::spawn(async move { provider.current().await.map(|s| tag(&s)) })
            })
            .collect();
        for h in handles {
            assert_eq!(h.await.unwrap(), Ok(1));
        }
        assert_eq!(p.calls.load(Ordering::SeqCst), 1);
        // A held fresh snapshot is reused.
        assert_eq!(tag(&provider.current().await.unwrap()), 1);
        assert_eq!(p.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn invalidation_forces_a_rebuild() {
        let (p, build) = probe();
        let provider = Arc::new(SnapshotProvider::new(build));
        assert_eq!(tag(&provider.current().await.unwrap()), 1);
        provider.invalidate();
        assert_eq!(tag(&provider.current().await.unwrap()), 2);
        assert_eq!(p.calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn invalidation_during_a_build_is_not_lost() {
        let (p, build) = probe();
        // Close the gate so the first build blocks after it started.
        let held = p.gate.clone().acquire_many_owned(1_000).await.unwrap();
        let provider = Arc::new(SnapshotProvider::new(build));
        let first = {
            let provider = provider.clone();
            tokio::spawn(async move { provider.current().await.map(|s| tag(&s)) })
        };
        while p.calls.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
        provider.invalidate();
        drop(held);
        // The build still answers the callers waiting on it...
        assert_eq!(first.await.unwrap(), Ok(1));
        // ...but it predates the invalidation, so it is not kept.
        assert_eq!(tag(&provider.current().await.unwrap()), 2);
    }

    #[tokio::test]
    async fn a_caller_that_gives_up_does_not_cancel_the_build() {
        let (p, build) = probe();
        let held = p.gate.clone().acquire_many_owned(1_000).await.unwrap();
        let provider = Arc::new(SnapshotProvider::new(build));
        let gave_up = tokio::time::timeout(Duration::from_millis(20), provider.current()).await;
        assert!(gave_up.is_err());
        drop(held);
        // The same build completes and serves the next caller.
        assert_eq!(tag(&provider.current().await.unwrap()), 1);
        assert_eq!(p.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_snapshot_past_its_ttl_is_never_returned() {
        let (p, build) = probe();
        let provider = Arc::new(SnapshotProvider::with_ttl(build, Duration::from_millis(30)));
        assert_eq!(tag(&provider.current().await.unwrap()), 1);
        tokio::time::sleep(Duration::from_millis(40)).await;
        p.fail.store(true, Ordering::SeqCst);
        assert!(provider.current().await.is_err());
        p.fail.store(false, Ordering::SeqCst);
        assert_eq!(tag(&provider.current().await.unwrap()), 3);
    }

    #[tokio::test]
    async fn a_failed_build_keeps_a_fresh_snapshot_unreachable_after_invalidation() {
        let (p, build) = probe();
        let provider = Arc::new(SnapshotProvider::new(build));
        assert_eq!(tag(&provider.current().await.unwrap()), 1);
        provider.invalidate();
        p.fail.store(true, Ordering::SeqCst);
        // Invalidated: the old snapshot may describe a revoked grant.
        assert!(provider.current().await.is_err());
    }

    #[tokio::test]
    async fn builds_from_the_database_in_a_read_only_snapshot() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (user, _) = tdh::create_user(&pool).await;
        let (repo, _, _) = tdh::create_repo(&pool, "local", "generic").await;
        let project = Uuid::new_v4();
        sqlx::query("INSERT INTO projects (id, key, name) VALUES ($1, $2, 'p')")
            .bind(project)
            .bind(format!("proj-{project}"))
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("UPDATE repositories SET project_id = $2 WHERE id = $1")
            .bind(repo)
            .bind(project)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO permissions (id, principal_type, principal_id, target_type, target_id, actions) \
             VALUES ($1, 'user', $2, 'repository', $3, ARRAY['read','write'])",
        )
        .bind(Uuid::new_v4())
        .bind(user)
        .bind(repo)
        .execute(&pool)
        .await
        .unwrap();

        let snapshot = build_from_database(&pool).await.expect("build");
        assert_eq!(
            snapshot
                .resources()
                .repositories
                .get(&repo)
                .and_then(|r| r.project),
            Some(project)
        );
        let subject = crate::services::iam_legacy_projection::SubjectRef::User(user);
        assert!(snapshot.bindings().iter().any(|b| b.subject == subject
            && b.scope == crate::services::iam_legacy_projection::ScopeRef::Repository(repo)));

        // The build transaction cannot write.
        let mut tx = begin_snapshot(&pool).await.unwrap();
        let write = sqlx::query("UPDATE repositories SET key = key WHERE id = $1")
            .bind(repo)
            .execute(&mut *tx)
            .await;
        assert!(write.is_err());
        tx.rollback().await.unwrap();
    }

    /// The `permissions_changed` notifications one statement on `writer`
    /// produced. A sentinel notification sent after the statement marks the
    /// end, and notifications from other sessions (parallel tests) are
    /// filtered out by backend pid.
    async fn kinds_published_by(
        listener: &mut sqlx::postgres::PgListener,
        writer: &mut sqlx::pool::PoolConnection<sqlx::Postgres>,
        pid: i32,
        statement: &str,
    ) -> usize {
        use crate::services::cache_invalidation::{
            parse_invalidation_payload, InvalidationEvent, CACHE_INVALIDATION_CHANNEL,
        };
        sqlx::query(sqlx::AssertSqlSafe(statement))
            .execute(&mut **writer)
            .await
            .unwrap_or_else(|e| panic!("{statement}: {e}"));
        sqlx::query("SELECT pg_notify($1, 'sentinel')")
            .bind(CACHE_INVALIDATION_CHANNEL)
            .execute(&mut **writer)
            .await
            .unwrap();
        let mut published = 0;
        loop {
            let n = tokio::time::timeout(Duration::from_secs(10), listener.recv())
                .await
                .expect("sentinel notification")
                .expect("listener");
            if n.process_id() as i32 != pid {
                continue;
            }
            if n.payload() == "sentinel" {
                return published;
            }
            if parse_invalidation_payload(n.payload()) == Ok(InvalidationEvent::PermissionsChanged)
            {
                published += 1;
            }
        }
    }

    /// Every table the snapshot reads carries the notification triggers.
    #[tokio::test]
    async fn every_snapshot_table_has_a_notify_trigger() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let tables: Vec<String> = sqlx::query_scalar(
            "SELECT DISTINCT tgrelid::regclass::text FROM pg_trigger \
             WHERE tgname LIKE 'ak_iam_%' ORDER BY 1",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        let mut expected = vec![
            "api_token_repositories",
            "api_tokens",
            "ci_oidc_identity_mappings",
            "ci_oidc_providers",
            "groups",
            "ldap_configs",
            "oidc_configs",
            "permission_grants",
            "projects",
            "repositories",
            "role_assignments",
            "roles",
            "saml_configs",
            "user_roles",
            "users",
        ];
        expected.sort_unstable();
        assert_eq!(tables, expected);
    }

    /// A real change publishes `permissions_changed`; a write that changes
    /// nothing the snapshot reads, including the SSO login update, does not.
    #[tokio::test]
    async fn only_real_changes_publish_permissions_changed() {
        use crate::api::handlers::test_db_helpers as tdh;
        use crate::services::cache_invalidation::CACHE_INVALIDATION_CHANNEL;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (user, _) = tdh::create_user(&pool).await;
        let (repo, _, _) = tdh::create_repo(&pool, "local", "generic").await;
        let project = Uuid::new_v4();
        let mut listener = sqlx::postgres::PgListener::connect_with(&pool)
            .await
            .unwrap();
        listener.listen(CACHE_INVALIDATION_CHANNEL).await.unwrap();
        let mut writer = pool.acquire().await.unwrap();
        let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *writer)
            .await
            .unwrap();

        let cases = [
            // The SSO login shape: `is_admin` in SET, row filtered out.
            (
                format!(
                    "UPDATE users SET email = email, display_name = display_name, \
                     is_admin = is_admin, last_login_at = NOW(), updated_at = NOW() \
                     WHERE id = '{user}' AND email IS DISTINCT FROM email"
                ),
                0,
            ),
            // The same row written with an unchanged `is_admin`.
            (
                format!(
                    "UPDATE users SET is_admin = is_admin, last_login_at = NOW() \
                     WHERE id = '{user}'"
                ),
                0,
            ),
            ("DELETE FROM roles WHERE false".to_string(), 0),
            (
                format!("UPDATE users SET is_admin = NOT is_admin WHERE id = '{user}'"),
                1,
            ),
            (
                format!("UPDATE users SET is_admin = NOT is_admin WHERE id = '{user}'"),
                1,
            ),
            (
                format!(
                    "INSERT INTO role_assignments (user_id, role_id, repository_id) \
                     SELECT '{user}', r.id, '{repo}' FROM roles r WHERE r.name = 'reader'"
                ),
                1,
            ),
            (
                format!("DELETE FROM role_assignments WHERE user_id = '{user}'"),
                1,
            ),
            (
                format!(
                    "INSERT INTO projects (id, key, name) VALUES ('{project}', 'p-{project}', 'p')"
                ),
                1,
            ),
            (
                format!("UPDATE projects SET name = name WHERE id = '{project}'"),
                0,
            ),
            (
                format!("UPDATE repositories SET project_id = '{project}' WHERE id = '{repo}'"),
                1,
            ),
            (
                format!("UPDATE repositories SET project_id = project_id WHERE id = '{repo}'"),
                0,
            ),
            (
                format!("UPDATE repositories SET description = 'd' WHERE id = '{repo}'"),
                0,
            ),
            (
                format!("UPDATE repositories SET project_id = NULL WHERE id = '{repo}'"),
                1,
            ),
            (format!("DELETE FROM projects WHERE id = '{project}'"), 1),
        ];
        for (statement, expected) in &cases {
            assert_eq!(
                kinds_published_by(&mut listener, &mut writer, pid, statement).await,
                *expected,
                "{statement}"
            );
        }
        drop(writer);
        tdh::cleanup(&pool, repo, user).await;
    }
}
