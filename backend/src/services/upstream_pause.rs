//! One switch that pauses every scheduled job that contacts an upstream on
//! its own (#5288): "this instance is disconnected; do not start outbound
//! work".
//!
//! The switch is the `upstream_jobs_paused` system setting (admin API
//! `PATCH /api/v1/admin/settings/system`, no restart) with the env default
//! `UPSTREAM_JOBS_PAUSED` (read by [`crate::config::Config`]). The env var set
//! to `true` pins the switch on: a disconnected deployment that declares
//! itself so in its manifest cannot be resumed from the UI.
//!
//! Every scheduled upstream job holds an [`UpstreamPauseGate`] and asks it at
//! the top of each tick, before any network work. While the switch is on the
//! tick is skipped (debug log per tick, info log once per state change), so
//! turning it off resumes the job on its next tick from wherever it stopped.
//! Request-time proxy fetches are out of scope: they answer a client.
//!
//! A new scheduled upstream job adds its name to [`PAUSABLE_JOBS`] and calls
//! the gate; the structural test at the bottom of this file fails when a
//! listed job's loop no longer does.

use std::sync::atomic::{AtomicBool, Ordering};

use async_trait::async_trait;
use serde::Serialize;
use sqlx::PgPool;
use utoipa::ToSchema;

/// `system_settings` key of the runtime switch.
pub const UPSTREAM_JOBS_PAUSED_SETTING: &str = "upstream_jobs_paused";

/// Scheduled curation upstream metadata sync of Staging repositories,
/// including the popularity lookups it makes.
pub const CURATION_SYNC_JOB: &str = "curation_sync";
/// Advisory-delta re-evaluation of stored environments (queries OSV).
pub const ENVIRONMENT_REEVAL_JOB: &str = "environment_reeval";
/// npm replication-feed consumer (`NPM_UPSTREAM_FEED_ENABLED`).
pub const NPM_UPSTREAM_FEED_JOB: &str = "npm_upstream_feed";
/// Peer replication transfers (push / mirror sync tasks).
pub const PEER_SYNC_JOB: &str = "peer_sync";
/// Remote MCP registry sync (`mcp_remote::spawn`, #5253).
pub const MCP_REMOTE_SYNC_JOB: &str = "mcp_remote_sync";

/// Every scheduled job that honours the switch.
pub const PAUSABLE_JOBS: &[&str] = &[
    CURATION_SYNC_JOB,
    ENVIRONMENT_REEVAL_JOB,
    NPM_UPSTREAM_FEED_JOB,
    PEER_SYNC_JOB,
    MCP_REMOTE_SYNC_JOB,
];

/// `UPSTREAM_JOBS_PAUSED`, installed once at startup by [`set_env_default`].
/// A process-wide value rather than a read of the environment inside the
/// gate, so tests pass the flag in through [`resolve`] and never race on env.
static ENV_DEFAULT: AtomicBool = AtomicBool::new(false);

/// Install the `UPSTREAM_JOBS_PAUSED` value from the loaded configuration.
pub fn set_env_default(paused: bool) {
    ENV_DEFAULT.store(paused, Ordering::Relaxed);
}

fn env_default() -> bool {
    ENV_DEFAULT.load(Ordering::Relaxed)
}

/// Where the effective value of the switch comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamPauseSource {
    /// `UPSTREAM_JOBS_PAUSED=true` pins the switch on; a stored value has no
    /// effect until the env var is unset.
    Environment,
    /// The `upstream_jobs_paused` system setting.
    Database,
    /// Neither: jobs run.
    Default,
    /// The setting could not be read: jobs are treated as paused until a read
    /// succeeds (fail closed, so a database blip never starts outbound work
    /// an operator turned off).
    Unavailable,
}

/// The effective switch together with its provenance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UpstreamPauseState {
    pub paused: bool,
    pub source: UpstreamPauseSource,
    /// The stored setting, when it is a JSON boolean.
    pub stored: Option<bool>,
}

/// Resolve the switch from the env default and the stored setting. Pure.
///
/// `stored` is `Err(())` when the setting could not be read. A stored value
/// that is not a JSON boolean counts as unset.
pub fn resolve(
    env_default: bool,
    stored: Result<Option<&serde_json::Value>, ()>,
) -> UpstreamPauseState {
    let stored_bool = stored.ok().flatten().and_then(serde_json::Value::as_bool);
    let (paused, source) = match (env_default, stored, stored_bool) {
        (true, _, _) => (true, UpstreamPauseSource::Environment),
        (false, Err(()), _) => (true, UpstreamPauseSource::Unavailable),
        (false, Ok(_), Some(v)) => (v, UpstreamPauseSource::Database),
        (false, Ok(_), None) => (false, UpstreamPauseSource::Default),
    };
    UpstreamPauseState {
        paused,
        source,
        stored: stored_bool,
    }
}

async fn load_stored(db: &PgPool) -> Result<Option<serde_json::Value>, sqlx::Error> {
    sqlx::query_scalar("SELECT value FROM system_settings WHERE key = $1")
        .bind(UPSTREAM_JOBS_PAUSED_SETTING)
        .fetch_optional(db)
        .await
}

/// Read the switch, surfacing a read error (for the admin endpoints, which
/// must not show a guessed value).
pub async fn try_state(db: &PgPool) -> Result<UpstreamPauseState, sqlx::Error> {
    let stored = load_stored(db).await?;
    Ok(resolve(env_default(), Ok(stored.as_ref())))
}

/// Tests only: ignore the stored setting in this process, so a test is not
/// paused by another test that is toggling `upstream_jobs_paused` in the shared
/// test database at the same moment (the env default still applies; nextest
/// runs each test in its own process).
#[cfg(test)]
static IGNORE_STORED_FOR_TESTS: AtomicBool = AtomicBool::new(false);

/// Tests only: see [`IGNORE_STORED_FOR_TESTS`].
#[cfg(test)]
pub fn ignore_stored_setting_for_tests() {
    IGNORE_STORED_FOR_TESTS.store(true, Ordering::Relaxed);
}

/// Read the switch for a scheduled job. Never fails: a read error is
/// [`UpstreamPauseSource::Unavailable`] (paused).
pub async fn state(db: &PgPool) -> UpstreamPauseState {
    #[cfg(test)]
    if IGNORE_STORED_FOR_TESTS.load(Ordering::Relaxed) {
        return resolve(env_default(), Ok(None));
    }
    match load_stored(db).await {
        Ok(stored) => resolve(env_default(), Ok(stored.as_ref())),
        Err(e) => {
            tracing::warn!(error = %e, "could not read the upstream_jobs_paused setting; treating scheduled upstream jobs as paused");
            resolve(env_default(), Err(()))
        }
    }
}

/// Whether scheduled upstream jobs are paused right now. The one helper every
/// scheduled upstream job consults (through [`UpstreamPauseGate`]).
pub async fn upstream_jobs_paused(db: &PgPool) -> bool {
    state(db).await.paused
}

/// Store the runtime switch. Takes effect on each job's next tick.
pub async fn store(db: &PgPool, paused: bool, updated_by: uuid::Uuid) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        INSERT INTO system_settings (key, value, description, updated_by)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (key) DO UPDATE
            SET value = $2, updated_by = $4, updated_at = NOW()
        "#,
    )
    .bind(UPSTREAM_JOBS_PAUSED_SETTING)
    .bind(serde_json::Value::Bool(paused))
    .bind(
        "Pause every scheduled job that contacts an upstream; UPSTREAM_JOBS_PAUSED=true pins it on",
    )
    .bind(updated_by)
    .execute(db)
    .await?;
    Ok(())
}

/// The startup line naming the paused jobs, `None` while they run. Pure.
pub fn startup_message(state: &UpstreamPauseState) -> Option<String> {
    state.paused.then(|| {
        format!(
            "Scheduled upstream jobs are PAUSED (source: {:?}); skipped until the switch is off: {}",
            state.source,
            PAUSABLE_JOBS.join(", ")
        )
    })
}

/// A change of the switch as one job observes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PauseTransition {
    Paused,
    Resumed,
}

/// The transition from the previous observation to `now`, if any. A job's
/// first observation reports `Paused` when paused and nothing when running.
pub fn transition(last: Option<bool>, now: bool) -> Option<PauseTransition> {
    match (last, now) {
        (Some(true), true) | (None | Some(false), false) => None,
        (None | Some(false), true) => Some(PauseTransition::Paused),
        (Some(true), false) => Some(PauseTransition::Resumed),
    }
}

/// Source of the switch for a job, so a job's loop can be exercised without a
/// database.
#[async_trait]
pub trait PauseProbe: Send + Sync {
    async fn paused(&self) -> bool;
}

/// The production probe: the system setting plus the env default.
pub struct DbPauseProbe(pub PgPool);

#[async_trait]
impl PauseProbe for DbPauseProbe {
    async fn paused(&self) -> bool {
        upstream_jobs_paused(&self.0).await
    }
}

/// Per-job view of the switch: logs each state change once and every skipped
/// tick at debug.
#[derive(Debug)]
pub struct UpstreamPauseGate {
    job: &'static str,
    last: Option<bool>,
}

impl UpstreamPauseGate {
    pub fn new(job: &'static str) -> Self {
        Self { job, last: None }
    }

    /// Whether this tick must be skipped. Call before any network work.
    pub async fn skip_tick(&mut self, db: &PgPool) -> bool {
        let paused = upstream_jobs_paused(db).await;
        self.observe(paused)
    }

    /// [`Self::skip_tick`] against any [`PauseProbe`].
    pub async fn skip_tick_with(&mut self, probe: &dyn PauseProbe) -> bool {
        let paused = probe.paused().await;
        self.observe(paused)
    }

    /// Record one observation of the switch and return it.
    pub fn observe(&mut self, paused: bool) -> bool {
        match transition(self.last, paused) {
            Some(PauseTransition::Paused) => tracing::info!(
                job = self.job,
                "scheduled upstream job paused (upstream_jobs_paused is on); no outbound work until it is turned off"
            ),
            Some(PauseTransition::Resumed) => tracing::info!(
                job = self.job,
                "scheduled upstream job resumed (upstream_jobs_paused is off)"
            ),
            None => {}
        }
        if paused {
            tracing::debug!(job = self.job, "upstream jobs paused; skipping tick");
        }
        self.last = Some(paused);
        paused
    }
}

#[cfg(ak_test_shard = "services-2")]
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn resolve_truth_table() {
        let t = json!(true);
        let f = json!(false);
        let junk = json!("yes");
        type Stored<'a> = Result<Option<&'a serde_json::Value>, ()>;
        let cases: &[(bool, Stored<'_>, bool, UpstreamPauseSource)] = &[
            (false, Ok(None), false, UpstreamPauseSource::Default),
            (false, Ok(Some(&t)), true, UpstreamPauseSource::Database),
            (false, Ok(Some(&f)), false, UpstreamPauseSource::Database),
            (false, Ok(Some(&junk)), false, UpstreamPauseSource::Default),
            (false, Err(()), true, UpstreamPauseSource::Unavailable),
            // The env var pins the switch on whatever is stored.
            (true, Ok(None), true, UpstreamPauseSource::Environment),
            (true, Ok(Some(&f)), true, UpstreamPauseSource::Environment),
            (true, Err(()), true, UpstreamPauseSource::Environment),
        ];
        for (env, stored, paused, source) in cases {
            let s = resolve(*env, *stored);
            assert_eq!((s.paused, s.source), (*paused, *source), "{env} {stored:?}");
        }
        assert_eq!(resolve(true, Ok(Some(&f))).stored, Some(false));
        assert_eq!(resolve(false, Ok(Some(&junk))).stored, None);
    }

    #[test]
    fn source_serializes_snake_case() {
        assert_eq!(
            serde_json::to_value(UpstreamPauseSource::Unavailable).unwrap(),
            json!("unavailable")
        );
    }

    #[test]
    fn transition_reports_each_change_once() {
        assert_eq!(transition(None, false), None);
        assert_eq!(transition(None, true), Some(PauseTransition::Paused));
        assert_eq!(transition(Some(false), true), Some(PauseTransition::Paused));
        assert_eq!(transition(Some(true), true), None);
        assert_eq!(
            transition(Some(true), false),
            Some(PauseTransition::Resumed)
        );
        assert_eq!(transition(Some(false), false), None);
    }

    #[test]
    fn gate_skips_exactly_the_paused_ticks() {
        let mut gate = UpstreamPauseGate::new(CURATION_SYNC_JOB);
        let observed: Vec<bool> = [false, true, true, false]
            .into_iter()
            .map(|p| gate.observe(p))
            .collect();
        assert_eq!(observed, vec![false, true, true, false]);
        assert_eq!(gate.last, Some(false));
    }

    #[test]
    fn startup_message_names_every_job_only_when_paused() {
        let running = resolve(false, Ok(None));
        assert_eq!(startup_message(&running), None);
        let msg = startup_message(&resolve(true, Ok(None))).expect("paused");
        for job in PAUSABLE_JOBS {
            assert!(msg.contains(job), "{msg}");
        }
        assert!(msg.contains("Environment"), "{msg}");
    }

    /// Structural guard (#5288): each job in [`PAUSABLE_JOBS`] builds its
    /// gate in the loop that does its upstream work, and the gate is asked
    /// before that work. A new scheduled upstream job adds a row here and to
    /// [`PAUSABLE_JOBS`]. Needles are assembled at runtime so this test's own
    /// source cannot satisfy them.
    #[test]
    fn every_pausable_job_consults_the_gate() {
        // (job, source, gate constant, how the loop asks, its upstream work)
        let sources: &[(&str, &str, &str, &str, &str)] = &[
            (
                CURATION_SYNC_JOB,
                include_str!("scheduler_service.rs"),
                "CURATION_SYNC_JOB",
                ".skip_tick(",
                "run_curation_sync_cycle(&db, None",
            ),
            (
                ENVIRONMENT_REEVAL_JOB,
                include_str!("scheduler_service.rs"),
                "ENVIRONMENT_REEVAL_JOB",
                ".skip_tick(",
                "process_pending_deltas(100)",
            ),
            (
                NPM_UPSTREAM_FEED_JOB,
                include_str!("upstream_feed.rs"),
                "NPM_UPSTREAM_FEED_JOB",
                "self.paused(",
                "self.adapter.poll(",
            ),
            (
                PEER_SYNC_JOB,
                include_str!("sync_worker.rs"),
                "PEER_SYNC_JOB",
                ".skip_tick(",
                "process_pending_tasks(&db",
            ),
            (
                MCP_REMOTE_SYNC_JOB,
                include_str!("mcp_remote.rs"),
                "MCP_REMOTE_SYNC_JOB",
                ".skip_tick(",
                "run_due(state, interval_secs",
            ),
        ];
        let gate_ctor = format!("{}::new(", "UpstreamPauseGate");
        for job in PAUSABLE_JOBS {
            let rows: Vec<_> = sources.iter().filter(|r| r.0 == *job).collect();
            assert_eq!(rows.len(), 1, "{job} must have exactly one structural row");
        }
        for (job, src, const_name, ask, work) in sources {
            let ctor = format!("{gate_ctor}upstream_pause::{const_name})");
            let ctor_at = src
                .find(&ctor)
                .unwrap_or_else(|| panic!("{job}: its loop must build `{ctor}`"));
            let work_at = src[ctor_at..]
                .find(work)
                .unwrap_or_else(|| panic!("{job}: upstream work `{work}` must follow its gate"));
            assert!(
                src[ctor_at..ctor_at + work_at].contains(ask),
                "{job}: the gate must be asked (`{ask}`) before `{work}`"
            );
        }
    }
}
