//! How old each scanner's vulnerability database is, and whether it is stale
//! (#5177).
//!
//! A scan graded against an old database looks the same as one graded
//! against current data, so "no findings" can overstate how safe an artifact
//! is. Every scan row already records the database it ran against
//! (`vuln_db_version` / `vuln_db_published_at`, #3014); this module answers
//! the instance-level question instead: per engine, which database is
//! installed, when it was built, how old it is now, and whether that is past
//! the operator's limit.
//!
//! # Sources, cheapest first
//!
//! * **grype**: the scanner's own `grype db status` probe, which
//!   [`crate::services::grype_scanner`] already caches for five minutes.
//! * **trivy**: the scanner adapter's `GET /api/v1/vulndb`, which reads the
//!   installed DB's `metadata.json`: no subprocess, no scan. It needs the
//!   adapter's `SCANNER_ADAPTER_TOKEN`, sent as [`VULN_DB_PROBE_TOKEN_ENV`]
//!   (or the scan token when that is unset); without it, or in trivy client
//!   mode, the adapter answers 403/404 and the next source is used.
//! * **scan history**: the newest database a completed scan recorded in the
//!   last 48 hours, plus the rescan worker's last-known build per scan type
//!   (`scan_vuln_db_builds`, #5947). Covers a trivy CLI install and an
//!   adapter that cannot be probed.
//!
//! Age is always measured against now, not against the last scan, so an
//! air-gapped install whose database never updates goes stale on schedule
//! even when nothing new is scanned.
//!
//! # Cost
//!
//! One computed report is shared by the API and the metrics for
//! [`STATUS_TTL`]; concurrent callers wait on the one refresh in flight
//! rather than each probing. A background task refreshes it every
//! [`REFRESH_INTERVAL`] so the gauges move without anyone calling the API.
//!
//! # Verdicts: report only
//!
//! A stale database never changes a scan verdict, a quarantine decision or a
//! repository grade. It is reported (API field, gauges, a throttled warning
//! log) and nothing else. Failing closed on age would block every pull on an
//! air-gapped install the moment its imported DB passed the limit, which is
//! an outage, not safety; failing open is what happens today. Operators who
//! want enforcement can alert on `ak_scanner_vuln_db_stale`.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use utoipa::ToSchema;

/// Env var: the age, in hours, past which a vulnerability database is
/// reported stale. Unset, empty, `0` or unparsable: the staleness check is
/// off (ages are still reported), which is the behaviour before #5177.
pub const VULN_DB_MAX_AGE_HOURS_ENV: &str = "SCAN_VULN_DB_MAX_AGE_HOURS";

/// Env var naming the bearer token sent to the adapter's DB route; also read
/// as `<NAME>_FILE`. Must match the adapter's `SCANNER_ADAPTER_TOKEN`. When
/// unset, the scan token (`TRIVY_ADAPTER_TOKEN`) is tried.
pub const VULN_DB_PROBE_TOKEN_ENV: &str = "TRIVY_ADAPTER_VULNDB_TOKEN";

/// How long one computed report is reused.
pub const STATUS_TTL: Duration = Duration::from_secs(60);

/// How often the background task recomputes the report (and the gauges).
pub const REFRESH_INTERVAL: Duration = Duration::from_secs(300);

/// Timeout of the adapter probe. The adapter reads one small file.
const ADAPTER_PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// Scan history window, the same one the rescan worker reads.
const HISTORY_WINDOW_HOURS: i32 = 48;

/// Interval between repeated stale warnings for one engine.
const WARN_EVERY: Duration = Duration::from_secs(3600);

/// The age gauge, per engine.
pub const AGE_METRIC: &str = "ak_scanner_vuln_db_age_seconds";
/// 1 while an engine's database is past the limit, else 0.
pub const STALE_METRIC: &str = "ak_scanner_vuln_db_stale";
/// The configured limit in seconds, 0 when the check is off.
pub const MAX_AGE_METRIC: &str = "ak_scanner_vuln_db_max_age_seconds";
/// One-hot state per engine: 1 for the current `state` label
/// (`ok`, `stale`, `unknown`), 0 for the others.
pub const STATE_METRIC: &str = "ak_scanner_vuln_db_state";
/// Stale warnings logged, per engine.
pub const STALE_WARNINGS_METRIC: &str = "ak_scanner_vuln_db_stale_warnings_total";

/// Where an engine's database facts came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum VulnDbSource {
    /// The local scanner's own probe (`grype db status`).
    Scanner,
    /// The scanner adapter's `GET /api/v1/vulndb`.
    Adapter,
    /// The newest database recent completed scans recorded.
    ScanHistory,
}

/// One engine's database state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum VulnDbState {
    /// Within the limit, or the check is off.
    Ok,
    /// Older than the limit.
    Stale,
    /// No source reported a build time.
    Unknown,
}

/// One engine's vulnerability database.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct VulnDbEngineStatus {
    /// `trivy` or `grype`.
    pub engine: String,
    /// The scan types this engine grades (`image`, `filesystem`, `incus` for
    /// trivy; `grype` for grype).
    pub scan_types: Vec<String>,
    /// Database identity, e.g. `trivy-db-v2`, `grype-db-v6.0.2`, when known.
    pub version: Option<String>,
    /// When the database was built upstream.
    pub published_at: Option<DateTime<Utc>>,
    /// `checked_at - published_at`, in seconds.
    pub age_seconds: Option<i64>,
    /// When the engine's own updater considers the database due (trivy).
    pub next_update: Option<DateTime<Utc>>,
    /// The adapter runs with `SCANNER_OFFLINE` (trivy, adapter source only).
    pub offline: Option<bool>,
    /// Where these facts came from; `None` when nothing reported.
    pub source: Option<VulnDbSource>,
    pub state: VulnDbState,
}

/// `GET /api/v1/admin/security/vuln-db`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct VulnDbStatusReport {
    /// When this report was computed. Reused for up to 60 seconds.
    pub checked_at: DateTime<Utc>,
    /// `SCAN_VULN_DB_MAX_AGE_HOURS` in seconds; `None` when the check is off.
    pub max_age_seconds: Option<i64>,
    /// True when any engine is `stale`.
    pub any_stale: bool,
    /// Always `false`: a stale database is reported, it never changes a
    /// scan verdict, quarantine decision or grade.
    pub affects_verdicts: bool,
    pub engines: Vec<VulnDbEngineStatus>,
}

/// The staleness limit from `raw` (the env value). `None` disables it:
/// deployments that set no limit keep their behaviour (no stale state, no
/// warning).
pub fn parse_max_age(raw: Option<&str>) -> Option<Duration> {
    let v = raw.map(str::trim).filter(|s| !s.is_empty())?;
    match v.parse::<u64>() {
        Ok(hours) => (hours > 0).then(|| Duration::from_secs(hours.saturating_mul(3600))),
        Err(_) => {
            tracing::warn!(
                "{VULN_DB_MAX_AGE_HOURS_ENV}={v:?} is not a whole number of hours; the staleness check is off"
            );
            None
        }
    }
}

/// The configured limit, read once.
pub fn max_age() -> Option<Duration> {
    static MAX: OnceLock<Option<Duration>> = OnceLock::new();
    *MAX.get_or_init(|| parse_max_age(std::env::var(VULN_DB_MAX_AGE_HOURS_ENV).ok().as_deref()))
}

/// The engine that grades `scan_type`, for the scan types that have a local
/// vulnerability database. Live-feed and database-less scanners are `None`.
pub fn engine_for(scan_type: &str) -> Option<&'static str> {
    match scan_type {
        "grype" => Some("grype"),
        "image" | "filesystem" | "incus" => Some("trivy"),
        _ => None,
    }
}

/// One build observation from any source.
#[derive(Debug, Clone, PartialEq)]
pub struct Observation {
    pub scan_type: String,
    pub version: Option<String>,
    pub published_at: DateTime<Utc>,
    pub source: VulnDbSource,
    pub next_update: Option<DateTime<Utc>>,
    pub offline: Option<bool>,
}

/// Fold observations into one status per engine.
///
/// A live probe (scanner or adapter) beats scan history for its engine,
/// whatever the dates: it describes the database installed now, while
/// history can name a newer build another instance used. Within one class
/// the newest build wins. `engines` lists the engines that must appear even
/// with no observation (they are configured), as `unknown`.
pub fn summarize(
    observations: &[Observation],
    engines: &[&str],
    now: DateTime<Utc>,
    max_age: Option<Duration>,
) -> VulnDbStatusReport {
    let mut best: BTreeMap<&'static str, Observation> = BTreeMap::new();
    let mut scan_types: BTreeMap<&'static str, Vec<String>> = BTreeMap::new();
    for obs in observations {
        let Some(engine) = engine_for(&obs.scan_type) else {
            continue;
        };
        let types = scan_types.entry(engine).or_default();
        if !types.contains(&obs.scan_type) {
            types.push(obs.scan_type.clone());
        }
        let rank = |o: &Observation| (o.source != VulnDbSource::ScanHistory, o.published_at);
        let prev = best.get(engine);
        if prev.is_none_or(|cur| rank(obs) > rank(cur)) {
            let mut chosen = obs.clone();
            // The schema identity outlives one build: keep the one another
            // source knew when the winner carries none (the grype probe).
            if chosen.version.is_none() {
                chosen.version = prev.and_then(|c| c.version.clone());
            }
            best.insert(engine, chosen);
        } else if let Some(cur) = best.get_mut(engine) {
            if cur.version.is_none() {
                cur.version = obs.version.clone();
            }
        }
    }
    let max_secs = max_age.map(|d| d.as_secs() as i64);
    let mut names: Vec<&str> = best.keys().copied().collect();
    for e in engines {
        if !names.contains(e) {
            names.push(e);
        }
    }
    names.sort_unstable();
    let engines: Vec<VulnDbEngineStatus> = names
        .into_iter()
        .map(|engine| {
            let mut types = scan_types.get(engine).cloned().unwrap_or_default();
            types.sort();
            match best.get(engine) {
                Some(o) => {
                    let age = (now - o.published_at).num_seconds().max(0);
                    let stale = max_secs.is_some_and(|m| age > m);
                    VulnDbEngineStatus {
                        engine: engine.to_string(),
                        scan_types: types,
                        version: o.version.clone(),
                        published_at: Some(o.published_at),
                        age_seconds: Some(age),
                        next_update: o.next_update,
                        offline: o.offline,
                        source: Some(o.source),
                        state: if stale {
                            VulnDbState::Stale
                        } else {
                            VulnDbState::Ok
                        },
                    }
                }
                None => VulnDbEngineStatus {
                    engine: engine.to_string(),
                    scan_types: types,
                    version: None,
                    published_at: None,
                    age_seconds: None,
                    next_update: None,
                    offline: None,
                    source: None,
                    state: VulnDbState::Unknown,
                },
            }
        })
        .collect();
    VulnDbStatusReport {
        checked_at: now,
        max_age_seconds: max_secs,
        any_stale: engines.iter().any(|e| e.state == VulnDbState::Stale),
        affects_verdicts: false,
        engines,
    }
}

/// The adapter's `GET /api/v1/vulndb` body (docker/scanner-adapter
/// `VulnDBStatus`); only the fields read here.
#[derive(Debug, Deserialize)]
struct AdapterDbStatus {
    #[serde(default)]
    version: Option<u64>,
    #[serde(default)]
    updated_at: Option<DateTime<Utc>>,
    #[serde(default)]
    next_update: Option<DateTime<Utc>>,
    #[serde(default)]
    offline: Option<bool>,
}

/// Parse an adapter DB-status body into an observation of the trivy scan
/// types. `None` for a body with no schema version or build time.
fn adapter_observation(body: &[u8]) -> Option<Observation> {
    let st: AdapterDbStatus = serde_json::from_slice(body).ok()?;
    let version = st.version.filter(|v| *v > 0)?;
    Some(Observation {
        // Stands for all three trivy scan types; `summarize` maps it to the
        // engine, and history fills in the others it saw.
        scan_type: "image".to_string(),
        version: Some(format!("trivy-db-v{version}")),
        published_at: st.updated_at?,
        source: VulnDbSource::Adapter,
        next_update: st.next_update,
        offline: st.offline,
    })
}

/// The token for the adapter's DB route.
fn adapter_probe_token() -> Option<String> {
    let read = |name: &str| {
        crate::config::secret_or_env(name)
            .ok()
            .flatten()
            .map(|t| t.trim().to_string())
            .filter(|t| !t.is_empty())
    };
    read(VULN_DB_PROBE_TOKEN_ENV).or_else(|| read("TRIVY_ADAPTER_TOKEN"))
}

/// Probe the adapter at `base`. Any failure is `None` and logged at debug:
/// the history source then covers trivy.
async fn probe_adapter(base: &str) -> Option<Observation> {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    let client = CLIENT.get_or_init(|| {
        crate::services::http_client::internal_service_client_builder()
            .timeout(ADAPTER_PROBE_TIMEOUT)
            .build()
            .unwrap_or_default()
    });
    let url = format!("{}/api/v1/vulndb", base.trim_end_matches('/'));
    let mut req = client.get(&url);
    if let Some(token) = adapter_probe_token() {
        req = req.bearer_auth(token);
    }
    match req.send().await {
        Ok(resp) if resp.status().is_success() => {
            // The status document is a few hundred bytes.
            let body = crate::services::http_client::read_body_capped(resp, 64 * 1024)
                .await
                .ok()?;
            let obs = adapter_observation(&body);
            if obs.is_none() {
                tracing::debug!(url = %url, "scanner adapter DB status carried no build time");
            }
            obs
        }
        Ok(resp) => {
            tracing::debug!(url = %url, status = %resp.status(), "scanner adapter DB status unavailable");
            None
        }
        Err(e) => {
            tracing::debug!(url = %url, error = %e, "scanner adapter DB status probe failed");
            None
        }
    }
}

/// `(scan_type, vuln_db_version, vuln_db_published_at)`.
type HistoryRow = (String, Option<String>, DateTime<Utc>);

/// Newest database per scan type from recent completed scans and the rescan
/// worker's builds table. Bounded: the 48 h window, one row per scan type.
async fn history_observations(db: &PgPool) -> Vec<Observation> {
    let rows: Result<Vec<HistoryRow>, _> = sqlx::query_as(
        r#"
        SELECT scan_type, vuln_db_version, vuln_db_published_at FROM (
            SELECT DISTINCT ON (scan_type) scan_type, vuln_db_version, vuln_db_published_at
            FROM scan_results
            WHERE created_at > NOW() - make_interval(hours => $1::int)
              AND status = 'completed'
              AND vuln_db_published_at IS NOT NULL
              AND (vuln_db_version IS NULL OR vuln_db_version NOT LIKE 'live:%')
            ORDER BY scan_type, vuln_db_published_at DESC
        ) recent
        UNION ALL
        SELECT scan_type, NULL, built_at FROM scan_vuln_db_builds
        "#,
    )
    .bind(HISTORY_WINDOW_HOURS)
    .fetch_all(db)
    .await;
    match rows {
        Ok(rows) => rows
            .into_iter()
            .map(|(scan_type, version, published_at)| Observation {
                scan_type,
                version,
                published_at,
                source: VulnDbSource::ScanHistory,
                next_update: None,
                offline: None,
            })
            .collect(),
        Err(e) => {
            tracing::warn!(error = %e, "could not read recent vulnerability-database builds");
            Vec::new()
        }
    }
}

/// Compute a fresh report for `state`.
async fn compute(state: &crate::api::AppState) -> VulnDbStatusReport {
    let mut observations = history_observations(&state.db).await;
    let mut engines: Vec<&str> = Vec::new();
    if let Some(scanner) = state.scanner_service.as_ref() {
        for (scan_type, at) in scanner.current_vuln_db_builds().await {
            if scan_type == "grype" {
                engines.push("grype");
            }
            observations.push(Observation {
                scan_type,
                version: None,
                published_at: at,
                source: VulnDbSource::Scanner,
                next_update: None,
                offline: None,
            });
        }
    }
    let adapters =
        crate::services::health_monitor_service::scanner_adapter_probe_urls(&state.config);
    if !adapters.is_empty() || state.config.trivy_url.is_some() {
        engines.push("trivy");
    }
    for (_, url) in adapters {
        if let Some(obs) = probe_adapter(url).await {
            observations.push(obs);
            break;
        }
    }
    summarize(&observations, &engines, Utc::now(), max_age())
}

struct Cache {
    report: Option<(Instant, Arc<VulnDbStatusReport>)>,
    last_warned: BTreeMap<String, Instant>,
}

fn cache() -> &'static Mutex<Cache> {
    static CACHE: OnceLock<Mutex<Cache>> = OnceLock::new();
    CACHE.get_or_init(|| {
        Mutex::new(Cache {
            report: None,
            last_warned: BTreeMap::new(),
        })
    })
}

/// Serialises refreshes so a burst of callers costs one probe.
fn refresh_lock() -> &'static tokio::sync::Mutex<()> {
    static LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

fn cached(max_age: Duration) -> Option<Arc<VulnDbStatusReport>> {
    let guard = cache().lock().unwrap_or_else(|p| p.into_inner());
    guard
        .report
        .as_ref()
        .filter(|(at, _)| at.elapsed() < max_age)
        .map(|(_, r)| r.clone())
}

/// The current report, reused for [`STATUS_TTL`].
pub async fn status(state: &crate::api::AppState) -> Arc<VulnDbStatusReport> {
    if let Some(r) = cached(STATUS_TTL) {
        return r;
    }
    let _guard = refresh_lock().lock().await;
    // Another caller may have refreshed while this one waited.
    if let Some(r) = cached(STATUS_TTL) {
        return r;
    }
    let report = Arc::new(compute(state).await);
    publish(&report);
    cache().lock().unwrap_or_else(|p| p.into_inner()).report =
        Some((Instant::now(), report.clone()));
    report
}

/// Set the gauges from `report` and log (throttled) any stale engine.
pub fn publish(report: &VulnDbStatusReport) {
    metrics::gauge!(MAX_AGE_METRIC).set(report.max_age_seconds.unwrap_or(0) as f64);
    for e in &report.engines {
        let engine = e.engine.clone();
        // An engine no source answered for has no age: the gauge is set to
        // NaN rather than left at its last value, so an age alert cannot
        // keep reading a frozen number; `ak_scanner_vuln_db_state` says why.
        metrics::gauge!(AGE_METRIC, "engine" => engine.clone())
            .set(e.age_seconds.map_or(f64::NAN, |a| a as f64));
        let stale = e.state == VulnDbState::Stale;
        metrics::gauge!(STALE_METRIC, "engine" => engine.clone()).set(if stale {
            1.0
        } else {
            0.0
        });
        for (label, st) in [
            ("ok", VulnDbState::Ok),
            ("stale", VulnDbState::Stale),
            ("unknown", VulnDbState::Unknown),
        ] {
            metrics::gauge!(STATE_METRIC, "engine" => engine.clone(), "state" => label)
                .set(if e.state == st { 1.0 } else { 0.0 });
        }
        if stale && should_warn(&engine) {
            metrics::counter!(STALE_WARNINGS_METRIC, "engine" => engine.clone()).increment(1);
            tracing::warn!(
                engine = %engine,
                version = e.version.as_deref().unwrap_or("unknown"),
                published_at = ?e.published_at,
                age_hours = e.age_seconds.unwrap_or(0) / 3600,
                max_age_hours = report.max_age_seconds.unwrap_or(0) / 3600,
                offline = ?e.offline,
                "vulnerability database is older than {VULN_DB_MAX_AGE_HOURS_ENV}; scans still run \
                 and verdicts are unchanged, but findings may be missing newer advisories"
            );
        }
    }
    let mut guard = cache().lock().unwrap_or_else(|p| p.into_inner());
    for e in &report.engines {
        if e.state != VulnDbState::Stale {
            // A recovered engine warns again at once if it goes stale later.
            guard.last_warned.remove(&e.engine);
        }
    }
}

fn should_warn(engine: &str) -> bool {
    let mut guard = cache().lock().unwrap_or_else(|p| p.into_inner());
    match guard.last_warned.get(engine) {
        Some(at) if at.elapsed() < WARN_EVERY => false,
        _ => {
            guard.last_warned.insert(engine.to_string(), Instant::now());
            true
        }
    }
}

/// Describe the metrics once at startup.
pub fn describe_metrics() {
    metrics::describe_gauge!(
        AGE_METRIC,
        metrics::Unit::Seconds,
        "Age of each scanner engine's vulnerability database (now minus its build time)"
    );
    metrics::describe_gauge!(
        STALE_METRIC,
        "1 while an engine's vulnerability database is older than SCAN_VULN_DB_MAX_AGE_HOURS"
    );
    metrics::describe_gauge!(
        MAX_AGE_METRIC,
        metrics::Unit::Seconds,
        "SCAN_VULN_DB_MAX_AGE_HOURS in seconds, 0 when the staleness check is off"
    );
    metrics::describe_gauge!(
        STATE_METRIC,
        "1 for each engine's current vulnerability-database state (ok, stale, unknown), 0 for the others"
    );
    metrics::describe_counter!(
        STALE_WARNINGS_METRIC,
        "Warnings logged because an engine's vulnerability database was stale"
    );
}

/// Refresh the report every [`REFRESH_INTERVAL`] until `shutdown`, so the
/// gauges and the warning do not depend on anyone calling the API. Does
/// nothing on an instance with no scanner.
pub fn spawn_refresher(
    state: crate::api::SharedState,
    shutdown: tokio_util::sync::CancellationToken,
) {
    if state.scanner_service.is_none() {
        return;
    }
    describe_metrics();
    tokio::spawn(async move {
        // Let startup finish before the first probe.
        tokio::select! {
            _ = shutdown.cancelled() => return,
            _ = tokio::time::sleep(Duration::from_secs(15)) => {}
        }
        loop {
            cache().lock().unwrap_or_else(|p| p.into_inner()).report = None;
            status(&state).await;
            tokio::select! {
                _ = shutdown.cancelled() => return,
                _ = tokio::time::sleep(REFRESH_INTERVAL) => {}
            }
        }
    });
}

#[cfg(ak_test_shard = "services-2")]
#[cfg(test)]
mod tests {
    use super::*;

    fn at(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    fn obs(scan_type: &str, published: &str, source: VulnDbSource) -> Observation {
        Observation {
            scan_type: scan_type.to_string(),
            version: None,
            published_at: at(published),
            source,
            next_update: None,
            offline: None,
        }
    }

    #[test]
    fn max_age_is_off_unless_set() {
        for off in [
            None,
            Some(""),
            Some(" "),
            Some("soon"),
            Some("0"),
            Some("-5"),
        ] {
            assert_eq!(parse_max_age(off), None, "{off:?}");
        }
        assert_eq!(
            parse_max_age(Some(" 24 ")),
            Some(Duration::from_secs(86_400))
        );
        assert_eq!(
            parse_max_age(Some("168")),
            Some(Duration::from_secs(168 * 3600))
        );
    }

    #[test]
    fn engines_cover_the_trivy_and_grype_scan_types_only() {
        assert_eq!(engine_for("grype"), Some("grype"));
        for t in ["image", "filesystem", "incus"] {
            assert_eq!(engine_for(t), Some("trivy"));
        }
        for t in ["dependency", "openscap", "license", "model_file"] {
            assert_eq!(engine_for(t), None);
        }
    }

    #[test]
    fn an_old_database_is_stale_and_its_age_is_measured_against_now() {
        let now = at("2026-11-23T12:00:00Z");
        let report = summarize(
            &[obs("grype", "2026-11-01T12:00:00Z", VulnDbSource::Scanner)],
            &["grype"],
            now,
            parse_max_age(Some("168")),
        );
        let g = &report.engines[0];
        assert_eq!(g.engine, "grype");
        assert_eq!(g.age_seconds, Some(22 * 86_400));
        assert_eq!(g.state, VulnDbState::Stale);
        assert!(report.any_stale);
        assert!(!report.affects_verdicts);
        assert_eq!(report.max_age_seconds, Some(168 * 3600));
    }

    #[test]
    fn a_fresh_database_is_ok_and_the_check_can_be_off() {
        let now = at("2026-11-23T12:00:00Z");
        let o = [obs(
            "filesystem",
            "2026-11-23T06:00:00Z",
            VulnDbSource::ScanHistory,
        )];
        let report = summarize(&o, &[], now, parse_max_age(Some("168")));
        assert_eq!(report.engines[0].state, VulnDbState::Ok);
        assert_eq!(report.engines[0].age_seconds, Some(6 * 3600));
        // Off: even a year-old DB is only reported.
        let old = [obs(
            "filesystem",
            "2025-11-23T06:00:00Z",
            VulnDbSource::ScanHistory,
        )];
        let off = summarize(&old, &[], now, None);
        assert_eq!(off.engines[0].state, VulnDbState::Ok);
        assert_eq!(off.max_age_seconds, None);
        assert!(!off.any_stale);
    }

    #[test]
    fn a_live_probe_beats_newer_history_and_trivy_types_fold_into_one_engine() {
        let now = at("2026-11-23T12:00:00Z");
        let mut adapter = obs("image", "2026-11-10T00:00:00Z", VulnDbSource::Adapter);
        adapter.version = Some("trivy-db-v2".to_string());
        adapter.offline = Some(true);
        let report = summarize(
            &[
                obs(
                    "filesystem",
                    "2026-11-22T00:00:00Z",
                    VulnDbSource::ScanHistory,
                ),
                adapter,
                obs("incus", "2026-11-21T00:00:00Z", VulnDbSource::ScanHistory),
            ],
            &["trivy"],
            now,
            parse_max_age(Some("168")),
        );
        assert_eq!(report.engines.len(), 1);
        let t = &report.engines[0];
        assert_eq!(t.source, Some(VulnDbSource::Adapter));
        assert_eq!(t.published_at, Some(at("2026-11-10T00:00:00Z")));
        assert_eq!(t.offline, Some(true));
        assert_eq!(t.state, VulnDbState::Stale);
        assert_eq!(t.scan_types, vec!["filesystem", "image", "incus"]);
    }

    #[test]
    fn the_newest_history_build_wins_and_keeps_a_known_version() {
        let now = at("2026-11-23T12:00:00Z");
        let mut recent = obs("grype", "2026-11-20T00:00:00Z", VulnDbSource::ScanHistory);
        recent.version = Some("grype-db-v6.0.2".to_string());
        let builds_table = obs("grype", "2026-11-22T00:00:00Z", VulnDbSource::ScanHistory);
        let report = summarize(&[recent, builds_table], &[], now, None);
        let g = &report.engines[0];
        assert_eq!(g.published_at, Some(at("2026-11-22T00:00:00Z")));
        assert_eq!(g.version.as_deref(), Some("grype-db-v6.0.2"));
    }

    #[test]
    fn a_configured_engine_with_no_data_is_unknown_not_fresh() {
        let report = summarize(
            &[],
            &["trivy", "grype"],
            Utc::now(),
            parse_max_age(Some("168")),
        );
        assert_eq!(report.engines.len(), 2);
        assert!(report
            .engines
            .iter()
            .all(|e| e.state == VulnDbState::Unknown && e.age_seconds.is_none()));
        assert!(!report.any_stale);
    }

    #[test]
    fn live_feeds_and_db_less_scanners_are_left_out() {
        let report = summarize(
            &[obs(
                "dependency",
                "2026-11-23T00:00:00Z",
                VulnDbSource::Scanner,
            )],
            &[],
            Utc::now(),
            None,
        );
        assert!(report.engines.is_empty());
    }

    #[test]
    fn adapter_status_body_parses_into_a_trivy_observation() {
        let body = br#"{"version":2,"updated_at":"2026-10-04T19:39:34.7Z",
            "next_update":"2026-10-05T19:39:34.7Z","age_seconds":100,"stale":true,"offline":true}"#;
        let o = adapter_observation(body).expect("observation");
        assert_eq!(o.version.as_deref(), Some("trivy-db-v2"));
        assert_eq!(o.source, VulnDbSource::Adapter);
        assert_eq!(o.offline, Some(true));
        assert_eq!(engine_for(&o.scan_type), Some("trivy"));
        // No build time or no schema version: nothing to report.
        assert!(adapter_observation(br#"{"version":2}"#).is_none());
        assert!(adapter_observation(br#"{"updated_at":"2026-10-04T19:39:34Z"}"#).is_none());
        assert!(adapter_observation(b"not json").is_none());
    }

    #[tokio::test]
    async fn adapter_probe_reads_the_status_and_a_refusal_is_no_observation() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/vulndb"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"{"version":2,"updated_at":"2026-10-01T00:00:00Z","stale":true,"offline":true}"#,
            ))
            .expect(1)
            .mount(&server)
            .await;
        let o = probe_adapter(&server.uri()).await.expect("probe answers");
        assert_eq!(o.published_at, at("2026-10-01T00:00:00Z"));
        // A refusal (no token configured on the adapter) is no observation.
        let refusing = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/vulndb"))
            .respond_with(ResponseTemplate::new(403))
            .mount(&refusing)
            .await;
        assert!(probe_adapter(&refusing.uri()).await.is_none());
    }

    /// The history query runs on Postgres and returns the newest completed
    /// scan per scan type inside the window, with its version. Far-future
    /// builds on a scan type no other test writes keep other rows out of the
    /// assertion (`scan_type` is a checked enum). The builds-table half of
    /// the query is exercised by the same statement; its rows are owned by
    /// the rescan tests, which reset that table.
    #[tokio::test]
    async fn history_reads_the_newest_recent_scan_per_type_from_postgres() {
        let Some(pool) = crate::testing::try_pool_with(2).await else {
            return;
        };
        let tag = uuid::Uuid::new_v4().simple().to_string();
        let repo = uuid::Uuid::new_v4();
        sqlx::query(
            "INSERT INTO repositories (id, key, name, storage_path, repo_type, format) \
             VALUES ($1, $2, $2, $3, 'local', 'generic')",
        )
        .bind(repo)
        .bind(format!("vuln-db-status-{tag}"))
        .bind(format!("/tmp/vuln-db-status/{tag}"))
        .execute(&pool)
        .await
        .expect("repo");
        let newest = at("2098-03-04T05:06:07Z");
        for (published, version, age) in [
            (newest, "trivy-db-v2", "1 minute"),
            (at("2098-01-01T00:00:00Z"), "trivy-db-v1", "2 minutes"),
            // Outside the window: ignored although it names a newer build.
            (at("2098-12-01T00:00:00Z"), "trivy-db-v9", "3 days"),
        ] {
            let id = uuid::Uuid::new_v4();
            let digest = format!("{:0>64}", id.simple());
            sqlx::query(
                "INSERT INTO artifacts (id, repository_id, path, name, size_bytes, \
                 checksum_sha256, content_type, storage_key) \
                 VALUES ($1, $2, $3, $3, 1, $4, 'application/octet-stream', $3)",
            )
            .bind(id)
            .bind(repo)
            .bind(format!("vdb/{id}"))
            .bind(&digest)
            .execute(&pool)
            .await
            .expect("artifact");
            sqlx::query(
                "INSERT INTO scan_results (artifact_id, repository_id, scan_type, status, \
                 checksum_sha256, completed_at, created_at, vuln_db_version, \
                 vuln_db_published_at) \
                 VALUES ($1, $2, 'incus', 'completed', $3, NOW(), NOW() - $4::interval, $5, $6)",
            )
            .bind(id)
            .bind(repo)
            .bind(&digest)
            .bind(age)
            .bind(version)
            .bind(published)
            .execute(&pool)
            .await
            .expect("scan row");
        }

        let rows = history_observations(&pool).await;
        let recent: Vec<_> = rows
            .iter()
            .filter(|o| o.scan_type == "incus" && o.version.is_some())
            .collect();
        sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(repo)
            .execute(&pool)
            .await
            .unwrap();
        assert_eq!(recent.len(), 1, "{rows:?}");
        assert_eq!(recent[0].published_at, newest);
        assert_eq!(recent[0].version.as_deref(), Some("trivy-db-v2"));
        assert_eq!(recent[0].source, VulnDbSource::ScanHistory);
    }

    #[test]
    fn stale_warnings_are_throttled_per_engine() {
        let engine = format!("test-engine-{}", uuid::Uuid::new_v4());
        assert!(should_warn(&engine));
        assert!(!should_warn(&engine));
        let other = format!("test-engine-{}", uuid::Uuid::new_v4());
        assert!(should_warn(&other));
    }
}
