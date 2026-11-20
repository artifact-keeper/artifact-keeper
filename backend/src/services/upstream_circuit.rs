//! Per-upstream circuit breaker for proxy fetches (#5013).
//!
//! A Remote repository whose upstream is down used to pay for that on every
//! request: a refused connection costs little, but a black-holed address costs
//! the connect timeout (`PROXY_UPSTREAM_CONNECT_TIMEOUT_SECS`, 10 s by
//! default) and a hung upstream the read timeout, before the request can fall
//! back to a stale copy, a lower-priority virtual member or a `503`. Under CI
//! load those waits stack up into request-ceiling `503`s.
//!
//! Every upstream request [`crate::services::proxy_service`] makes for a
//! Remote repository goes through [`UpstreamCircuits::admit`] first. The
//! circuit is keyed by the repository and the upstream host (with its port),
//! so a dead Remote never short-circuits another Remote on the same host, and
//! a redirect or token host gets a circuit of its own.
//!
//! * **Closed** (the normal state): requests go out. After
//!   [`CIRCUIT_FAILURES_ENV`] failures in a row, each within
//!   [`CIRCUIT_WINDOW_SECS_ENV`] of the one before, the circuit opens.
//! * **Open**: requests are refused at once with an [`AppError`] the callers
//!   already read as "the upstream could not answer"
//!   ([`crate::services::proxy_service::MemberFetchFailure::Unavailable`]):
//!   a Remote serves its stale copy within the stale-if-error grace, a
//!   virtual walk moves to the next member or answers `503` with
//!   `Retry-After`, and nothing is reported as a miss. The open period starts
//!   at [`CIRCUIT_OPEN_SECS_ENV`], doubles each time a probe fails, up to
//!   [`CIRCUIT_MAX_OPEN_SECS_ENV`], and is jittered by ±20 % so replicas and
//!   repositories do not probe in lockstep.
//! * **Half-open**: once the open period has passed, exactly one request is
//!   let through as the probe while the others keep being refused. Its
//!   success closes the circuit and resets the backoff; its failure opens it
//!   again for the next, longer period.
//!
//! What counts:
//! * a **failure** is a connect error, a timeout, another transport error, an
//!   upstream `502`, `503` or `504`, or a request abandoned (its future
//!   dropped by a deadline above it) after it had waited
//!   [`CIRCUIT_SLOW_CALL_SECS_ENV`] for response headers;
//! * a **success** is any other HTTP answer: `2xx`, `3xx`, `404`, `410`,
//!   `401`, `403` and the other `4xx`. The upstream answered, so a real miss
//!   stays a miss and a credentials refusal stays a refusal;
//! * **neither**: `429` and `500`/`501`/other `5xx` (a rate limit and an
//!   application error about one object say nothing about whether the
//!   upstream is reachable, and must not cut off every other path), and a
//!   refusal by this server's own outbound policy (SSRF, egress proxy).
//!
//! The state is in memory, per replica. Nothing about the circuit is a
//! correctness decision: open only turns "wait for the upstream" into "the
//! upstream is unavailable", which every caller already handles. Each replica
//! learns of an outage within [`CIRCUIT_FAILURES_ENV`] requests of its own,
//! and sharing the state (database or another store) would add a round trip
//! to every upstream request and make the breaker depend on a second system
//! during exactly the partial outages it exists for. A replica whose own
//! egress is broken also ought to open on its own.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use rand::RngExt;
use reqwest::StatusCode;
use tokio::time::Instant;
use uuid::Uuid;

use crate::error::AppError;

/// Consecutive failures that open a circuit. Default
/// [`DEFAULT_CIRCUIT_FAILURES`]; values below 1 are read as 1.
pub const CIRCUIT_FAILURES_ENV: &str = "AK_UPSTREAM_CIRCUIT_FAILURES";
/// A failure more than this many seconds after the previous one starts a
/// new count. Default [`DEFAULT_CIRCUIT_WINDOW_SECS`]; values below 1 are
/// read as 1.
pub const CIRCUIT_WINDOW_SECS_ENV: &str = "AK_UPSTREAM_CIRCUIT_WINDOW_SECS";
/// The first open period, in seconds. Default [`DEFAULT_CIRCUIT_OPEN_SECS`];
/// `0` disables the breaker.
pub const CIRCUIT_OPEN_SECS_ENV: &str = "AK_UPSTREAM_CIRCUIT_OPEN_SECS";
/// The longest open period the backoff grows to, in seconds. Default
/// [`DEFAULT_CIRCUIT_MAX_OPEN_SECS`]; never below the first period.
pub const CIRCUIT_MAX_OPEN_SECS_ENV: &str = "AK_UPSTREAM_CIRCUIT_MAX_OPEN_SECS";
/// A request abandoned after waiting this many seconds for its response
/// headers counts as a failure. Default [`DEFAULT_CIRCUIT_SLOW_CALL_SECS`];
/// `0` never counts an abandoned request.
pub const CIRCUIT_SLOW_CALL_SECS_ENV: &str = "AK_UPSTREAM_CIRCUIT_SLOW_CALL_SECS";

/// Default for [`CIRCUIT_FAILURES_ENV`].
pub const DEFAULT_CIRCUIT_FAILURES: u32 = 5;
/// Default for [`CIRCUIT_WINDOW_SECS_ENV`]: twice the default upstream read
/// timeout, so requests that each wait out a hung upstream one after another
/// still add up.
pub const DEFAULT_CIRCUIT_WINDOW_SECS: u64 = 120;
/// Default for [`CIRCUIT_OPEN_SECS_ENV`].
pub const DEFAULT_CIRCUIT_OPEN_SECS: u64 = 10;
/// Default for [`CIRCUIT_MAX_OPEN_SECS_ENV`].
pub const DEFAULT_CIRCUIT_MAX_OPEN_SECS: u64 = 300;
/// Default for [`CIRCUIT_SLOW_CALL_SECS_ENV`]: the default connect timeout.
pub const DEFAULT_CIRCUIT_SLOW_CALL_SECS: u64 = 10;

/// Gauge per circuit: `0` closed, `1` open, `2` half-open (a probe is out).
pub const CIRCUIT_STATE_GAUGE: &str = "ak_upstream_circuit_state";
/// Counter per circuit: times it opened (a reopen after a failed probe
/// included).
pub const CIRCUIT_OPENS_COUNTER: &str = "ak_upstream_circuit_opens_total";
/// Counter per circuit: requests refused without contacting the upstream.
pub const CIRCUIT_SHORT_CIRCUITED_COUNTER: &str = "ak_upstream_circuit_short_circuited_total";

/// How every error for a refused request begins; see
/// [`is_upstream_circuit_open`].
const CIRCUIT_OPEN_MESSAGE_PREFIX: &str = "Upstream circuit open";

/// Jitter applied to every open period: a factor in `[1 - J, 1 + J]`.
const JITTER: f64 = 0.2;

/// The breaker's settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CircuitSettings {
    pub failures: u32,
    pub window: Duration,
    /// `None`: disabled.
    pub open_base: Option<Duration>,
    pub open_max: Duration,
    /// `None`: an abandoned request never counts.
    pub slow_call: Option<Duration>,
}

impl Default for CircuitSettings {
    fn default() -> Self {
        Self::from_values(None, None, None, None, None)
    }
}

impl CircuitSettings {
    /// From the `AK_UPSTREAM_CIRCUIT_*` environment variables.
    pub fn from_env() -> Self {
        let var = |name: &str| std::env::var(name).ok();
        Self::from_values(
            var(CIRCUIT_FAILURES_ENV).as_deref(),
            var(CIRCUIT_WINDOW_SECS_ENV).as_deref(),
            var(CIRCUIT_OPEN_SECS_ENV).as_deref(),
            var(CIRCUIT_MAX_OPEN_SECS_ENV).as_deref(),
            var(CIRCUIT_SLOW_CALL_SECS_ENV).as_deref(),
        )
    }

    fn from_values(
        failures: Option<&str>,
        window_secs: Option<&str>,
        open_secs: Option<&str>,
        max_open_secs: Option<&str>,
        slow_call_secs: Option<&str>,
    ) -> Self {
        fn num<T: std::str::FromStr>(raw: Option<&str>, default: T) -> T {
            raw.and_then(|v| v.trim().parse::<T>().ok())
                .unwrap_or(default)
        }
        let open = num(open_secs, DEFAULT_CIRCUIT_OPEN_SECS);
        let max_open = num(max_open_secs, DEFAULT_CIRCUIT_MAX_OPEN_SECS).max(open);
        let slow = num(slow_call_secs, DEFAULT_CIRCUIT_SLOW_CALL_SECS);
        Self {
            failures: num(failures, DEFAULT_CIRCUIT_FAILURES).max(1),
            window: Duration::from_secs(num(window_secs, DEFAULT_CIRCUIT_WINDOW_SECS).max(1)),
            open_base: (open > 0).then(|| Duration::from_secs(open)),
            open_max: Duration::from_secs(max_open),
            slow_call: (slow > 0).then(|| Duration::from_secs(slow)),
        }
    }

    /// The un-jittered open period after `opens` consecutive openings (1 for
    /// the first): the base period doubled per failed probe, capped.
    fn open_period(&self, opens: u32) -> Option<Duration> {
        let base = self.open_base?;
        let factor = 1u32 << opens.saturating_sub(1).min(16);
        Some(base.saturating_mul(factor).min(self.open_max))
    }
}

/// What one upstream request said about its upstream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallOutcome {
    /// The upstream answered.
    Success,
    /// The upstream could not answer; the reason is for the log.
    Failure(&'static str),
    /// Says nothing about the upstream's availability.
    Neutral,
}

impl CallOutcome {
    /// The outcome of an upstream answer with `status`.
    pub fn of_status(status: StatusCode) -> Self {
        match status {
            StatusCode::BAD_GATEWAY => Self::Failure("upstream 502"),
            StatusCode::SERVICE_UNAVAILABLE => Self::Failure("upstream 503"),
            StatusCode::GATEWAY_TIMEOUT => Self::Failure("upstream 504"),
            s if s.is_server_error() || s == StatusCode::TOO_MANY_REQUESTS => Self::Neutral,
            _ => Self::Success,
        }
    }

    /// The outcome of a request that produced no response. `policy_refusal`
    /// is a refusal by this server's own outbound policy, which never reached
    /// the upstream.
    pub fn of_transport_error(err: &reqwest::Error, policy_refusal: bool) -> Self {
        if policy_refusal || err.is_builder() || err.is_redirect() {
            Self::Neutral
        } else if err.is_timeout() {
            Self::Failure("timeout")
        } else if err.is_connect() {
            Self::Failure("connect error")
        } else {
            Self::Failure("transport error")
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CircuitKey {
    repo: Uuid,
    host: String,
}

impl CircuitKey {
    fn of(repo: Uuid, url: &reqwest::Url) -> Self {
        let host = url.host_str().unwrap_or_default().to_ascii_lowercase();
        let host = match url.port_or_known_default() {
            Some(port) => format!("{host}:{port}"),
            None => host,
        };
        Self { repo, host }
    }

    fn labels(&self) -> [(&'static str, String); 2] {
        [
            ("repository_id", self.repo.to_string()),
            ("host", self.host.clone()),
        ]
    }
}

#[derive(Debug, Default)]
struct CircuitState {
    /// Failures in a row while closed.
    failures: u32,
    /// When the last of those failures happened.
    last_failure_at: Option<Instant>,
    /// Set while open (and half-open, once the instant has passed).
    open_until: Option<Instant>,
    /// Consecutive openings without a success; drives the backoff.
    opens: u32,
    /// The half-open probe is out.
    probing: bool,
}

/// A request to the upstream refused because its circuit is open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CircuitOpen {
    pub host: String,
    /// Until the circuit lets the next probe through (zero while a probe is
    /// already out).
    pub retry_in: Duration,
}

impl CircuitOpen {
    /// The error the proxy reports for the refused request: a `503` that
    /// every caller reads as "upstream unavailable" (stale-if-error, the
    /// virtual walks' `503`, never a miss).
    pub fn into_app_error(self) -> AppError {
        AppError::ServiceUnavailable(format!(
            "{CIRCUIT_OPEN_MESSAGE_PREFIX} for {}: it failed repeatedly, so it is not \
             contacted for another {} s",
            self.host,
            self.retry_in.as_secs()
        ))
    }
}

/// Whether `err` is a request the circuit refused ([`CircuitOpen`]).
pub fn is_upstream_circuit_open(err: &AppError) -> bool {
    matches!(err, AppError::ServiceUnavailable(m) if m.starts_with(CIRCUIT_OPEN_MESSAGE_PREFIX))
}

/// The circuits of one proxy service, shared by its clones.
#[derive(Debug)]
pub struct UpstreamCircuits {
    settings: CircuitSettings,
    states: Mutex<HashMap<CircuitKey, CircuitState>>,
}

impl Default for UpstreamCircuits {
    fn default() -> Self {
        Self::new(CircuitSettings::default())
    }
}

/// An admitted request. Report how it went with [`Self::finish`]; dropping it
/// unfinished (the request was abandoned) counts as a failure only once it
/// had waited [`CircuitSettings::slow_call`], and otherwise just frees the
/// probe slot.
#[must_use]
pub struct CircuitCall<'a> {
    circuits: &'a UpstreamCircuits,
    /// `None`: the breaker is disabled, nothing is recorded.
    key: Option<CircuitKey>,
    probe: bool,
    started: Instant,
}

impl CircuitCall<'_> {
    /// Whether this request is the half-open probe.
    pub fn is_probe(&self) -> bool {
        self.probe
    }

    /// Record how the request went.
    pub fn finish(mut self, outcome: CallOutcome) {
        if let Some(key) = self.key.take() {
            self.circuits.record(&key, outcome, self.probe);
        }
    }
}

impl Drop for CircuitCall<'_> {
    fn drop(&mut self) {
        let Some(key) = self.key.take() else {
            return;
        };
        let slow = self
            .circuits
            .settings
            .slow_call
            .is_some_and(|slow| self.started.elapsed() >= slow);
        let outcome = if slow {
            CallOutcome::Failure("no response headers before the request was abandoned")
        } else {
            CallOutcome::Neutral
        };
        self.circuits.record(&key, outcome, self.probe);
    }
}

impl UpstreamCircuits {
    pub fn new(settings: CircuitSettings) -> Self {
        Self {
            settings,
            states: Mutex::new(HashMap::new()),
        }
    }

    pub fn from_env() -> Self {
        Self::new(CircuitSettings::from_env())
    }

    pub fn settings(&self) -> &CircuitSettings {
        &self.settings
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<CircuitKey, CircuitState>> {
        // A few counters per entry: a panic while holding the lock leaves
        // nothing worth refusing to read.
        self.states
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Admit a request from `repo` to `url`, or refuse it because the
    /// circuit is open. Once the open period has passed, exactly one request
    /// is admitted as the probe.
    pub fn admit(&self, repo: Uuid, url: &reqwest::Url) -> Result<CircuitCall<'_>, CircuitOpen> {
        let started = Instant::now();
        if self.settings.open_base.is_none() {
            return Ok(CircuitCall {
                circuits: self,
                key: None,
                probe: false,
                started,
            });
        }
        let key = CircuitKey::of(repo, url);
        let mut states = self.lock();
        let open_until = states.get(&key).and_then(|s| s.open_until);
        let Some(open_until) = open_until else {
            drop(states);
            return Ok(CircuitCall {
                circuits: self,
                key: Some(key),
                probe: false,
                started,
            });
        };
        let state = states.get_mut(&key).expect("present: open_until was read");
        if started < open_until || state.probing {
            let retry_in = open_until.saturating_duration_since(started);
            drop(states);
            metrics::counter!(CIRCUIT_SHORT_CIRCUITED_COUNTER, &key.labels()).increment(1);
            return Err(CircuitOpen {
                host: key.host,
                retry_in,
            });
        }
        state.probing = true;
        drop(states);
        metrics::gauge!(CIRCUIT_STATE_GAUGE, &key.labels()).set(2.0);
        tracing::info!(
            repository_id = %key.repo,
            host = %key.host,
            "upstream circuit half-open: letting one request through as a probe"
        );
        Ok(CircuitCall {
            circuits: self,
            key: Some(key),
            probe: true,
            started,
        })
    }

    fn record(&self, key: &CircuitKey, outcome: CallOutcome, probe: bool) {
        let now = Instant::now();
        let mut states = self.lock();
        match outcome {
            CallOutcome::Neutral => {
                if probe {
                    if let Some(state) = states.get_mut(key) {
                        // The probe said nothing: the next request probes.
                        state.probing = false;
                    }
                }
            }
            CallOutcome::Success => {
                let Some(state) = states.remove(key) else {
                    return;
                };
                drop(states);
                if state.open_until.is_some() {
                    metrics::gauge!(CIRCUIT_STATE_GAUGE, &key.labels()).set(0.0);
                    tracing::info!(
                        repository_id = %key.repo,
                        host = %key.host,
                        "upstream answered again; its circuit is closed"
                    );
                }
            }
            CallOutcome::Failure(reason) => {
                let state = states.entry(key.clone()).or_default();
                if state.open_until.is_some() && !probe {
                    // A request admitted before the circuit opened, failing
                    // late: already counted by the opening.
                    return;
                }
                if !probe {
                    let in_window = state
                        .last_failure_at
                        .is_some_and(|last| now.duration_since(last) <= self.settings.window);
                    if !in_window {
                        state.failures = 0;
                    }
                    state.last_failure_at = Some(now);
                    state.failures = state.failures.saturating_add(1);
                    if state.failures < self.settings.failures {
                        return;
                    }
                }
                state.opens = state.opens.saturating_add(1);
                let Some(period) = self.settings.open_period(state.opens) else {
                    return;
                };
                let period = jittered(period);
                state.open_until = Some(now + period);
                state.probing = false;
                let (failures, opens) = (state.failures, state.opens);
                drop(states);
                metrics::gauge!(CIRCUIT_STATE_GAUGE, &key.labels()).set(1.0);
                metrics::counter!(CIRCUIT_OPENS_COUNTER, &key.labels()).increment(1);
                tracing::warn!(
                    repository_id = %key.repo,
                    host = %key.host,
                    reason,
                    consecutive_failures = failures,
                    opens,
                    open_secs = period.as_secs_f64(),
                    probe_failed = probe,
                    "upstream circuit open: requests to this upstream are answered as \
                     unavailable without contacting it until a probe succeeds \
                     ({CIRCUIT_FAILURES_ENV}, {CIRCUIT_OPEN_SECS_ENV})"
                );
            }
        }
    }
}

/// `period` scaled by a random factor in `[1 - JITTER, 1 + JITTER]`.
fn jittered(period: Duration) -> Duration {
    let factor = rand::rng().random_range((1.0 - JITTER)..=(1.0 + JITTER));
    period.mul_f64(factor)
}

#[cfg(ak_test_shard = "services-2")]
#[cfg(test)]
mod tests {
    use super::*;

    const OPEN: Duration = Duration::from_secs(10);

    fn settings(failures: u32) -> CircuitSettings {
        CircuitSettings {
            failures,
            window: Duration::from_secs(60),
            open_base: Some(OPEN),
            open_max: Duration::from_secs(300),
            slow_call: Some(Duration::from_secs(10)),
        }
    }

    fn url(s: &str) -> reqwest::Url {
        reqwest::Url::parse(s).expect("url")
    }

    fn fail(c: &UpstreamCircuits, repo: Uuid, u: &reqwest::Url, n: u32) {
        for _ in 0..n {
            c.admit(repo, u)
                .expect("admitted")
                .finish(CallOutcome::Failure("test"));
        }
    }

    #[tokio::test(start_paused = true)]
    async fn opens_after_consecutive_failures_and_refuses_5013() {
        let c = UpstreamCircuits::new(settings(3));
        let (repo, u) = (Uuid::new_v4(), url("http://up.example/a"));
        fail(&c, repo, &u, 2);
        assert!(c.admit(repo, &u).is_ok(), "closed after 2 of 3");
        fail(&c, repo, &u, 1);
        let open = c.admit(repo, &u).err().expect("open after 3 failures");
        assert_eq!(open.host, "up.example:80");
        assert!(open.retry_in <= OPEN.mul_f64(1.0 + JITTER));
        let err = open.into_app_error();
        assert!(is_upstream_circuit_open(&err));
        assert_eq!(
            crate::services::proxy_service::classify_member_fetch_failure(&err),
            crate::services::proxy_service::MemberFetchFailure::Unavailable,
            "an open circuit is unavailable, never a miss"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn keyed_by_repository_and_host_5013() {
        let c = UpstreamCircuits::new(settings(1));
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        fail(&c, a, &url("https://up.example/x"), 1);
        assert!(c.admit(a, &url("https://up.example/other/path")).is_err());
        assert!(c.admit(a, &url("https://UP.example:443/y")).is_err());
        assert!(
            c.admit(b, &url("https://up.example/x")).is_ok(),
            "other repo"
        );
        assert!(
            c.admit(a, &url("https://cdn.example/x")).is_ok(),
            "other host"
        );
        assert!(
            c.admit(a, &url("https://up.example:8443/x")).is_ok(),
            "other port"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn successes_and_misses_reset_the_count_5013() {
        let c = UpstreamCircuits::new(settings(3));
        let (repo, u) = (Uuid::new_v4(), url("http://up.example/a"));
        for status in [200u16, 404, 410, 401, 403] {
            fail(&c, repo, &u, 2);
            let outcome = CallOutcome::of_status(StatusCode::from_u16(status).unwrap());
            assert_eq!(outcome, CallOutcome::Success, "{status}");
            c.admit(repo, &u).unwrap().finish(outcome);
        }
        assert!(c.admit(repo, &u).is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn failures_outside_the_window_restart_the_count_5013() {
        let c = UpstreamCircuits::new(settings(3));
        let (repo, u) = (Uuid::new_v4(), url("http://up.example/a"));
        fail(&c, repo, &u, 2);
        tokio::time::advance(Duration::from_secs(61)).await;
        fail(&c, repo, &u, 1);
        assert!(c.admit(repo, &u).is_ok(), "the gap restarted the count");
        // Failures each within the window of the one before add up, however
        // long the streak takes in all.
        for _ in 0..2 {
            tokio::time::advance(Duration::from_secs(59)).await;
            assert!(c.admit(repo, &u).is_ok());
            fail(&c, repo, &u, 1);
        }
        assert!(c.admit(repo, &u).is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn half_open_admits_one_probe_and_recovers_5013() {
        let c = UpstreamCircuits::new(settings(1));
        let (repo, u) = (Uuid::new_v4(), url("http://up.example/a"));
        fail(&c, repo, &u, 1);
        tokio::time::advance(OPEN.mul_f64(1.0 + JITTER)).await;
        let probe = c.admit(repo, &u).expect("probe");
        assert!(probe.is_probe());
        let other = c.admit(repo, &u).err().expect("one probe at a time");
        assert_eq!(other.retry_in, Duration::ZERO);
        probe.finish(CallOutcome::Success);
        let next = c.admit(repo, &u).expect("closed");
        assert!(!next.is_probe());
    }

    #[tokio::test(start_paused = true)]
    async fn failed_probes_back_off_exponentially_up_to_the_cap_5013() {
        let mut s = settings(1);
        s.open_max = Duration::from_secs(35);
        let c = UpstreamCircuits::new(s);
        let (repo, u) = (Uuid::new_v4(), url("http://up.example/a"));
        fail(&c, repo, &u, 1);
        let mut periods = Vec::new();
        for _ in 0..4 {
            let open = c.admit(repo, &u).err().expect("open");
            periods.push(open.retry_in.as_secs_f64());
            tokio::time::advance(open.retry_in).await;
            c.admit(repo, &u)
                .expect("probe")
                .finish(CallOutcome::Failure("test"));
        }
        let within = |got: f64, want: f64| {
            got >= want * (1.0 - JITTER) - 0.01 && got <= want * (1.0 + JITTER) + 0.01
        };
        for (got, want) in periods.iter().zip([10.0, 20.0, 35.0, 35.0]) {
            assert!(within(*got, want), "{periods:?}");
        }
        // A success resets the backoff.
        let open = c.admit(repo, &u).err().expect("open");
        tokio::time::advance(open.retry_in).await;
        c.admit(repo, &u).unwrap().finish(CallOutcome::Success);
        fail(&c, repo, &u, 1);
        let open = c.admit(repo, &u).err().expect("open");
        assert!(within(open.retry_in.as_secs_f64(), 10.0));
    }

    #[tokio::test(start_paused = true)]
    async fn an_abandoned_probe_frees_the_slot_unless_it_was_slow_5013() {
        let c = UpstreamCircuits::new(settings(1));
        let (repo, u) = (Uuid::new_v4(), url("http://up.example/a"));
        fail(&c, repo, &u, 1);
        tokio::time::advance(OPEN * 2).await;
        drop(c.admit(repo, &u).expect("probe"));
        let probe = c
            .admit(repo, &u)
            .expect("a quick cancel frees the probe slot");
        assert!(probe.is_probe());
        tokio::time::advance(Duration::from_secs(10)).await;
        drop(probe);
        assert!(
            c.admit(repo, &u).is_err(),
            "a probe abandoned after the slow-call threshold reopens"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn slow_abandoned_requests_trip_the_circuit_5013() {
        let c = UpstreamCircuits::new(settings(2));
        let (repo, u) = (Uuid::new_v4(), url("http://up.example/a"));
        for _ in 0..2 {
            let call = c.admit(repo, &u).unwrap();
            tokio::time::advance(Duration::from_secs(11)).await;
            drop(call);
        }
        assert!(c.admit(repo, &u).is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn neutral_answers_neither_trip_nor_reset_5013() {
        let c = UpstreamCircuits::new(settings(2));
        let (repo, u) = (Uuid::new_v4(), url("http://up.example/a"));
        fail(&c, repo, &u, 1);
        for status in [429u16, 500, 501] {
            let outcome = CallOutcome::of_status(StatusCode::from_u16(status).unwrap());
            assert_eq!(outcome, CallOutcome::Neutral, "{status}");
            c.admit(repo, &u).unwrap().finish(outcome);
        }
        drop(c.admit(repo, &u).unwrap());
        fail(&c, repo, &u, 1);
        assert!(c.admit(repo, &u).is_err(), "the two failures still add up");
    }

    #[test]
    fn status_outcomes_5013() {
        for code in [502u16, 503, 504] {
            assert!(matches!(
                CallOutcome::of_status(StatusCode::from_u16(code).unwrap()),
                CallOutcome::Failure(_)
            ));
        }
        for code in [200u16, 204, 304, 400, 401, 403, 404, 410, 451] {
            assert_eq!(
                CallOutcome::of_status(StatusCode::from_u16(code).unwrap()),
                CallOutcome::Success,
                "{code}"
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn disabled_never_refuses_5013() {
        let s = CircuitSettings::from_values(Some("1"), None, Some("0"), None, None);
        assert_eq!(s.open_base, None);
        let c = UpstreamCircuits::new(s);
        let (repo, u) = (Uuid::new_v4(), url("http://up.example/a"));
        fail(&c, repo, &u, 10);
        assert!(c.admit(repo, &u).is_ok());
        assert!(c.lock().is_empty(), "nothing is tracked while disabled");
    }

    #[test]
    fn settings_parse_and_clamp_5013() {
        let d = CircuitSettings::default();
        assert_eq!(d.failures, DEFAULT_CIRCUIT_FAILURES);
        assert_eq!(d.window, Duration::from_secs(DEFAULT_CIRCUIT_WINDOW_SECS));
        assert_eq!(
            d.open_base,
            Some(Duration::from_secs(DEFAULT_CIRCUIT_OPEN_SECS))
        );
        assert_eq!(
            d.open_max,
            Duration::from_secs(DEFAULT_CIRCUIT_MAX_OPEN_SECS)
        );
        assert_eq!(
            d.slow_call,
            Some(Duration::from_secs(DEFAULT_CIRCUIT_SLOW_CALL_SECS))
        );
        let s =
            CircuitSettings::from_values(Some("0"), Some("0"), Some("30"), Some("5"), Some("0"));
        assert_eq!(s.failures, 1);
        assert_eq!(s.window, Duration::from_secs(1));
        assert_eq!(s.open_max, Duration::from_secs(30), "never below the base");
        assert_eq!(s.slow_call, None);
        let junk = CircuitSettings::from_values(Some("x"), Some("y"), Some("z"), None, None);
        assert_eq!(junk, CircuitSettings::default());
    }

    #[test]
    fn a_successful_close_forgets_the_upstream_5013() {
        let c = UpstreamCircuits::new(settings(3));
        let (repo, u) = (Uuid::new_v4(), url("http://up.example/a"));
        // Outside a runtime: `tokio::time::Instant` falls back to std.
        fail(&c, repo, &u, 2);
        c.admit(repo, &u).unwrap().finish(CallOutcome::Success);
        assert!(c.lock().is_empty(), "only failing upstreams are kept");
    }
}
