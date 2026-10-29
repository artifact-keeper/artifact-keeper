//! Prometheus metrics collection for business-level events.
//!
//! HTTP request instrumentation lives in `crate::api::middleware::metrics`.
//! This module provides helpers for recording domain-specific metrics such as
//! artifact uploads/downloads, security scans, backups, and storage gauges.
//!
//! The `metrics` facade can fan out to more than one recorder: `/metrics` is
//! always served from the Prometheus recorder, and when OTLP metrics export is
//! configured an OTel recorder is installed alongside it (#4337, see
//! [`install_otel_recorder`]). The handle returned by [`init_metrics`] keeps
//! rendering the Prometheus half.

use std::sync::Mutex;

use metrics::{counter, gauge, histogram};
use metrics_exporter_prometheus::{Matcher, PrometheusBuilder, PrometheusHandle};

/// The OpenTelemetry recorder handed over by `telemetry::init_tracing`, waiting
/// for [`init_metrics`] to install it beside the Prometheus recorder.
static PENDING_OTEL_RECORDER: Mutex<Option<Box<dyn metrics::Recorder + Send + Sync>>> =
    Mutex::new(None);

/// Name of the HTTP request latency histogram recorded by
/// `crate::api::middleware::metrics`.
pub const HTTP_REQUEST_DURATION_METRIC: &str = "ak_http_request_duration_seconds";

/// Bucket upper bounds (seconds) for [`HTTP_REQUEST_DURATION_METRIC`] (#3954).
///
/// Without explicit buckets `metrics-exporter-prometheus` renders a histogram
/// as a Prometheus *summary*: per-series quantiles pre-computed over the
/// exporter's own window, which cannot be aggregated across replicas, paths or
/// a chosen time range, so `histogram_quantile()` is unusable. Exporting
/// `_bucket{le=...}` series instead makes fleet-wide percentiles computable.
///
/// The range is sized for a registry: 5 ms covers a cached metadata hit, the
/// sub-second buckets cover database- and storage-bound requests, and the tail
/// out to 60 s covers upstream proxy fetches and large blob transfers.
pub const HTTP_REQUEST_DURATION_BUCKETS: &[f64] = &[
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0,
];

/// The configured (not yet installed) Prometheus builder: bucketed export of
/// the HTTP latency histogram, defaults for everything else. Split out of
/// [`init_metrics`] so tests can build a local recorder from the exact
/// production configuration without installing a process-global one.
pub fn prometheus_builder() -> PrometheusBuilder {
    PrometheusBuilder::new()
        .set_buckets_for_metric(
            Matcher::Full(HTTP_REQUEST_DURATION_METRIC.to_string()),
            HTTP_REQUEST_DURATION_BUCKETS,
        )
        .expect("HTTP_REQUEST_DURATION_BUCKETS is a non-empty constant")
}

/// Initialize the Prometheus metrics recorder and return the handle for rendering.
///
/// When OTLP metrics export is configured, `telemetry::init_tracing` (which
/// `main` runs first) has handed an OpenTelemetry recorder to
/// [`install_otel_recorder`]; the global recorder is then a fan-out of the
/// Prometheus recorder and that one, so `/metrics` reports exactly what it
/// does without OTLP. The `metrics` facade accepts one global recorder per
/// process, which is why both halves are installed here, once, rather than the
/// OTel half being added later.
pub fn init_metrics() -> PrometheusHandle {
    let otel = PENDING_OTEL_RECORDER
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take();
    let (recorder, handle) = build_global_recorder(otel);
    metrics::set_global_recorder(recorder).expect("failed to install Prometheus recorder");
    handle
}

/// The recorder [`init_metrics`] installs: the Prometheus recorder alone, or a
/// fan-out of it and `otel`.
pub(crate) fn build_global_recorder(
    otel: Option<Box<dyn metrics::Recorder + Send + Sync>>,
) -> (Box<dyn metrics::Recorder + Sync>, PrometheusHandle) {
    let prometheus = prometheus_builder().build_recorder();
    let handle = prometheus.handle();
    let recorder: Box<dyn metrics::Recorder + Sync> = match otel {
        Some(otel) => Box::new(
            metrics_util::layers::FanoutBuilder::default()
                .add_recorder(prometheus)
                .add_recorder(otel)
                .build(),
        ),
        None => Box::new(prometheus),
    };
    (recorder, handle)
}

/// Hand the OpenTelemetry `metrics` recorder to [`init_metrics`] (#4337).
///
/// Called by `telemetry::init_tracing` when OTLP metrics export is enabled,
/// which `main` does before it calls [`init_metrics`] (the recorder must be in
/// place before the startup pool connect records anything, #4828). Nothing is
/// recorded to OTLP until [`init_metrics`] has installed the fan-out.
pub fn install_otel_recorder(otel: impl metrics::Recorder + Send + Sync + 'static) {
    *PENDING_OTEL_RECORDER
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Box::new(otel));
}

/// Count one HTTP connection closed because the client did not deliver a
/// complete request head within `HTTP_HEADER_READ_TIMEOUT_SECS` (#4665): a
/// slow or stalled client, the slow-loris shape. Idle keep-alive connections
/// closed by the same timer are not counted.
pub fn record_http_header_read_timeout() {
    counter!("ak_http_header_read_timeouts_total").increment(1);
}

/// Count one database pool connection failure (#4549), labelled by `stage`:
///
///   * `startup` — an initial pool-connect attempt failed at boot: Postgres
///     refusing sessions (`FATAL: sorry, too many clients already` seen from
///     this side as a connect error) or the attempt hitting
///     `DATABASE_ACQUIRE_TIMEOUT_SECS`. Each of the bounded startup retries
///     increments once, so a refusal storm shows its shape before the process
///     exits or recovers.
///   * `request` — a pool acquire timed out while serving a request and the
///     caller was answered `503 POOL_EXHAUSTED`.
///
/// The server-side `FATAL` lines themselves are only visible in the Postgres
/// log: a pool growth attempt that fails is absorbed by sqlx's internal
/// retry-until-acquire-timeout loop and leaves no other client-side trace.
/// Together the two stages cover the two places #4549's saturation became
/// visible — a replacement pod dying at startup and requests shedding load.
pub fn record_db_pool_connection_failure(stage: &'static str) {
    counter!("ak_db_pool_connection_failures_total", "stage" => stage.to_string()).increment(1);
}

/// Connections currently held open by the HTTP accept loop (#4676): every
/// accepted TCP connection, from accept until hyper finishes with it,
/// including idle keep-alive connections and ones still sending a request
/// head. A slow-connection hold shows as this gauge climbing while request
/// throughput does not.
pub const HTTP_CONNECTIONS_OPEN_METRIC: &str = "ak_http_connections_open";

/// Holds one unit of [`HTTP_CONNECTIONS_OPEN_METRIC`] for as long as it lives,
/// so a connection task that ends any way (return, panic, cancellation)
/// releases it.
pub struct OpenConnectionGuard(());

impl OpenConnectionGuard {
    pub fn open() -> Self {
        gauge!(HTTP_CONNECTIONS_OPEN_METRIC).increment(1.0);
        Self(())
    }
}

impl Drop for OpenConnectionGuard {
    fn drop(&mut self) {
        gauge!(HTTP_CONNECTIONS_OPEN_METRIC).decrement(1.0);
    }
}

/// Count one request refused with 429 by a rate limiter (#4676). `limiter` is
/// the limiter's fixed name (`login`, `login_global`, `token`, `auth`, `api`,
/// `search`, `presign`, `password_change`, `upload`, `proxy_rescan`), never a
/// key, user or address.
pub fn record_rate_limit_rejection(limiter: &'static str) {
    counter!("ak_rate_limit_rejections_total", "limiter" => limiter).increment(1);
}

/// Count one outbound URL refused by the SSRF guard (#4676), by the bounded
/// surface that asked: `upstream`, `webhook`, `sso`, `ldap`, `plugin`,
/// `peer`, `internal`. Recorded beside [`record_outbound_url_blocked`], whose
/// `label` is the caller's free-text field name; this one is the series to
/// alert on.
pub fn record_ssrf_block(surface: &'static str) {
    counter!("ak_ssrf_blocks_total", "surface" => surface).increment(1);
}

/// Where a rejected credential was presented, for `ak_auth_failures_total`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthFailureSurface {
    /// `POST /api/v1/auth/login`, and a Bearer JWT, API token or `X-API-Key`
    /// presented to any HTTP route.
    Api,
    /// HTTP Basic `username:password` presented to any HTTP route.
    Basic,
    /// The OCI credential exchange, `/v2/token`.
    V2Token,
    /// The CI OIDC token exchange, `POST /api/v1/auth/ci/token`.
    CiOidc,
    /// OIDC, SAML and LDAP sign-in.
    Sso,
}

impl AuthFailureSurface {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Api => "api",
            Self::Basic => "basic",
            Self::V2Token => "v2_token",
            Self::CiOidc => "ci_oidc",
            Self::Sso => "sso",
        }
    }
}

/// Why a credential was rejected, bucketed for `ak_auth_failures_total`. A
/// closed set so no username, token or message text can become a label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthFailureReason {
    /// Wrong password for an account that can sign in locally (or a rejected
    /// LDAP bind).
    BadPassword,
    /// No account that can sign in with a password: unknown or inactive
    /// username, a federated account, or one with no stored password.
    UnknownUser,
    /// A token or assertion past its expiry.
    Expired,
    /// A wrong password against an account whose lockout is in force.
    Lockout,
    /// A token, assertion or header that did not validate.
    InvalidToken,
    /// A valid assertion that no policy admits (no CI OIDC mapping matches,
    /// or the identity provider's user is refused by the provider's rules).
    Scope,
}

impl AuthFailureReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BadPassword => "bad_password",
            Self::UnknownUser => "unknown_user",
            Self::Expired => "expired",
            Self::Lockout => "lockout",
            Self::InvalidToken => "invalid_token",
            Self::Scope => "scope",
        }
    }

    /// Bucket a rejected token's error: `Expired` when the validator said it
    /// had expired (`jsonwebtoken`'s `ExpiredSignature`, "API token expired",
    /// an expired SAML assertion), otherwise `fallback`. A message that does
    /// not commit either way ("Invalid or expired SSO state") is `fallback`.
    pub fn for_token_error(err: &crate::error::AppError, fallback: Self) -> Self {
        let message = err.to_string().to_ascii_lowercase();
        if message.contains("expired") && !message.contains("invalid or expired") {
            Self::Expired
        } else {
            fallback
        }
    }

    /// Bucket a local password rejection by the reason its audit event
    /// records (`auth_service::LoginFailure::reason`).
    pub fn for_login_audit_reason(reason: &str) -> Self {
        match reason {
            "invalid_password" => Self::BadPassword,
            "account_locked" => Self::Lockout,
            _ => Self::UnknownUser,
        }
    }
}

/// Count one rejected credential (#4676). Only a presented credential that
/// failed counts: a request with no credential at all, and a check that could
/// not complete (a 503 for a database outage or the bcrypt cap), do not.
pub fn record_auth_failure(surface: AuthFailureSurface, reason: AuthFailureReason) {
    counter!(
        "ak_auth_failures_total",
        "surface" => surface.as_str(),
        "reason" => reason.as_str(),
    )
    .increment(1);
}

/// [`record_auth_failure`] for an error a credential check returned, counted
/// only when the error is a credential or policy refusal (`Authentication`,
/// `Unauthorized`, `Authorization`), never for an outage or a malformed
/// request.
pub fn record_auth_failure_for_error(
    surface: AuthFailureSurface,
    err: &crate::error::AppError,
    fallback: AuthFailureReason,
) {
    use crate::error::AppError;
    if matches!(
        err,
        AppError::Authentication(_) | AppError::Unauthorized(_) | AppError::Authorization(_)
    ) {
        record_auth_failure(surface, AuthFailureReason::for_token_error(err, fallback));
    }
}

/// Count one proxy-scan decision on a pull (#4676). `verdict` is what the
/// pull was judged as (`clean`, `vulnerable`, `pending` for a first pull
/// served before its scan, `inconclusive` for an over-cap object or a scan
/// that could not finish); `action` is what was done with it (`served`,
/// `blocked` 403, `locked` 423, `recorded` for a record-only repository
/// serving a vulnerable verdict). A vulnerable verdict below the
/// repository's opted-in severity threshold is served as `clean`.
pub fn record_proxy_scan_verdict(verdict: &'static str, action: &'static str) {
    counter!(
        "ak_proxy_scan_verdicts_total",
        "verdict" => verdict,
        "action" => action,
    )
    .increment(1);
}

/// Record one committed artifact upload: `ak_artifact_uploads_total` and the
/// `ak_artifact_upload_size_bytes` histogram. Called from
/// `scanner_service::trigger_scan_on_upload`, the post-commit step every
/// upload path reaches (#4642). Labels are the repository key and format only,
/// never an artifact name, so the series count stays bounded.
pub fn record_artifact_upload(repo_key: &str, format: &str, size_bytes: u64) {
    counter!("ak_artifact_uploads_total", "repository" => repo_key.to_string(), "format" => format.to_string()).increment(1);
    histogram!("ak_artifact_upload_size_bytes", "format" => format.to_string())
        .record(size_bytes as f64);
}

/// Count `count` served artifact downloads in `ak_artifact_downloads_total`.
/// Called by the download-event dispatcher once it has persisted the
/// `download_statistics` rows (#4642), so the counter moves by the rows a
/// flush wrote. Same bounded labels as [`record_artifact_upload`].
pub fn record_artifact_downloads(repo_key: &str, format: &str, count: u64) {
    counter!("ak_artifact_downloads_total", "repository" => repo_key.to_string(), "format" => format.to_string()).increment(count);
}

/// Record a proxy-cache lookup. `result` is a stable low-cardinality
/// string describing the outcome, used as a Prometheus label:
///
///   * `hit` -- valid cached body returned to the caller
///   * `miss_no_metadata` -- the metadata sidecar was absent (first
///     request for this key, OR sidecar was evicted/deleted out of band)
///   * `miss_expired` -- metadata loaded but `expires_at` was in the past
///   * `miss_no_content` -- metadata existed but the content object was
///     gone (typical eviction race; cache will refill on the next miss)
///   * `miss_checksum_mismatch` -- content loaded but its sha256 did not
///     match the recorded sidecar checksum; cache self-heals on the next
///     write but this should be very rare and indicates either backend
///     corruption or a content rewrite by a sibling writer
///   * `error` -- the storage backend returned a non-NotFound error
///     (network, ACL, KMS) so the lookup couldn't determine hit-or-miss
///
/// Operators investigating "why is the cache not working" can chart
/// `rate(ak_proxy_cache_lookups_total[5m])` by `result` and see exactly
/// which branch is responsible for slow repeat requests. The repository
/// label keeps cardinality bounded by the operator's repo count, which
/// matches the existing `ak_artifact_downloads_total` shape.
pub fn record_proxy_cache_lookup(repo_key: &str, result: &'static str) {
    // The same outcome tags the request's trace (#4455), as a span attribute
    // only: the repository label above is the metric's only per-repo series.
    crate::api::middleware::request_span::record_cache_outcome(result);
    counter!(
        "ak_proxy_cache_lookups_total",
        "repository" => repo_key.to_string(),
        "result" => result.to_string()
    )
    .increment(1);
}

/// A response served from a stale cache entry under the RFC 5861
/// `stale-if-error` grace because the upstream was unreachable (#4581).
///
/// A sustained rate means a remote's upstream is down while clients keep
/// getting 200s; alert on `rate(ak_proxy_stale_if_error_responses_total[5m]) > 0`.
pub fn record_proxy_stale_if_error_response(repo_key: &str) {
    counter!(
        "ak_proxy_stale_if_error_responses_total",
        "repo" => repo_key.to_string()
    )
    .increment(1);
}

/// Virtual conda merge pressure (#4608). `kind` is the merged document:
/// `repodata`, `channeldata` or `shard_index`.
///
/// A cache hit is a request answered without running a merge of its own:
/// `via="cache"` for a fresh merged document kept from an earlier merge,
/// `via="stale"` for a kept document served stale while one background merge
/// rebuilds it (#4879), and `via="singleflight"` for a request that waited on
/// the merge another request for the same document was already running.
pub fn record_conda_virtual_merge_cache_hit(kind: &'static str, via: &'static str) {
    counter!("ak_conda_virtual_merge_cache_hits_total", "kind" => kind, "via" => via).increment(1);
}

/// A request that started a merge (no usable cached document, none in
/// flight), in the foreground or as the background rebuild of a stale one.
pub fn record_conda_virtual_merge_cache_miss(kind: &'static str) {
    counter!("ak_conda_virtual_merge_cache_misses_total", "kind" => kind).increment(1);
}

/// A merge shed with 503 because it could not get a merge slot
/// (`reason="queue"`) or its share of the buffered-metadata budget
/// (`reason="budget"`) within `CONDA_VIRTUAL_MERGE_QUEUE_SECS`. Counted once
/// per merge, not once per request sharing it.
pub fn record_conda_virtual_merge_rejected(kind: &'static str, reason: &'static str) {
    counter!("ak_conda_virtual_merge_rejected_total", "kind" => kind, "reason" => reason)
        .increment(1);
}

/// Merges currently running (each holds one of
/// `CONDA_VIRTUAL_MAX_CONCURRENT_MERGES` slots).
pub fn set_conda_virtual_merge_inflight(merges: usize) {
    gauge!("ak_conda_virtual_merge_inflight").set(merges as f64);
}

/// Bytes of the buffered-metadata budget currently reserved by virtual conda
/// merges (fetch buffers, decoded member documents and merge output).
pub fn set_conda_virtual_merge_bytes_reserved(bytes: usize) {
    gauge!("ak_conda_virtual_merge_bytes_reserved").set(bytes as f64);
}

/// Bytes of the serve-time verification buffer budget currently reserved
/// (#4989): small stored objects read whole and checked before their status
/// is sent, held until the client has read them.
pub fn set_serve_verify_buffer_bytes_reserved(bytes: usize) {
    gauge!("ak_serve_verify_buffer_bytes_reserved").set(bytes as f64);
}

/// A small stored object served with its verification while streaming,
/// because the verification buffer budget had no room for it (#4989). A
/// steady rate means `AK_SERVE_VERIFY_BUFFER_BUDGET_BYTES` is too small for
/// the load.
pub fn record_serve_verify_buffer_fallback() {
    counter!("ak_serve_verify_buffer_fallback_total").increment(1);
}

/// Outcome of a CEP-27 publish attestation decision (#4711). `outcome` is one
/// of [`CONDA_ATTESTATION_OUTCOMES`]; `repository` is the repository key.
///
/// * `verified`: an attestation PUT whose bundle verified, and was stored.
/// * `failed`: an attestation PUT whose bundle did not verify, stored anyway
///   because `CONDA_ATTESTATION_REQUIRE_VERIFIED` is explicitly off.
/// * `rejected`: an attestation PUT whose bundle did not verify, refused
///   because verification is required (the default).
/// * `absent`: a hosted package upload, which carries no attestation of its
///   own (CEP-27 attestations are attached afterwards by PUT).
pub fn record_conda_attestation(repo_key: &str, outcome: &'static str) {
    debug_assert!(CONDA_ATTESTATION_OUTCOMES.contains(&outcome));
    counter!(
        "ak_conda_attestation_total",
        "repository" => repo_key.to_string(),
        "outcome" => outcome,
    )
    .increment(1);
}

/// The bounded `outcome` label values of `ak_conda_attestation_total`.
pub const CONDA_ATTESTATION_OUTCOMES: [&str; 4] = ["verified", "failed", "absent", "rejected"];

/// Install scripts found in an uploaded conda package's payload (#4711).
/// `kind` is the conda hook the script implements (`pre-link`, `post-link`,
/// `pre-unlink`), as `conda_scripts::classify_script_path` classifies it.
pub fn record_conda_install_script_findings(repo_key: &str, kind: &'static str, count: u64) {
    if count == 0 {
        return;
    }
    counter!(
        "ak_conda_install_script_findings_total",
        "repository" => repo_key.to_string(),
        "kind" => kind,
    )
    .increment(count);
}

/// Remote records a virtual conda channel's package allowlist (#4576)
/// dropped from one merge, per remote member (#4711). `repository` is the
/// virtual repository's key and `member` the remote member's key. Counted
/// once per merge, so cached and single-flighted requests add nothing.
pub fn record_conda_allowlist_dropped(virtual_repo_key: &str, member: &str, count: u64) {
    if count == 0 {
        return;
    }
    counter!(
        "ak_conda_allowlist_dropped_total",
        "repository" => virtual_repo_key.to_string(),
        "member" => member.to_string(),
    )
    .increment(count);
}

/// Record a lookup against the npm attestation negative cache (#3764),
/// which memoises the `404`s that `npm audit signatures` provokes on the
/// `/-/npm/v1/attestations/{pkg}@{ver}` proxy path.
///
/// Deliberately a **separate** counter from
/// [`record_proxy_cache_lookup`] rather than another `result` label on it:
/// that metric is the artifact proxy-cache's hit rate, and folding a second
/// cache into the same series would silently change what every existing
/// `ak_proxy_cache_lookups_total` dashboard and alert is measuring.
///
/// `result` is one of:
///   * `hit` -- served from cache, no upstream request
///   * `miss_stored` -- upstream answered, the answer was cached
///   * `miss_uncacheable` -- upstream answered, but not with a cacheable
///     result (a real attestation `200`, an auth failure, a rate limit, a
///     5xx, or a body over the size cap)
///   * `error` -- upstream was unreachable, so the request fell through to
///     the local handler
///
/// Same bounded-label contract as [`record_proxy_cache_lookup`]: the
/// repository label is bounded by the operator's repo count, and the package
/// spec is deliberately NOT a label (its cardinality is unbounded).
pub fn record_npm_attestation_cache_lookup(repo_key: &str, result: &str) {
    counter!(
        "ak_npm_attestation_cache_lookups_total",
        "repository" => repo_key.to_string(),
        "result" => result.to_string()
    )
    .increment(1);
}

/// Record a download request blocked by the age gate. Incremented once per
/// blocked HTTP request (a client asking for one specific artifact version),
/// never per version in a metadata document, so packument/simple-index
/// fan-out cannot inflate the counter. Labels are bounded to repository and
/// format; package name and version are deliberately NOT labels (their
/// cardinality is unbounded).
pub fn record_age_gate_blocked_request(repo_key: &str, format: &str) {
    counter!("ak_age_gate_blocked_requests_total", "repository" => repo_key.to_string(), "format" => format.to_string()).increment(1);
}

/// Record a metadata listing fetch (npm packument / PyPI simple index) from
/// which the age gate withheld at least one version. Incremented once per
/// affected fetch — not once per withheld version — so it stays a
/// request-rate signal (how often listings are filtered) rather than a
/// version-volume signal. Same bounded-label contract as
/// [`record_age_gate_blocked_request`].
pub fn record_age_gate_filtered_metadata(repo_key: &str, format: &str) {
    counter!("ak_age_gate_filtered_metadata_total", "repository" => repo_key.to_string(), "format" => format.to_string()).increment(1);
}

/// Record a backup event.
pub fn record_backup(backup_type: &str, success: bool, duration_secs: f64) {
    let status = if success { "success" } else { "failure" };
    counter!("ak_backup_operations_total", "type" => backup_type.to_string(), "status" => status.to_string()).increment(1);
    histogram!("ak_backup_duration_seconds", "type" => backup_type.to_string())
        .record(duration_secs);
}

/// Record a security scan event.
pub fn record_security_scan(scanner: &str, success: bool, duration_secs: f64) {
    let status = if success { "success" } else { "failure" };
    counter!("ak_security_scans_total", "scanner" => scanner.to_string(), "status" => status.to_string()).increment(1);
    histogram!("ak_security_scan_duration_seconds", "scanner" => scanner.to_string())
        .record(duration_secs);
}

/// Record a scanner backend health-check failure. Distinct from
/// `record_security_scan` so dashboards can separate "Trivy was down" from
/// "scan ran and failed mid-execution". `reason` is "unreachable" (network
/// error / timeout) or "unhealthy" (non-2xx response).
pub fn record_scanner_health_check_failure(scanner: &str, reason: &str) {
    counter!(
        "ak_scanner_health_check_failures_total",
        "scanner" => scanner.to_string(),
        "reason" => reason.to_string()
    )
    .increment(1);
}

/// Record a scan that succeeded at the scanner level but failed to persist
/// its package inventory in full (#1157). The scan row is marked
/// `inventory_status = 'partial'` and this counter increments so operator
/// dashboards can alert on "scans succeed but SBOMs are degraded" without
/// having to poll the scan_results table directly. `scan_type` matches the
/// label used in `record_security_scan` (e.g. `"trivy"`, `"openscap"`) so
/// the two metrics can be correlated.
pub fn record_scan_inventory_failure(scan_type: &str) {
    counter!(
        "scan_inventory_failures_total",
        "scan_type" => scan_type.to_string()
    )
    .increment(1);
}

/// Companion to `record_scan_inventory_failure`. Increments on every
/// successful `scan_packages` persistence. Exposing both counters lets
/// SRE alerts target the failure *ratio*
/// (`failures / (failures + success)`) rather than the raw failure rate,
/// which is brittle under traffic changes (low-traffic instances can
/// produce a few failures without being degraded; high-traffic instances
/// can produce many failures and still be healthy in ratio terms).
pub fn record_scan_inventory_success(scan_type: &str) {
    counter!(
        "scan_inventory_success_total",
        "scan_type" => scan_type.to_string()
    )
    .increment(1);
}

/// Record a webhook delivery event.
pub fn record_webhook_delivery(event: &str, success: bool) {
    let status = if success { "success" } else { "failure" };
    counter!("ak_webhook_deliveries_total", "event" => event.to_string(), "status" => status.to_string()).increment(1);
}

/// Record a webhook delivery row enqueued by the EventBus producer.
/// Distinct from `record_webhook_delivery` so dashboards can separate
/// "events that had matching subscribers" (enqueue count) from
/// "actual HTTP deliveries" (delivery count, success+failure).
pub fn record_webhook_delivery_enqueued(event: &str) {
    counter!("ak_webhook_deliveries_enqueued_total", "event" => event.to_string()).increment(1);
}

/// Record a webhook delivery row that the producer failed to insert into
/// `webhook_deliveries`. Counted distinctly from `enqueued_total` so an
/// alert can fire on persistent insert failures (DB down, constraint
/// violation, pool exhaustion) without polluting the success metric.
/// `reason` is a short tag classifying the failure (e.g. `"db_error"`).
pub fn record_webhook_delivery_enqueue_failed(event: &str, reason: &str) {
    counter!(
        "ak_webhook_deliveries_enqueue_failed_total",
        "event" => event.to_string(),
        "reason" => reason.to_string()
    )
    .increment(1);
}

/// Record that a webhook delivery exhausted its retry budget and was
/// dead-lettered. This is the signal ops watches to detect persistently
/// failing receivers; auto-disable also fires on this transition.
pub fn record_webhook_dead_letter(event: &str) {
    counter!(
        "ak_webhook_dead_letter_total",
        "event" => event.to_string()
    )
    .increment(1);
}

/// Record download side-effect events (stats/audit) dropped by the bounded
/// dispatcher (#2522). `kind` is `"stats"` or `"audit"`; `reason` is
/// `"queue_full"` (overflow shed under load), `"closed"` (workers gone),
/// `"uninitialised"` (no dispatcher installed — tests/embedders), or
/// `"flush_failed"` (the DB rejected the row even via the per-row fallback,
/// e.g. a poison row or event-store error — `count` is the rows lost). A
/// sustained `queue_full` rate means the event store cannot keep up with
/// download volume; any `flush_failed` deserves a look at the warn logs. The
/// byte plane is unaffected by design in every case.
pub fn record_download_events_dropped(kind: &str, reason: &str, count: u64) {
    counter!(
        "ak_download_events_dropped_total",
        "kind" => kind.to_string(),
        "reason" => reason.to_string()
    )
    .increment(count);
}

/// Update the bounded download-event queue-depth gauge (#2522). Sampled on
/// enqueue; a depth pinned at the configured capacity together with a rising
/// `ak_download_events_dropped_total{reason="queue_full"}` means the flush
/// workers are saturated.
pub fn set_download_event_queue_depth(depth: f64) {
    gauge!("ak_download_event_queue_depth").set(depth);
}

/// Record an outbound URL that was rejected by SSRF validation, either
/// at handler entry (`validate_outbound_url`) or on a redirect hop
/// inside the shared HTTP client. `reason` is `"hostname"` or `"ip"`,
/// `label` identifies the calling site (e.g. `"Webhook URL"`,
/// `"Cargo upstream download URL"`, `"http-client redirect"`).
pub fn record_outbound_url_blocked(reason: &str, label: &str) {
    counter!(
        "ak_outbound_url_blocked_total",
        "reason" => reason.to_string(),
        "label" => label.to_string()
    )
    .increment(1);
}

/// Update storage gauge metrics from database stats.
pub fn set_storage_gauge(total_bytes: i64, total_artifacts: i64, total_repos: i64) {
    gauge!("ak_storage_used_bytes").set(total_bytes as f64);
    gauge!("ak_artifacts_total").set(total_artifacts as f64);
    gauge!("ak_repositories_total").set(total_repos as f64);
}

/// Update user count gauge.
pub fn set_user_gauge(total_users: i64) {
    gauge!("ak_users_total").set(total_users as f64);
}

/// Update database connection pool gauge metrics.
pub fn set_db_pool_gauges(pool: &sqlx::PgPool) {
    let size = pool.size() as f64;
    let idle = pool.num_idle() as f64;
    gauge!("ak_db_pool_connections_active").set(size - idle);
    gauge!("ak_db_pool_connections_idle").set(idle);
    gauge!("ak_db_pool_connections_max").set(pool.options().get_max_connections() as f64);
    gauge!("ak_db_pool_connections_size").set(size);
}

/// Record a cleanup operation.
pub fn record_cleanup(cleanup_type: &str, items_removed: u64) {
    counter!("ak_cleanup_items_removed_total", "type" => cleanup_type.to_string())
        .increment(items_removed);
}

/// Record a structured audit-stream delivery failure. `reason` is a bounded
/// internal label (`queue_full`, `writer_disconnected`, or `write_error`) so
/// backpressure and broken stdout delivery are observable without logging back
/// into the same potentially-blocked stream.
pub fn record_audit_stream_failure(reason: &'static str) {
    counter!("ak_audit_stream_failures_total", "reason" => reason).increment(1);
}

/// Record an email dispatch that was dropped by the per-event rate limiter.
/// `reason` is the [`crate::services::email_rate_limiter::RateLimitDecision`]
/// label (`"recipient"` or `"domain"`); the `"allowed"` decision does not
/// trigger this counter. Fix for #1169.
pub fn record_email_dispatch_rate_limited(reason: &str) {
    counter!(
        "email_dispatch_rate_limited_total",
        "reason" => reason.to_string()
    )
    .increment(1);
}

/// Allow-list of event-type strings allowed as a Prometheus label on
/// the email-dispatch counters. Anything outside this set collapses to
/// `"other"` before becoming a label so a future emitter cannot blow up
/// cardinality with a `format!("event.{id}")` string.
const KNOWN_EMAIL_EVENT_TYPES: &[&str] = &[
    "artifact.created",
    "artifact.uploaded",
    "artifact.deleted",
    "scan.completed",
    "scan.failed",
    "repository.created",
    "repository.deleted",
    "license.violation",
    "vulnerability.detected",
];

/// Collapse an arbitrary event-type string to a bounded label set. See
/// [`KNOWN_EMAIL_EVENT_TYPES`] for the contract. Comparison is ASCII
/// case-insensitive so a producer that publishes `"Artifact.Uploaded"`
/// is still recognized and reported under the canonical lowercase
/// label (rather than silently bucketing into `"other"`).
fn bounded_email_event_type(event_type: &str) -> &'static str {
    for known in KNOWN_EMAIL_EVENT_TYPES {
        if known.eq_ignore_ascii_case(event_type) {
            return known;
        }
    }
    "other"
}

/// Record a per-recipient email dispatch attempt (post-limiter,
/// pre-SMTP). Paired with `email_dispatch_rate_limited_total`: the two
/// counters share the per-recipient unit so `attempted + rate_limited`
/// equals total per-recipient tries. `event_type` is collapsed to a
/// bounded allow-list (`KNOWN_EMAIL_EVENT_TYPES`) so a future emitter
/// cannot blow up Prometheus cardinality. Fix for #1172.
pub fn record_email_dispatch_attempted(event_type: &str) {
    counter!(
        "email_dispatch_attempted_total",
        "event_type" => bounded_email_event_type(event_type)
    )
    .increment(1);
}

/// Record a proxy-cache write refused because the fetched body's SHA-256
/// did not match the checksum embedded in a content-addressed path (e.g. an
/// RPM createrepo unique-filename `repodata/<sha256>-primary.xml.gz`).
///
/// This is a `target: "security"`-adjacent signal: a mismatch here means
/// either transport corruption or a dishonest/compromised upstream handed us
/// bytes that do not match the identity the path itself promises. The body
/// is still served to the client; only the cache write is skipped so a bad
/// body is never pinned as "immutable forever".
pub fn record_proxy_cache_checksum_mismatch(repo_key: &str) {
    counter!(
        "ak_proxy_cache_checksum_mismatch_total",
        "repository" => repo_key.to_string()
    )
    .increment(1);
}

/// Record a proxy-cache write skipped because the fetched object exceeded
/// the repository's `quota_bytes` (Phase-1 interim single-object guard for
/// bug artifact-keeper-x70; full per-repo usage accounting is deferred to
/// P4). The body is still served to the client; only the cache write is
/// skipped.
pub fn record_proxy_cache_quota_exceeded(repo_key: &str) {
    counter!(
        "ak_proxy_cache_quota_exceeded_total",
        "repository" => repo_key.to_string()
    )
    .increment(1);
}

/// Why a proxy-cache publish failed (#4319). A bounded label set: the class
/// says which step of the publish refused, not what the error text was.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyCachePublishFailure {
    /// Writing the body to the backend failed: the buffered `put`, or the
    /// streaming `put_stream` into the staging key, for a reason on the
    /// storage side (an upstream error or the per-object ceiling is not
    /// counted, the backend did nothing wrong there).
    PutFailed,
    /// The backend refused the server-side copy from the staging key onto the
    /// live key (the GCS S3-compatible API answering 411 before #3737 was
    /// this class).
    CopyRejected,
    /// The copy reported success but the live key does not hold the staged
    /// bytes: a different size, or the ETag of an empty object (#4630).
    PublishMismatch,
    /// The body landed but the metadata sidecar that commits it could not be
    /// written, so the entry reads as a miss.
    CommitFailed,
}

impl ProxyCachePublishFailure {
    /// The `class` label value.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PutFailed => "put_failed",
            Self::CopyRejected => "copy_rejected",
            Self::PublishMismatch => "publish_mismatch",
            Self::CommitFailed => "commit_failed",
        }
    }
}

/// Record a proxy-cache publish that failed (#4319), labelled by the storage
/// backend the proxy cache runs on and the failure class. The body was still
/// served to the client; only the cache write was lost, so before this a
/// backend that silently refused every cache write showed up in the logs
/// only. Alert on `sum by (backend, class)
/// (rate(ak_proxy_cache_publish_failures_total[5m])) > 0`.
pub fn record_proxy_cache_publish_failure(backend: &'static str, class: ProxyCachePublishFailure) {
    counter!(
        "ak_proxy_cache_publish_failures_total",
        "backend" => backend,
        "class" => class.as_str()
    )
    .increment(1);
}

/// Record a proxy serve that kept a cached body because upstream answered a
/// definitive 404/410 and the repository's `on_upstream_not_found` policy is
/// `keep` (#4640). The counter is the observable signal that a served body no
/// longer exists upstream, so an operator can list (and evict) content that is
/// being kept past its upstream life.
pub fn record_proxy_kept_on_upstream_not_found(repo_key: &str) {
    counter!(
        "ak_proxy_kept_on_upstream_not_found_total",
        "repository" => repo_key.to_string()
    )
    .increment(1);
}

/// Entries and bytes the per-Remote proxy-cache cap evicted (#4660). A
/// steady rate means the cap is smaller than the repository's working set and
/// clients are refetching what it evicts.
pub fn record_proxy_cache_cap_evictions(repo_key: &str, entries: u64, bytes: u64) {
    counter!(
        "ak_proxy_cache_cap_evicted_entries_total",
        "repository" => repo_key.to_string()
    )
    .increment(entries);
    counter!(
        "ak_proxy_cache_cap_evicted_bytes_total",
        "repository" => repo_key.to_string()
    )
    .increment(bytes);
}

/// An eviction run for the per-Remote proxy-cache cap could not get the cache
/// under its cap, so the repository refuses new cache fills for a while
/// (#4660). Any increment needs attention: storage is refusing deletes.
pub fn record_proxy_cache_cap_refusing(repo_key: &str) {
    counter!(
        "ak_proxy_cache_cap_refusing_total",
        "repository" => repo_key.to_string()
    )
    .increment(1);
}

/// Counters recorded while a test ran, as `(name, labels, value)`; read one
/// with [`CounterCapture::get`].
#[cfg(test)]
pub(crate) struct CounterCapture(Vec<CapturedCounter>);

/// One captured counter series: name, labels, value.
#[cfg(test)]
type CapturedCounter = (String, Vec<(String, String)>, u64);

#[cfg(test)]
impl CounterCapture {
    /// The sum of every `name` series whose labels include all of `labels`.
    pub(crate) fn get(&self, name: &str, labels: &[(&str, &str)]) -> u64 {
        self.0
            .iter()
            .filter(|(n, ls, _)| {
                n == name
                    && labels
                        .iter()
                        .all(|(k, v)| ls.iter().any(|(lk, lv)| lk == k && lv == v))
            })
            .map(|(_, _, v)| *v)
            .sum()
    }
}

/// Run `f` against a thread-local debugging recorder and return what it
/// counted. Async work must run inside `f` on a current-thread runtime, so
/// the increments happen on this thread.
#[cfg(test)]
pub(crate) fn capture_counters<R>(f: impl FnOnce() -> R) -> (R, CounterCapture) {
    use metrics_util::debugging::{DebugValue, DebuggingRecorder};
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    let out = metrics::with_local_recorder(&recorder, f);
    let counters = snapshotter
        .snapshot()
        .into_vec()
        .into_iter()
        .filter_map(|(ck, _, _, value)| match value {
            DebugValue::Counter(v) => {
                let key = ck.key();
                Some((
                    key.name().to_string(),
                    key.labels()
                        .map(|l| (l.key().to_string(), l.value().to_string()))
                        .collect(),
                    v,
                ))
            }
            _ => None,
        })
        .collect();
    (out, CounterCapture(counters))
}

/// Run an async test body on a current-thread runtime under
/// [`capture_counters`].
#[cfg(test)]
pub(crate) fn capture_counters_async<F: std::future::Future>(
    f: impl FnOnce() -> F,
) -> (F::Output, CounterCapture) {
    capture_counters(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("current-thread runtime")
            .block_on(f())
    })
}

#[cfg(ak_test_shard = "services-1")]
#[cfg(test)]
mod tests {
    use super::*;

    /// Render what a local recorder built from the production configuration
    /// exports after `record` runs against it. A local recorder, because only
    /// one global recorder may be installed per process.
    fn render_with_production_recorder(record: impl FnOnce()) -> String {
        let recorder = prometheus_builder().build_recorder();
        let handle = recorder.handle();
        metrics::with_local_recorder(&recorder, record);
        handle.render()
    }

    #[test]
    fn test_stale_if_error_counter_is_labelled_by_repo() {
        let out = render_with_production_recorder(|| {
            record_proxy_stale_if_error_response("conda-forge");
            record_proxy_stale_if_error_response("conda-forge");
        });
        assert!(
            out.contains("ak_proxy_stale_if_error_responses_total{repo=\"conda-forge\"} 2"),
            "unexpected exposition: {out}"
        );
    }

    #[test]
    fn test_http_request_duration_exports_as_bucketed_histogram() {
        // #3954: without buckets the latency histogram rendered as a summary
        // (`quantile=` series, no `_bucket`), so no aggregate percentile
        // could be computed across replicas or paths.
        let rendered = render_with_production_recorder(|| {
            histogram!(HTTP_REQUEST_DURATION_METRIC, "method" => "GET", "path" => "/x", "status" => "200")
                .record(0.042);
        });

        assert!(
            rendered.contains("# TYPE ak_http_request_duration_seconds histogram"),
            "expected histogram type line, got:\n{rendered}"
        );
        assert!(
            !rendered.contains("quantile="),
            "summary quantile series must be gone, got:\n{rendered}"
        );
        for le in ["0.005", "0.05", "1", "60", "+Inf"] {
            assert!(
                rendered.contains(&format!("le=\"{le}\"")),
                "missing le={le} bucket, got:\n{rendered}"
            );
        }
        // 0.042 s lands in the 0.05 bucket but not the 0.025 one.
        assert!(rendered.contains(
            "ak_http_request_duration_seconds_bucket{method=\"GET\",path=\"/x\",status=\"200\",le=\"0.05\"} 1"
        ));
        assert!(rendered.contains(
            "ak_http_request_duration_seconds_bucket{method=\"GET\",path=\"/x\",status=\"200\",le=\"0.025\"} 0"
        ));
    }

    #[test]
    fn test_unbucketed_histograms_keep_summary_export() {
        // Buckets are scoped to the HTTP latency metric only; every other
        // histogram keeps its existing exposition shape.
        let rendered = render_with_production_recorder(|| {
            record_artifact_upload("my-repo", "maven", 1024);
        });
        assert!(
            rendered.contains("# TYPE ak_artifact_upload_size_bytes summary"),
            "got:\n{rendered}"
        );
    }

    #[test]
    fn test_http_request_duration_buckets_span_5ms_to_60s_ascending() {
        let b = HTTP_REQUEST_DURATION_BUCKETS;
        assert_eq!(b.first(), Some(&0.005));
        assert_eq!(b.last(), Some(&60.0));
        assert!(b.windows(2).all(|w| w[0] < w[1]));
    }

    /// #4711: the conda counters carry only bounded labels, and a zero
    /// count creates no series.
    #[test]
    fn test_conda_security_counters_record_bounded_labels_4711() {
        let ((), c) = capture_counters(|| {
            for outcome in CONDA_ATTESTATION_OUTCOMES {
                record_conda_attestation("local", outcome);
            }
            record_conda_install_script_findings("local", "post-link", 2);
            record_conda_install_script_findings("local", "pre-link", 0);
            record_conda_allowlist_dropped("virt", "remote-a", 5);
            record_conda_allowlist_dropped("virt", "remote-b", 0);
        });
        for outcome in CONDA_ATTESTATION_OUTCOMES {
            assert_eq!(
                c.get(
                    "ak_conda_attestation_total",
                    &[("repository", "local"), ("outcome", outcome)]
                ),
                1
            );
        }
        assert_eq!(
            c.get(
                "ak_conda_install_script_findings_total",
                &[("repository", "local"), ("kind", "post-link")]
            ),
            2
        );
        assert_eq!(
            c.get(
                "ak_conda_install_script_findings_total",
                &[("kind", "pre-link")]
            ),
            0
        );
        assert_eq!(
            c.get(
                "ak_conda_allowlist_dropped_total",
                &[("repository", "virt"), ("member", "remote-a")]
            ),
            5
        );
        assert_eq!(
            c.get(
                "ak_conda_allowlist_dropped_total",
                &[("member", "remote-b")]
            ),
            0
        );
    }

    /// #4676: auth-failure reasons come from a closed set; message text only
    /// ever selects between them.
    #[test]
    fn test_auth_failure_reason_bucketing_4676() {
        use crate::error::AppError;
        let expired = [
            AppError::Authentication("Invalid token: ExpiredSignature".into()),
            AppError::Authentication("API token expired".into()),
            AppError::Authentication("Assertion has expired".into()),
            AppError::Authentication("CI JWT validation failed: ExpiredSignature".into()),
        ];
        for err in expired {
            assert_eq!(
                AuthFailureReason::for_token_error(&err, AuthFailureReason::InvalidToken),
                AuthFailureReason::Expired,
                "{err}"
            );
        }
        for err in [
            AppError::Authentication("Invalid token: InvalidSignature".into()),
            AppError::Authentication("Invalid or expired SSO state".into()),
            AppError::Unauthorized("Token has been revoked".into()),
        ] {
            assert_eq!(
                AuthFailureReason::for_token_error(&err, AuthFailureReason::InvalidToken),
                AuthFailureReason::InvalidToken,
                "{err}"
            );
        }
        assert_eq!(
            AuthFailureReason::for_login_audit_reason("invalid_password"),
            AuthFailureReason::BadPassword
        );
        assert_eq!(
            AuthFailureReason::for_login_audit_reason("account_locked"),
            AuthFailureReason::Lockout
        );
        for reason in [
            "unknown_or_inactive_user",
            "federated_account",
            "no_password_hash",
        ] {
            assert_eq!(
                AuthFailureReason::for_login_audit_reason(reason),
                AuthFailureReason::UnknownUser
            );
        }
    }

    /// #4676: only a credential or policy refusal counts; an outage or a
    /// malformed request does not.
    #[test]
    fn test_auth_failure_for_error_counts_only_refusals_4676() {
        use crate::error::AppError;
        let ((), c) = capture_counters(|| {
            for err in [
                AppError::Authentication("Invalid token: ExpiredSignature".into()),
                AppError::Unauthorized("Token has been revoked".into()),
                AppError::Authorization("no automatic account creation".into()),
                AppError::Database("connection refused".into()),
                AppError::ServiceUnavailable("at capacity".into()),
                AppError::Validation("Invalid request body".into()),
                AppError::Internal("JWKS fetch failed".into()),
            ] {
                record_auth_failure_for_error(
                    AuthFailureSurface::Sso,
                    &err,
                    AuthFailureReason::Scope,
                );
            }
        });
        assert_eq!(
            c.get(
                "ak_auth_failures_total",
                &[("surface", "sso"), ("reason", "expired")]
            ),
            1
        );
        assert_eq!(
            c.get(
                "ak_auth_failures_total",
                &[("surface", "sso"), ("reason", "scope")]
            ),
            2
        );
        assert_eq!(c.get("ak_auth_failures_total", &[]), 3);
    }

    #[test]
    fn test_record_artifact_upload_does_not_panic() {
        // Metrics macros are no-ops when no recorder is installed.
        record_artifact_upload("my-repo", "maven", 1024);
    }

    #[test]
    fn test_record_artifact_downloads_does_not_panic() {
        record_artifact_downloads("my-repo", "npm", 3);
    }

    #[test]
    fn test_record_age_gate_blocked_request_does_not_panic() {
        record_age_gate_blocked_request("npm-remote", "npm");
        record_age_gate_blocked_request("pypi-remote", "pypi");
    }

    #[test]
    fn test_record_age_gate_filtered_metadata_does_not_panic() {
        record_age_gate_filtered_metadata("npm-remote", "npm");
        record_age_gate_filtered_metadata("pypi-remote", "pypi");
    }

    #[test]
    fn test_record_backup_does_not_panic() {
        record_backup("full", true, 12.5);
        record_backup("incremental", false, 0.3);
    }

    #[test]
    fn test_record_security_scan_does_not_panic() {
        record_security_scan("trivy", true, 5.0);
        record_security_scan("openscap", false, 1.2);
    }

    #[test]
    fn test_record_scanner_health_check_failure_does_not_panic() {
        record_scanner_health_check_failure("trivy", "unreachable");
        record_scanner_health_check_failure("trivy", "unhealthy");
    }

    #[test]
    fn test_record_scan_inventory_failure_does_not_panic() {
        record_scan_inventory_failure("trivy");
        record_scan_inventory_failure("openscap");
    }

    #[test]
    fn test_record_scan_inventory_success_does_not_panic() {
        record_scan_inventory_success("trivy");
        record_scan_inventory_success("openscap");
    }

    #[test]
    fn test_record_webhook_delivery_does_not_panic() {
        record_webhook_delivery("artifact.created", true);
        record_webhook_delivery("artifact.deleted", false);
    }

    #[test]
    fn test_record_outbound_url_blocked_does_not_panic() {
        record_outbound_url_blocked("hostname", "Webhook URL");
        record_outbound_url_blocked("ip", "http-client redirect");
    }

    #[test]
    fn test_record_cleanup_does_not_panic() {
        record_cleanup("temp_files", 42);
    }

    #[test]
    fn test_set_storage_gauge_does_not_panic() {
        set_storage_gauge(1_000_000, 500, 10);
    }

    #[test]
    fn test_set_user_gauge_does_not_panic() {
        set_user_gauge(25);
    }

    #[test]
    fn test_record_webhook_delivery_enqueued_does_not_panic() {
        record_webhook_delivery_enqueued("artifact.uploaded");
    }

    #[test]
    fn test_record_webhook_delivery_enqueue_failed_does_not_panic() {
        record_webhook_delivery_enqueue_failed("artifact.uploaded", "db_error");
    }

    #[test]
    fn test_record_webhook_dead_letter_does_not_panic() {
        record_webhook_dead_letter("artifact.uploaded");
    }

    #[test]
    fn test_record_email_dispatch_rate_limited_does_not_panic() {
        record_email_dispatch_rate_limited("recipient");
        record_email_dispatch_rate_limited("domain");
    }

    #[test]
    fn test_record_email_dispatch_attempted_does_not_panic() {
        record_email_dispatch_attempted("artifact.uploaded");
    }

    #[test]
    fn test_record_proxy_cache_checksum_mismatch_does_not_panic() {
        record_proxy_cache_checksum_mismatch("my-rpm-repo");
    }

    #[test]
    fn test_record_proxy_cache_quota_exceeded_does_not_panic() {
        record_proxy_cache_quota_exceeded("my-rpm-repo");
    }

    #[test]
    fn test_bounded_email_event_type_passes_known() {
        assert_eq!(
            bounded_email_event_type("artifact.uploaded"),
            "artifact.uploaded"
        );
        assert_eq!(bounded_email_event_type("scan.completed"), "scan.completed");
        assert_eq!(
            bounded_email_event_type("vulnerability.detected"),
            "vulnerability.detected"
        );
    }

    #[test]
    fn test_bounded_email_event_type_collapses_unknown_to_other() {
        // High-cardinality input must not become a distinct label.
        assert_eq!(bounded_email_event_type("event.uuid-12345"), "other");
        assert_eq!(bounded_email_event_type(""), "other");
        assert_eq!(bounded_email_event_type("anything.else"), "other");
    }

    #[test]
    fn test_bounded_email_event_type_is_ascii_case_insensitive() {
        // A future emitter publishing `"Artifact.Uploaded"` should still
        // map to the canonical lowercase label, not silently collapse
        // into the "other" bucket.
        assert_eq!(
            bounded_email_event_type("Artifact.Uploaded"),
            "artifact.uploaded"
        );
        assert_eq!(bounded_email_event_type("SCAN.COMPLETED"), "scan.completed");
    }
}
