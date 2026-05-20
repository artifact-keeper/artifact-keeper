//! Prometheus metrics collection for business-level events.
//!
//! HTTP request instrumentation lives in `crate::api::middleware::metrics`.
//! This module provides helpers for recording domain-specific metrics such as
//! artifact uploads/downloads, security scans, backups, and storage gauges.

use metrics::{counter, gauge, histogram};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};

/// Initialize the Prometheus metrics recorder and return the handle for rendering.
pub fn init_metrics() -> PrometheusHandle {
    let builder = PrometheusBuilder::new();
    builder
        .install_recorder()
        .expect("failed to install Prometheus recorder")
}

/// Record an artifact upload event.
pub fn record_artifact_upload(repo_key: &str, format: &str, size_bytes: u64) {
    counter!("ak_artifact_uploads_total", "repository" => repo_key.to_string(), "format" => format.to_string()).increment(1);
    histogram!("ak_artifact_upload_size_bytes", "format" => format.to_string())
        .record(size_bytes as f64);
}

/// Record an artifact download event.
pub fn record_artifact_download(repo_key: &str, format: &str) {
    counter!("ak_artifact_downloads_total", "repository" => repo_key.to_string(), "format" => format.to_string()).increment(1);
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
pub fn record_proxy_cache_lookup(repo_key: &str, result: &str) {
    counter!(
        "ak_proxy_cache_lookups_total",
        "repository" => repo_key.to_string(),
        "result" => result.to_string()
    )
    .increment(1);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prometheus_builder_can_be_created() {
        // Verify that PrometheusBuilder::new() compiles and runs. We cannot
        // call install_recorder() in tests because only one global recorder
        // is allowed per process.
        let _builder = PrometheusBuilder::new();
    }

    #[test]
    fn test_record_artifact_upload_does_not_panic() {
        // Metrics macros are no-ops when no recorder is installed.
        record_artifact_upload("my-repo", "maven", 1024);
    }

    #[test]
    fn test_record_artifact_download_does_not_panic() {
        record_artifact_download("my-repo", "npm");
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
