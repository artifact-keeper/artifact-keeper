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
}
