//! Prometheus metrics collection and HTTP request instrumentation.

use metrics::{counter, gauge, histogram};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use std::time::Instant;

use axum::{
    body::Body,
    http::{Request, Response},
    middleware::Next,
};

/// Initialize the Prometheus metrics recorder and return the handle for rendering.
pub fn init_metrics() -> PrometheusHandle {
    let builder = PrometheusBuilder::new();
    builder
        .install_recorder()
        .expect("failed to install Prometheus recorder")
}

/// Axum middleware that records HTTP request metrics.
pub async fn metrics_middleware(request: Request<Body>, next: Next) -> Response<Body> {
    let method = request.method().clone().to_string();
    let path = request.uri().path().to_string();
    // Normalize path to avoid high-cardinality labels (strip UUIDs and IDs)
    let normalized = normalize_path(&path);

    let start = Instant::now();
    counter!("ak_http_requests_total", "method" => method.clone(), "path" => normalized.clone())
        .increment(1);
    gauge!("ak_http_requests_in_flight", "method" => method.clone(), "path" => normalized.clone())
        .increment(1.0);

    let response = next.run(request).await;

    let duration = start.elapsed().as_secs_f64();
    let status = response.status().as_u16().to_string();

    histogram!("ak_http_request_duration_seconds", "method" => method.clone(), "path" => normalized.clone(), "status" => status.clone()).record(duration);
    counter!("ak_http_responses_total", "method" => method.clone(), "path" => normalized.clone(), "status" => status).increment(1);
    gauge!("ak_http_requests_in_flight", "method" => method, "path" => normalized).decrement(1.0);

    response
}

/// Normalize URL paths to reduce label cardinality.
/// Replaces UUIDs, numeric IDs, and package versions with placeholders.
fn normalize_path(path: &str) -> String {
    let segments: Vec<&str> = path.split('/').collect();
    let normalized: Vec<String> = segments
        .iter()
        .map(|seg| {
            if seg.len() == 36 && seg.chars().filter(|c| *c == '-').count() == 4 {
                // UUID pattern
                ":id".to_string()
            } else if seg.parse::<i64>().is_ok() && seg.len() > 0 {
                // Numeric ID
                ":id".to_string()
            } else {
                seg.to_string()
            }
        })
        .collect();
    normalized.join("/")
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

/// Record a webhook delivery event.
pub fn record_webhook_delivery(event: &str, success: bool) {
    let status = if success { "success" } else { "failure" };
    counter!("ak_webhook_deliveries_total", "event" => event.to_string(), "status" => status.to_string()).increment(1);
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

/// Record a cleanup operation.
pub fn record_cleanup(cleanup_type: &str, items_removed: u64) {
    counter!("ak_cleanup_items_removed_total", "type" => cleanup_type.to_string())
        .increment(items_removed);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_path_uuid() {
        let path = "/api/v1/repositories/550e8400-e29b-41d4-a716-446655440000/artifacts";
        let result = normalize_path(path);
        assert_eq!(result, "/api/v1/repositories/:id/artifacts");
    }

    #[test]
    fn test_normalize_path_numeric() {
        let path = "/api/v1/users/123";
        let result = normalize_path(path);
        assert_eq!(result, "/api/v1/users/:id");
    }

    #[test]
    fn test_normalize_path_no_change() {
        let path = "/api/v1/health";
        let result = normalize_path(path);
        assert_eq!(result, "/api/v1/health");
    }
}
