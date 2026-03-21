//! Prometheus metrics middleware.
//!
//! Records per-request counters, histograms, and in-flight gauges using the
//! `metrics` crate. Path labels are taken from axum's `MatchedPath` when
//! available, which gives the route pattern (e.g. `/api/v1/repositories/:key`)
//! instead of the concrete URL. This avoids high-cardinality label explosion.
//! When no matched path is available (404s, fallback routes), the raw path is
//! normalized by replacing UUIDs and numeric segments with `:id`.

use std::time::Instant;

use axum::{
    extract::{MatchedPath, Request},
    middleware::Next,
    response::Response,
};
use metrics::{counter, gauge, histogram};

/// Axum middleware that records HTTP request metrics.
///
/// Emits the following metrics (all prefixed with `ak_`):
///
/// - `ak_http_requests_total` (counter): incremented when a request arrives.
///   Labels: `method`, `path`.
/// - `ak_http_responses_total` (counter): incremented after the response is
///   produced. Labels: `method`, `path`, `status`.
/// - `ak_http_request_duration_seconds` (histogram): request latency in
///   seconds. Labels: `method`, `path`, `status`.
/// - `ak_http_requests_in_flight` (gauge): number of requests currently being
///   processed. Labels: `method`, `path`.
pub async fn metrics_middleware(request: Request, next: Next) -> Response {
    let method = request.method().to_string();

    // Prefer the matched route pattern for low-cardinality labels.
    let path = request
        .extensions()
        .get::<MatchedPath>()
        .map(|mp| mp.as_str().to_owned())
        .unwrap_or_else(|| normalize_path(request.uri().path()));

    let start = Instant::now();

    counter!("ak_http_requests_total", "method" => method.clone(), "path" => path.clone())
        .increment(1);
    gauge!("ak_http_requests_in_flight", "method" => method.clone(), "path" => path.clone())
        .increment(1.0);

    let response = next.run(request).await;

    let duration = start.elapsed().as_secs_f64();
    let status = response.status().as_u16().to_string();

    histogram!(
        "ak_http_request_duration_seconds",
        "method" => method.clone(),
        "path" => path.clone(),
        "status" => status.clone(),
    )
    .record(duration);
    counter!(
        "ak_http_responses_total",
        "method" => method.clone(),
        "path" => path.clone(),
        "status" => status,
    )
    .increment(1);
    gauge!("ak_http_requests_in_flight", "method" => method, "path" => path).decrement(1.0);

    response
}

/// Normalize URL paths to reduce label cardinality when `MatchedPath` is
/// unavailable. Replaces UUID-shaped segments and bare numeric segments
/// with `:id`.
fn normalize_path(path: &str) -> String {
    let segments: Vec<&str> = path.split('/').collect();
    let normalized: Vec<String> = segments
        .iter()
        .map(|seg| {
            if seg.len() == 36 && seg.chars().filter(|c| *c == '-').count() == 4 {
                // UUID pattern (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)
                ":id".to_string()
            } else if !seg.is_empty() && seg.parse::<i64>().is_ok() {
                // Numeric ID
                ":id".to_string()
            } else {
                seg.to_string()
            }
        })
        .collect();
    normalized.join("/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, middleware, routing::get, Router};
    use tower::ServiceExt;

    async fn test_handler() -> &'static str {
        "OK"
    }

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

    #[test]
    fn test_normalize_path_multiple_ids() {
        let path = "/api/v1/repos/42/artifacts/550e8400-e29b-41d4-a716-446655440000";
        let result = normalize_path(path);
        assert_eq!(result, "/api/v1/repos/:id/artifacts/:id");
    }

    #[test]
    fn test_normalize_path_root() {
        assert_eq!(normalize_path("/"), "/");
    }

    #[test]
    fn test_normalize_path_empty() {
        assert_eq!(normalize_path(""), "");
    }

    #[test]
    fn test_normalize_path_preserves_named_segments() {
        let path = "/api/v1/repositories/my-repo/artifacts/my-package";
        let result = normalize_path(path);
        assert_eq!(result, "/api/v1/repositories/my-repo/artifacts/my-package");
    }

    #[test]
    fn test_normalize_path_negative_number_treated_as_id() {
        let path = "/api/v1/items/-5";
        let result = normalize_path(path);
        assert_eq!(result, "/api/v1/items/:id");
    }

    #[tokio::test]
    async fn test_middleware_returns_response() {
        // Install a no-op recorder so the metrics macros don't panic when no
        // global recorder is set. In production, init_metrics() sets one up.
        let _ = metrics::NoopRecorder;

        let app = Router::new()
            .route("/test", get(test_handler))
            .layer(middleware::from_fn(metrics_middleware));

        let request = Request::builder().uri("/test").body(Body::empty()).unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
    }

    #[tokio::test]
    async fn test_middleware_handles_not_found() {
        let app = Router::new()
            .route("/exists", get(test_handler))
            .layer(middleware::from_fn(metrics_middleware));

        let request = Request::builder()
            .uri("/does-not-exist")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::NOT_FOUND);
    }
}
