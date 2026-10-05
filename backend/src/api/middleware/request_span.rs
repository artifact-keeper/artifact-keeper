//! Request-class attributes on the `http_request` root span (#3954 §4, #4455).
//!
//! The `http_request` span (built by
//! [`make_http_request_span`](super::tracing::make_http_request_span)) used to
//! carry only the method, the redacted URI and the correlation ID, so a trace
//! could not be filtered to a request class ("traces for repository X", "cache
//! expired"). This module fills in the rest:
//!
//! * `http.route`: the matched route pattern (the same value the
//!   `ak_http_request_duration_seconds` `path` label uses), recorded by
//!   `correlation_id_middleware`, which runs after routing;
//! * `http.response.status_code` and `http.response.body.size`, recorded by
//!   [`RecordResponseOnSpan`], the `TraceLayer` `on_response` hook. A 5xx also
//!   sets `error.type` and the error status, per the HTTP server semantic
//!   conventions (a 4xx is the client's error, not the server span's);
//! * `artifact_keeper.repository.key` and `artifact_keeper.cache.outcome`,
//!   recorded from deep inside the request (the repository-visibility
//!   middleware, the OCI resolver, the proxy cache) through
//!   [`record_repository_key`] / [`record_cache_outcome`].
//!
//! The last two are span attributes ONLY, never metric labels: spans are
//! sampled, metrics are not, and #2220 bounded metric-label cardinality.
//!
//! Deep code cannot reach the root span through `Span::current()` (that is the
//! innermost span, and recording a field a span does not declare is a no-op),
//! so `correlation_id_middleware` scopes a handle to it as a task-local for the
//! request future, the same way it scopes the correlation ID (#2414). Outside
//! that scope (background jobs, detached tasks, unit tests without the
//! middleware) both recorders are no-ops. When a request records a field more
//! than once (a virtual repository probing several members), the last value
//! wins.

use axum::body::HttpBody;
use axum::http::{header::CONTENT_LENGTH, Response, StatusCode};
use std::time::Duration;
use tower_http::trace::{DefaultOnResponse, OnResponse};
use tracing::Span;

/// `http.route` on the root span.
pub const HTTP_ROUTE_FIELD: &str = "http.route";
/// `http.response.status_code` on the root span.
pub const HTTP_STATUS_FIELD: &str = "http.response.status_code";
/// `http.response.body.size` on the root span, when the size is known up front.
pub const HTTP_BODY_SIZE_FIELD: &str = "http.response.body.size";
/// The repository the request addressed, once it resolved to a real row.
pub const REPOSITORY_KEY_FIELD: &str = "artifact_keeper.repository.key";
/// The proxy-cache outcome of the request (`hit`, `miss_expired`, ...).
pub const CACHE_OUTCOME_FIELD: &str = "artifact_keeper.cache.outcome";

tokio::task_local! {
    /// The `http_request` span of the request currently being handled.
    static REQUEST_SPAN: Span;
}

/// Run `fut` with [`record_repository_key`] / [`record_cache_outcome`]
/// recording onto `span`.
pub async fn with_request_span<F: std::future::Future>(span: Span, fut: F) -> F::Output {
    REQUEST_SPAN.scope(span, fut).await
}

fn record_on_request_span(field: &str, value: &str) {
    let _ = REQUEST_SPAN.try_with(|span| {
        span.record(field, value);
    });
}

/// Record the key of the repository this request resolved to. Call it only
/// once the key names an existing repository, so the attribute never carries
/// an arbitrary caller-typed string.
pub fn record_repository_key(key: &str) {
    record_on_request_span(REPOSITORY_KEY_FIELD, key);
}

/// Record the proxy-cache outcome of this request. `outcome` is one of the
/// fixed `ak_proxy_cache_lookups_total` `result` values, or `hit` / `miss` /
/// `negative_hit` from the streaming cache probe.
pub fn record_cache_outcome(outcome: &'static str) {
    record_on_request_span(CACHE_OUTCOME_FIELD, outcome);
}

/// The response body size to report: the `Content-Length` header when present
/// and valid, else the body's exact size hint. `None` for a streamed body of
/// unknown length, which then leaves the attribute unset.
fn response_body_size<B: HttpBody>(response: &Response<B>) -> Option<u64> {
    response
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<u64>().ok())
        .or_else(|| response.body().size_hint().exact())
}

/// Record the response attributes of `response` onto the root `span`.
pub fn record_http_response<B: HttpBody>(span: &Span, response: &Response<B>) {
    let status = response.status();
    span.record(HTTP_STATUS_FIELD, status.as_u16());
    if let Some(size) = response_body_size(response) {
        span.record(HTTP_BODY_SIZE_FIELD, size);
    }
    if server_span_is_error(status) {
        span.record("error.type", status.as_str());
        span.record("otel.status_code", "error");
    }
}

/// Whether a response status marks a `SERVER` span as failed. Per the HTTP
/// semantic conventions only a 5xx does: a 4xx is the caller's error and the
/// server handled it correctly.
fn server_span_is_error(status: StatusCode) -> bool {
    status.is_server_error()
}

/// `TraceLayer` `on_response` hook: records the response attributes onto the
/// `http_request` span, then does exactly what the default hook did (the
/// DEBUG "finished processing request" event).
#[derive(Clone, Debug, Default)]
pub struct RecordResponseOnSpan {
    inner: DefaultOnResponse,
}

impl<B: HttpBody> OnResponse<B> for RecordResponseOnSpan {
    fn on_response(self, response: &Response<B>, latency: Duration, span: &Span) {
        record_http_response(span, response);
        self.inner.on_response(response, latency, span);
    }
}

#[cfg(ak_test_shard = "services-2")]
#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use std::sync::{Arc, Mutex};
    use tracing_subscriber::layer::SubscriberExt;

    /// `(field, value)` pairs recorded on the `http_request` test span.
    #[derive(Clone, Default)]
    struct Recorded(Arc<Mutex<Vec<(String, String)>>>);

    impl Recorded {
        fn get(&self, name: &str) -> Option<String> {
            self.0
                .lock()
                .unwrap()
                .iter()
                .rev()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.clone())
        }
    }

    impl tracing::field::Visit for Recorded {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            self.0
                .lock()
                .unwrap()
                .push((field.name().to_string(), format!("{value:?}")));
        }
        fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
            self.0
                .lock()
                .unwrap()
                .push((field.name().to_string(), value.to_string()));
        }
    }

    impl<S> tracing_subscriber::Layer<S> for Recorded
    where
        S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
    {
        fn on_record(
            &self,
            id: &tracing::span::Id,
            values: &tracing::span::Record<'_>,
            ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            if ctx.span(id).is_some_and(|s| s.name() == "http_request") {
                values.record(&mut self.clone());
            }
        }
    }

    /// The real `http_request` span, so a field this module records but the
    /// span builder forgot to declare (a silent no-op in `tracing`) fails here.
    fn request_span() -> Span {
        let request = axum::http::Request::builder().uri("/x").body(()).unwrap();
        crate::api::middleware::tracing::make_http_request_span(&request, &[])
    }

    fn capture<T>(f: impl FnOnce() -> T) -> (T, Recorded) {
        let recorded = Recorded::default();
        let subscriber = tracing_subscriber::registry().with(recorded.clone());
        let out = tracing::subscriber::with_default(subscriber, f);
        (out, recorded)
    }

    #[test]
    fn records_status_and_content_length_without_error_on_success() {
        let (_, rec) = capture(|| {
            let span = request_span();
            let response = Response::builder()
                .status(200)
                .header(CONTENT_LENGTH, "42")
                .body(Body::empty())
                .unwrap();
            record_http_response(&span, &response);
        });
        assert_eq!(rec.get(HTTP_STATUS_FIELD).as_deref(), Some("200"));
        assert_eq!(rec.get(HTTP_BODY_SIZE_FIELD).as_deref(), Some("42"));
        assert_eq!(rec.get("otel.status_code"), None);
        assert_eq!(rec.get("error.type"), None);
    }

    #[test]
    fn body_size_falls_back_to_the_exact_size_hint() {
        let (_, rec) = capture(|| {
            let span = request_span();
            let response = Response::builder()
                .status(404)
                .body(Body::from("not here"))
                .unwrap();
            record_http_response(&span, &response);
        });
        assert_eq!(rec.get(HTTP_STATUS_FIELD).as_deref(), Some("404"));
        assert_eq!(rec.get(HTTP_BODY_SIZE_FIELD).as_deref(), Some("8"));
        // A 4xx is the caller's error, not the server span's.
        assert_eq!(rec.get("otel.status_code"), None);
    }

    #[test]
    fn unknown_body_size_leaves_the_attribute_unset() {
        let (_, rec) = capture(|| {
            let span = request_span();
            let stream = futures::stream::iter(vec![Ok::<_, std::io::Error>(
                bytes::Bytes::from_static(b"chunk"),
            )]);
            let response = Response::builder()
                .status(200)
                .header(CONTENT_LENGTH, "not-a-number")
                .body(Body::from_stream(stream))
                .unwrap();
            record_http_response(&span, &response);
        });
        assert_eq!(rec.get(HTTP_STATUS_FIELD).as_deref(), Some("200"));
        assert_eq!(rec.get(HTTP_BODY_SIZE_FIELD), None);
    }

    #[test]
    fn server_error_marks_the_span_failed() {
        let (_, rec) = capture(|| {
            let span = request_span();
            let response = Response::builder().status(503).body(Body::empty()).unwrap();
            RecordResponseOnSpan::default().on_response(&response, Duration::from_millis(3), &span);
        });
        assert_eq!(rec.get(HTTP_STATUS_FIELD).as_deref(), Some("503"));
        assert_eq!(rec.get("error.type").as_deref(), Some("503"));
        assert_eq!(rec.get("otel.status_code").as_deref(), Some("error"));
    }

    #[test]
    fn only_5xx_is_a_server_span_error() {
        assert!(!server_span_is_error(StatusCode::OK));
        assert!(!server_span_is_error(StatusCode::UNAUTHORIZED));
        assert!(!server_span_is_error(StatusCode::NOT_FOUND));
        assert!(server_span_is_error(StatusCode::INTERNAL_SERVER_ERROR));
        assert!(server_span_is_error(StatusCode::BAD_GATEWAY));
    }

    #[test]
    fn deep_recorders_write_to_the_scoped_request_span() {
        let (_, rec) = capture(|| {
            let span = request_span();
            let rt = tokio::runtime::Builder::new_current_thread()
                .build()
                .unwrap();
            rt.block_on(with_request_span(span.clone(), async {
                // A child span is current, as it would be in a handler.
                let _child = tracing::info_span!("handler").entered();
                record_repository_key("npm-remote");
                record_cache_outcome("miss_expired");
                record_cache_outcome("hit");
            }));
        });
        assert_eq!(rec.get(REPOSITORY_KEY_FIELD).as_deref(), Some("npm-remote"));
        // Last write wins.
        assert_eq!(rec.get(CACHE_OUTCOME_FIELD).as_deref(), Some("hit"));
    }

    /// End to end through `correlation_id_middleware`: it records the matched
    /// route and scopes the request span so a handler's recorder reaches it.
    #[tokio::test(flavor = "current_thread")]
    async fn correlation_middleware_records_route_and_scopes_the_span() {
        use axum::{middleware, routing::get, Router};
        use tower::ServiceExt;
        use tracing::Instrument;

        async fn handler() -> &'static str {
            record_repository_key("maven-central");
            "ok"
        }

        let rec = Recorded::default();
        let _guard =
            tracing::subscriber::set_default(tracing_subscriber::registry().with(rec.clone()));
        let app = Router::new()
            .route("/maven/:repo/*path", get(handler))
            .layer(middleware::from_fn(
                crate::api::middleware::tracing::correlation_id_middleware,
            ));
        let request = axum::http::Request::builder()
            .uri("/maven/maven-central/org/x/1.0/x-1.0.jar")
            .body(Body::empty())
            .unwrap();
        let response = app
            .oneshot(request)
            .instrument(request_span())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            rec.get(HTTP_ROUTE_FIELD).as_deref(),
            Some("/maven/:repo/*path")
        );
        assert_eq!(
            rec.get(REPOSITORY_KEY_FIELD).as_deref(),
            Some("maven-central")
        );
    }

    #[test]
    fn deep_recorders_are_noops_outside_a_request_scope() {
        let (_, rec) = capture(|| {
            let _span = request_span().entered();
            record_repository_key("npm-remote");
            record_cache_outcome("hit");
        });
        assert_eq!(rec.get(REPOSITORY_KEY_FIELD), None);
        assert_eq!(rec.get(CACHE_OUTCOME_FIELD), None);
    }
}
