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
//! middleware) both recorders are no-ops.
//!
//! The two recorders do not write to the span directly. They keep the latest
//! value in that task-local, and [`with_request_span`] records each field ONCE,
//! when the request future completes. The OTel SDK appends every
//! `set_attribute`, so recording on each call would export duplicate keys (a
//! virtual repository probing several members looks the cache up several
//! times, and the OCI resolver can run more than once), and the stdout log
//! formatter would show every value in turn. Recording once makes "the last
//! value wins" hold for both. The price: log lines emitted while the handler
//! runs do not show these two fields, and a request cancelled mid-flight (a
//! client disconnect) records neither.
//!
//! The phase spans that pair with these (`authenticate`,
//! `resolve_virtual_members`, `proxy_fetch`) are INFO, like the storage spans.
//! DEBUG would not keep them off the default stdout output (the default filter
//! is `artifact_keeper_backend=debug`), and because the `EnvFilter` is global
//! it WOULD drop them from exported traces on any deployment that sets
//! `RUST_LOG=info`, which defeats their purpose.

use axum::body::HttpBody;
use axum::http::{header::CONTENT_LENGTH, Response, StatusCode};
use std::cell::{Cell, RefCell};
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

/// The request-class values recorded so far for the request in flight.
#[derive(Default)]
struct RequestAttributes {
    repository_key: RefCell<Option<String>>,
    cache_outcome: Cell<Option<&'static str>>,
}

tokio::task_local! {
    static REQUEST_ATTRIBUTES: RequestAttributes;
}

/// Run `fut` with [`record_repository_key`] / [`record_cache_outcome`] in
/// effect, then record the latest value of each onto `span` (once each).
pub async fn with_request_span<F: std::future::Future>(span: Span, fut: F) -> F::Output {
    let (output, repository_key, cache_outcome) = REQUEST_ATTRIBUTES
        .scope(RequestAttributes::default(), async {
            let output = fut.await;
            let (key, outcome) = REQUEST_ATTRIBUTES
                .with(|attrs| (attrs.repository_key.take(), attrs.cache_outcome.get()));
            (output, key, outcome)
        })
        .await;
    if let Some(key) = repository_key {
        span.record(REPOSITORY_KEY_FIELD, key.as_str());
    }
    if let Some(outcome) = cache_outcome {
        span.record(CACHE_OUTCOME_FIELD, outcome);
    }
    output
}

/// Record the key of the repository this request resolved to. Call it only
/// once the key names an existing repository, so the attribute never carries
/// an arbitrary caller-typed string.
pub fn record_repository_key(key: &str) {
    let _ = REQUEST_ATTRIBUTES.try_with(|attrs| {
        *attrs.repository_key.borrow_mut() = Some(key.to_string());
    });
}

/// Record the proxy-cache outcome of this request. `outcome` is one of the
/// fixed `ak_proxy_cache_lookups_total` `result` values, or `hit` / `miss` /
/// `negative_hit` from the streaming cache probe.
pub fn record_cache_outcome(outcome: &'static str) {
    let _ = REQUEST_ATTRIBUTES.try_with(|attrs| attrs.cache_outcome.set(Some(outcome)));
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
    // Recorded as i64: `tracing-opentelemetry` exports a u64 field as a
    // string, and both attributes are integers in the semantic conventions.
    span.record(HTTP_STATUS_FIELD, i64::from(status.as_u16()));
    if let Some(size) = response_body_size(response).and_then(|s| i64::try_from(s).ok()) {
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
    use crate::testing::otel::{attr, otel_subscriber, ExportedSpans, SpanFields};
    use axum::body::Body;
    use opentelemetry::trace::Status;
    use opentelemetry::Value;
    use tracing_subscriber::layer::SubscriberExt;

    const REQUEST_SPAN_NAME: &str = "http_request";

    /// The real `http_request` span, so a field this module records but the
    /// span builder forgot to declare (a silent no-op in `tracing`) fails here.
    fn request_span() -> Span {
        let request = axum::http::Request::builder().uri("/x").body(()).unwrap();
        crate::api::middleware::tracing::make_http_request_span(&request, &[])
    }

    /// Both views of the request span: its raw `tracing` fields, and the OTel
    /// span `tracing-opentelemetry` exports once it ends.
    fn subscriber(
        fields: &SpanFields,
        exported: &ExportedSpans,
    ) -> impl tracing::Subscriber + Send + Sync {
        otel_subscriber(exported).with(fields.clone())
    }

    fn capture<T>(f: impl FnOnce() -> T) -> (T, SpanFields, ExportedSpans) {
        let fields = SpanFields::new(REQUEST_SPAN_NAME);
        let exported = ExportedSpans::default();
        let out = tracing::subscriber::with_default(subscriber(&fields, &exported), f);
        (out, fields, exported)
    }

    #[test]
    fn records_status_and_content_length_without_error_on_success() {
        let (_, rec, exported) = capture(|| {
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
        // What the trace backend receives.
        let span = exported.one(REQUEST_SPAN_NAME);
        assert_eq!(span.span_kind, opentelemetry::trace::SpanKind::Server);
        assert_eq!(span.status, Status::Unset);
        assert_eq!(attr(&span, HTTP_STATUS_FIELD), Some(Value::I64(200)));
        assert_eq!(attr(&span, HTTP_BODY_SIZE_FIELD), Some(Value::I64(42)));
    }

    #[test]
    fn body_size_falls_back_to_the_exact_size_hint() {
        let (_, rec, _) = capture(|| {
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
        let (_, rec, _) = capture(|| {
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
        let (_, rec, exported) = capture(|| {
            let span = request_span();
            let response = Response::builder().status(503).body(Body::empty()).unwrap();
            RecordResponseOnSpan::default().on_response(&response, Duration::from_millis(3), &span);
        });
        assert_eq!(rec.get(HTTP_STATUS_FIELD).as_deref(), Some("503"));
        assert_eq!(rec.get("error.type").as_deref(), Some("503"));
        assert_eq!(rec.get("otel.status_code").as_deref(), Some("error"));
        let span = exported.one(REQUEST_SPAN_NAME);
        assert!(
            matches!(span.status, Status::Error { .. }),
            "{:?}",
            span.status
        );
        assert_eq!(attr(&span, HTTP_STATUS_FIELD), Some(Value::I64(503)));
        assert_eq!(attr(&span, "error.type"), Some(Value::from("503")));
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
        let (_, rec, exported) = capture(|| {
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
        // Last write wins, and the exported span carries each key ONCE (the
        // SDK appends every `set_attribute`, so recording per call would
        // export `miss_expired` and `hit` side by side).
        assert_eq!(rec.get(CACHE_OUTCOME_FIELD).as_deref(), Some("hit"));
        let span = exported.one(REQUEST_SPAN_NAME);
        let outcomes: Vec<_> = span
            .attributes
            .iter()
            .filter(|kv| kv.key.as_str() == CACHE_OUTCOME_FIELD)
            .map(|kv| kv.value.clone())
            .collect();
        assert_eq!(outcomes, vec![Value::from("hit")]);
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

        let rec = SpanFields::new(REQUEST_SPAN_NAME);
        let exported = ExportedSpans::default();
        let _guard = tracing::subscriber::set_default(subscriber(&rec, &exported));
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
        let span = exported.one(REQUEST_SPAN_NAME);
        assert_eq!(
            attr(&span, HTTP_ROUTE_FIELD),
            Some(Value::from("/maven/:repo/*path"))
        );
        assert_eq!(
            attr(&span, REPOSITORY_KEY_FIELD),
            Some(Value::from("maven-central"))
        );
    }

    /// The production call site: the proxy-cache metric recorder also tags
    /// the request span, and the exported span carries it.
    #[test]
    fn proxy_cache_metric_records_the_outcome_on_the_request_span() {
        let (_, _, exported) = capture(|| {
            let rt = tokio::runtime::Builder::new_current_thread()
                .build()
                .unwrap();
            rt.block_on(with_request_span(request_span(), async {
                crate::services::metrics_service::record_proxy_cache_lookup(
                    "npm-remote",
                    "miss_expired",
                );
            }));
        });
        let span = exported.one(REQUEST_SPAN_NAME);
        assert_eq!(
            attr(&span, CACHE_OUTCOME_FIELD),
            Some(Value::from("miss_expired"))
        );
    }

    #[test]
    fn deep_recorders_are_noops_outside_a_request_scope() {
        let (_, rec, _) = capture(|| {
            let _span = request_span().entered();
            record_repository_key("npm-remote");
            record_cache_outcome("hit");
        });
        assert_eq!(rec.get(REPOSITORY_KEY_FIELD), None);
        assert_eq!(rec.get(CACHE_OUTCOME_FIELD), None);
    }
}
