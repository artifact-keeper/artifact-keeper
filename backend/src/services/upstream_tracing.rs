//! OpenTelemetry `CLIENT` spans for outbound upstream-registry requests (#3954).
//!
//! Every request the proxy service sends to an upstream registry (artifact and
//! metadata fetches, conditional revalidations, the OCI bearer-token exchange
//! and its retry) goes through [`send_upstream`]. It wraps the send in an
//! `otel.kind = "client"` span carrying the stable HTTP client semantic
//! conventions (`http.request.method`, `url.full`, `server.address`,
//! `server.port`, `http.response.status_code`, `error.type`) and injects the
//! W3C `traceparent` (plus `tracestate`) of that span into the request, so the
//! upstream's own spans, if it emits any, join the caller's trace.
//!
//! The span covers the whole `send`: DNS, connect, TLS, any redirects reqwest
//! follows, and the wait for response headers. Body streaming happens after
//! the caller receives the response and is not part of it; for a large blob
//! the span measures time-to-first-byte, not the transfer.
//!
//! Injection is a no-op unless OpenTelemetry export is configured:
//! `crate::telemetry::init_tracing` installs the W3C propagator only on that
//! path, and without it `get_text_map_propagator` is the no-op propagator. The
//! injected trace id is this service's own span context, which only adopts an
//! inbound `traceparent` from a trusted proxy (see
//! `api::middleware::tracing::trust_inbound_trace_context`), so an untrusted
//! caller cannot choose the trace id sent upstream.

use opentelemetry::propagation::Injector;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::{Method, StatusCode, Url};
use tracing::{field::Empty, Instrument, Span};
use tracing_opentelemetry::OpenTelemetrySpanExt;

use crate::services::proxy_service::redact_url_for_diagnostics;

/// Send `request` to an upstream inside a `CLIENT` span, injecting its trace
/// context. Returns exactly what `RequestBuilder::send` would, so each caller
/// keeps its own error mapping.
pub(crate) async fn send_upstream(
    request: reqwest::RequestBuilder,
) -> reqwest::Result<reqwest::Response> {
    let (client, built) = request.build_split();
    let mut request = built?;
    let span = upstream_client_span(request.method(), request.url());
    inject_trace_context(&span, request.headers_mut());

    let result = client.execute(request).instrument(span.clone()).await;
    match &result {
        Ok(response) => record_response_status(&span, response.status()),
        Err(err) => record_transport_error(&span, err),
    }
    result
}

/// Open the `CLIENT` span (`upstream_request`) for one upstream request. The
/// exported OTel span name is the HTTP method (`otel.name`), per the HTTP
/// semantic conventions. `url.full` is redacted (no userinfo, query or
/// fragment), as the semantic conventions require for credentials and as every
/// other upstream diagnostic in this crate does.
pub(crate) fn upstream_client_span(method: &Method, url: &Url) -> Span {
    tracing::info_span!(
        "upstream_request",
        otel.name = %method,
        otel.kind = "client",
        http.request.method = %method,
        url.full = %redact_url_for_diagnostics(url.as_str()),
        server.address = url.host_str().unwrap_or_default(),
        server.port = url.port_or_known_default(),
        http.response.status_code = Empty,
        error.type = Empty,
        otel.status_code = Empty,
    )
}

/// Write `span`'s W3C trace context into `headers` through the globally
/// installed propagator.
pub(crate) fn inject_trace_context(span: &Span, headers: &mut HeaderMap) {
    let cx = span.context();
    opentelemetry::global::get_text_map_propagator(|propagator| {
        propagator.inject_context(&cx, &mut HeaderInjector(headers));
    });
}

/// Whether an upstream response status marks the client span as failed.
///
/// The HTTP semantic conventions say a `CLIENT` span SHOULD be an error for
/// any 4xx or 5xx. `401` is the one exception taken here: an OCI registry
/// answers every first, unauthenticated request with a `401` bearer
/// challenge, which the proxy then satisfies with a token exchange and a
/// retry (each in its own span). Marking that expected step as an error would
/// put an error span in nearly every container-image trace.
pub(crate) fn status_is_error(status: StatusCode) -> bool {
    (status.is_client_error() || status.is_server_error()) && status != StatusCode::UNAUTHORIZED
}

/// Low-cardinality `error.type` for a request that produced no response.
pub(crate) fn transport_error_type(err: &reqwest::Error) -> &'static str {
    if err.is_timeout() {
        "timeout"
    } else if err.is_connect() {
        "connect"
    } else if err.is_redirect() {
        "redirect"
    } else if err.is_builder() {
        "builder"
    } else if err.is_body() || err.is_decode() {
        "body"
    } else if err.is_request() {
        "request"
    } else {
        "_OTHER"
    }
}

fn record_response_status(span: &Span, status: StatusCode) {
    span.record("http.response.status_code", status.as_u16());
    if status_is_error(status) {
        span.record("error.type", status.as_str());
        span.record("otel.status_code", "error");
    }
}

fn record_transport_error(span: &Span, err: &reqwest::Error) {
    span.record("error.type", transport_error_type(err));
    span.record("otel.status_code", "error");
}

/// `Injector` over reqwest's `HeaderMap`. A local impl rather than
/// `opentelemetry_http::HeaderInjector`, matching the extractor in
/// `api::middleware::tracing`, so the backend needs no extra dependency.
struct HeaderInjector<'a>(&'a mut HeaderMap);

impl Injector for HeaderInjector<'_> {
    fn set(&mut self, key: &str, value: String) {
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(key.as_bytes()),
            HeaderValue::from_str(&value),
        ) {
            self.0.insert(name, value);
        }
    }
}

#[cfg(ak_test_shard = "services-2")]
#[cfg(test)]
mod tests {
    use super::*;
    use opentelemetry::trace::TraceContextExt;
    use std::sync::{Arc, Mutex};
    use tracing_subscriber::layer::SubscriberExt;

    const UPSTREAM_SPAN_NAME: &str = "upstream_request";

    fn install_propagator() {
        opentelemetry::global::set_text_map_propagator(
            opentelemetry_sdk::propagation::TraceContextPropagator::new(),
        );
    }

    /// Captured `(field, value)` pairs recorded on `upstream_request` spans,
    /// both at creation and through later `Span::record` calls.
    #[derive(Clone, Default)]
    struct Fields(Arc<Mutex<Vec<(String, String)>>>);

    impl Fields {
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

    impl tracing::field::Visit for Fields {
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

    impl<S> tracing_subscriber::Layer<S> for Fields
    where
        S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
    {
        fn on_new_span(
            &self,
            attrs: &tracing::span::Attributes<'_>,
            _id: &tracing::span::Id,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            if attrs.metadata().name() == UPSTREAM_SPAN_NAME {
                attrs.record(&mut self.clone());
            }
        }
        fn on_record(
            &self,
            id: &tracing::span::Id,
            values: &tracing::span::Record<'_>,
            ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            if ctx.span(id).is_some_and(|s| s.name() == UPSTREAM_SPAN_NAME) {
                values.record(&mut self.clone());
            }
        }
    }

    /// A subscriber with a real `tracing-opentelemetry` layer (so spans have
    /// an OTel context to inject) plus the field capture.
    fn subscriber(fields: &Fields) -> impl tracing::Subscriber + Send + Sync {
        use opentelemetry::trace::TracerProvider as _;
        let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder().build();
        let tracer = provider.tracer("test");
        tracing_subscriber::registry()
            .with(tracing_opentelemetry::layer().with_tracer(tracer))
            .with(fields.clone())
    }

    #[test]
    fn span_carries_http_client_semantic_attributes_with_redacted_url() {
        let fields = Fields::default();
        tracing::subscriber::with_default(subscriber(&fields), || {
            let url = Url::parse("https://user:pw@registry.example:8443/v2/x?token=s").unwrap();
            let _span = upstream_client_span(&Method::HEAD, &url);
        });
        assert_eq!(fields.get("otel.kind").as_deref(), Some("client"));
        assert_eq!(fields.get("otel.name").as_deref(), Some("HEAD"));
        assert_eq!(fields.get("http.request.method").as_deref(), Some("HEAD"));
        assert_eq!(
            fields.get("url.full").as_deref(),
            Some("https://registry.example:8443/v2/x")
        );
        assert_eq!(
            fields.get("server.address").as_deref(),
            Some("registry.example")
        );
        assert_eq!(fields.get("server.port").as_deref(), Some("8443"));
    }

    #[test]
    fn default_port_is_reported_for_scheme_default_urls() {
        let fields = Fields::default();
        tracing::subscriber::with_default(subscriber(&fields), || {
            let url = Url::parse("https://registry.example/v2/").unwrap();
            let _span = upstream_client_span(&Method::GET, &url);
        });
        assert_eq!(fields.get("server.port").as_deref(), Some("443"));
    }

    #[test]
    fn injects_the_span_trace_context_as_traceparent() {
        install_propagator();
        let fields = Fields::default();
        tracing::subscriber::with_default(subscriber(&fields), || {
            let url = Url::parse("https://registry.example/v2/").unwrap();
            let span = upstream_client_span(&Method::GET, &url);
            let mut headers = HeaderMap::new();
            inject_trace_context(&span, &mut headers);

            let sc = span.context().span().span_context().clone();
            let traceparent = headers
                .get("traceparent")
                .expect("traceparent must be injected")
                .to_str()
                .unwrap()
                .to_string();
            assert_eq!(
                traceparent,
                format!("00-{}-{}-01", sc.trace_id(), sc.span_id()),
                "the upstream must be parented to this CLIENT span"
            );
        });
    }

    #[test]
    fn status_classification_follows_client_semconv_except_bearer_challenge() {
        for ok in [200u16, 204, 206, 301, 304] {
            assert!(!status_is_error(StatusCode::from_u16(ok).unwrap()), "{ok}");
        }
        for err in [400u16, 403, 404, 410, 429, 500, 502, 503] {
            assert!(status_is_error(StatusCode::from_u16(err).unwrap()), "{err}");
        }
        assert!(!status_is_error(StatusCode::UNAUTHORIZED));
    }

    #[tokio::test]
    async fn builder_error_is_returned_without_sending() {
        let err = send_upstream(reqwest::Client::new().get("not a url"))
            .await
            .expect_err("an unparseable URL cannot be sent");
        assert!(err.is_builder());
        assert_eq!(transport_error_type(&err), "builder");
    }

    #[tokio::test]
    async fn connect_failure_marks_the_span_failed() {
        // Bind then drop a listener so the port is (almost certainly) closed.
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let fields = Fields::default();
        let _guard = tracing::subscriber::set_default(subscriber(&fields));
        let err = send_upstream(reqwest::Client::new().get(format!("http://127.0.0.1:{port}/")))
            .await
            .expect_err("nothing listens on the port");
        assert_eq!(transport_error_type(&err), "connect");
        assert_eq!(fields.get("error.type").as_deref(), Some("connect"));
        assert_eq!(fields.get("otel.status_code").as_deref(), Some("error"));
    }

    #[tokio::test]
    async fn send_records_status_and_upstream_receives_traceparent() {
        use wiremock::matchers::{header_exists, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        install_propagator();
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/missing"))
            .and(header_exists("traceparent"))
            .respond_with(ResponseTemplate::new(404))
            .expect(1)
            .mount(&server)
            .await;

        let fields = Fields::default();
        let _guard = tracing::subscriber::set_default(subscriber(&fields));
        let response =
            send_upstream(reqwest::Client::new().get(format!("{}/missing", server.uri())))
                .await
                .expect("the mock answers");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            fields.get("http.response.status_code").as_deref(),
            Some("404")
        );
        assert_eq!(fields.get("error.type").as_deref(), Some("404"));
        assert_eq!(fields.get("otel.status_code").as_deref(), Some("error"));
        server.verify().await;
    }

    #[tokio::test]
    async fn successful_send_leaves_status_unset() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let fields = Fields::default();
        let _guard = tracing::subscriber::set_default(subscriber(&fields));
        send_upstream(reqwest::Client::new().get(server.uri()))
            .await
            .expect("the mock answers");
        assert_eq!(
            fields.get("http.response.status_code").as_deref(),
            Some("200")
        );
        assert_eq!(fields.get("otel.status_code"), None);
        assert_eq!(fields.get("error.type"), None);
    }
}
