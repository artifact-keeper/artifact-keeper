//! OpenTelemetry `CLIENT` spans for outbound upstream-registry requests (#3954).
//!
//! Every upstream request made by `services::proxy_service` (artifact and
//! metadata fetches, conditional revalidations, the OCI bearer-token exchange
//! and its retry) goes through [`send_upstream`], and so do the upstream calls
//! made outside it (#4455): the PyPI JSON publish-time lookup
//! (`services::upstream_metadata`), the npm change-feed consumer
//! (`services::upstream_feed`), the npm audit and `/-/` meta passthroughs, the
//! Go sumdb proxy, and the AWS token exchange in
//! `services::aws_upstream_auth` (its SigV4 signature does not cover the
//! injected headers, which are added after signing). Three upstream callers
//! off the request proxy path still use a bare `.send()` and are follow-ups on
//! #3954: the repository "test upstream" check (`api::handlers::repositories`),
//! the curation sync cycle (`services::scheduler_service`) and the popularity
//! source (`services::curation::popularity_source`). It wraps the send in an
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
//! path, and without it `get_text_map_propagator` is the no-op propagator.
//!
//! What is injected is this service's own span context, and it inherits
//! whatever inbound trace context the `http_request` span adopted (see
//! `api::middleware::tracing::trust_inbound_trace_context`). With
//! `RATE_LIMIT_TRUSTED_PROXY_CIDRS` configured, only a listed proxy's
//! `traceparent` is adopted. With the list EMPTY (the default) any client's
//! `traceparent` is adopted, so on an OTLP-enabled deployment a client can
//! choose the trace id, and its `tracestate` entries, that are forwarded to
//! third-party upstreams. Both are validated by the propagator and by
//! `HeaderValue`, so this is not a header-injection vector, but operators who
//! do not want caller-chosen trace context relayed upstream should set the
//! trusted-proxy list. Making upstream injection itself opt-in is a possible
//! follow-up on #3954.

use opentelemetry::propagation::Injector;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, AUTHORIZATION};
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
    let had_auth = request.headers().contains_key(AUTHORIZATION);
    let span = upstream_client_span(request.method(), request.url());
    inject_trace_context(&span, request.headers_mut());

    let result = client.execute(request).instrument(span.clone()).await;
    match &result {
        Ok(response) => record_response_status(&span, response.status(), had_auth),
        Err(err) => record_transport_error(&span, err),
    }
    result
}

/// Open the `CLIENT` span (`upstream_request`) for one upstream request. The
/// exported OTel span name is the HTTP method (`otel.name`), per the HTTP
/// semantic conventions. `url.full` is redacted (no userinfo, query or
/// fragment), as the semantic conventions require for credentials and as every
/// other upstream diagnostic in this crate does.
fn upstream_client_span(method: &Method, url: &Url) -> Span {
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
fn inject_trace_context(span: &Span, headers: &mut HeaderMap) {
    let cx = span.context();
    opentelemetry::global::get_text_map_propagator(|propagator| {
        propagator.inject_context(&cx, &mut HeaderInjector(headers));
    });
}

/// Whether an upstream response status marks the client span as failed.
///
/// The HTTP semantic conventions say a `CLIENT` span SHOULD be an error for
/// any 4xx or 5xx. The one exception is a `401` to a request sent WITHOUT an
/// `Authorization` header: an OCI registry answers every first anonymous
/// request with a `401` bearer challenge, which the proxy then satisfies with
/// a token exchange and a retry (each in its own span). Marking that expected
/// step as an error would put an error span in nearly every container-image
/// trace. A `401` to a request that carried credentials (configured Basic
/// auth, a bearer token, a token-endpoint request with Basic auth) means those
/// credentials were rejected, and is an error.
fn status_is_error(status: StatusCode, had_auth: bool) -> bool {
    if status == StatusCode::UNAUTHORIZED {
        return had_auth;
    }
    status.is_client_error() || status.is_server_error()
}

/// Low-cardinality `error.type` for a request that produced no response: the
/// first matching reqwest error class, in this order, else `_OTHER`.
fn transport_error_type(err: &reqwest::Error) -> &'static str {
    type Class = (fn(&reqwest::Error) -> bool, &'static str);
    const CLASSES: [Class; 7] = [
        (reqwest::Error::is_timeout, "timeout"),
        (reqwest::Error::is_connect, "connect"),
        (reqwest::Error::is_redirect, "redirect"),
        (reqwest::Error::is_builder, "builder"),
        (reqwest::Error::is_body, "body"),
        (reqwest::Error::is_decode, "body"),
        (reqwest::Error::is_request, "request"),
    ];
    CLASSES
        .iter()
        .find(|(matches, _)| matches(err))
        .map_or("_OTHER", |(_, name)| name)
}

fn record_response_status(span: &Span, status: StatusCode, had_auth: bool) {
    span.record("http.response.status_code", status.as_u16());
    if status_is_error(status, had_auth) {
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
    use crate::testing::otel::{
        install_w3c_propagator as install_propagator, otel_subscriber, ExportedSpans, SpanFields,
    };
    use opentelemetry::trace::TraceContextExt;
    use tracing_subscriber::layer::SubscriberExt;

    const UPSTREAM_SPAN_NAME: &str = "upstream_request";

    fn fields() -> SpanFields {
        SpanFields::new(UPSTREAM_SPAN_NAME)
    }

    /// The exported status of the single upstream span (exported under its
    /// `otel.name`, the HTTP method).
    fn upstream_status(exported: &ExportedSpans) -> opentelemetry::trace::Status {
        let span = exported.one("GET");
        assert_eq!(span.span_kind, opentelemetry::trace::SpanKind::Client);
        span.status
    }

    /// A subscriber with a real `tracing-opentelemetry` layer (so spans have
    /// an OTel context to inject and are exported to `exported`) plus the
    /// field capture.
    fn subscriber_exporting(
        fields: &SpanFields,
        exported: &ExportedSpans,
    ) -> impl tracing::Subscriber + Send + Sync {
        otel_subscriber(exported).with(fields.clone())
    }

    fn subscriber(fields: &SpanFields) -> impl tracing::Subscriber + Send + Sync {
        subscriber_exporting(fields, &ExportedSpans::default())
    }

    #[test]
    fn span_carries_http_client_semantic_attributes_with_redacted_url() {
        let fields = fields();
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
        let fields = fields();
        tracing::subscriber::with_default(subscriber(&fields), || {
            let url = Url::parse("https://registry.example/v2/").unwrap();
            let _span = upstream_client_span(&Method::GET, &url);
        });
        assert_eq!(fields.get("server.port").as_deref(), Some("443"));
    }

    #[test]
    fn injects_the_span_trace_context_as_traceparent() {
        install_propagator();
        let fields = fields();
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
        for had_auth in [false, true] {
            for ok in [200u16, 204, 206, 301, 304] {
                let status = StatusCode::from_u16(ok).unwrap();
                assert!(!status_is_error(status, had_auth), "{ok}");
            }
            for err in [400u16, 403, 404, 410, 429, 500, 502, 503] {
                let status = StatusCode::from_u16(err).unwrap();
                assert!(status_is_error(status, had_auth), "{err}");
            }
        }
        // An anonymous request's 401 is the OCI bearer challenge; an
        // authenticated request's 401 is rejected credentials.
        assert!(!status_is_error(StatusCode::UNAUTHORIZED, false));
        assert!(status_is_error(StatusCode::UNAUTHORIZED, true));
    }

    /// Send one GET to a mock answering 401 and return the exported status.
    async fn exported_status_of_401(authenticate: bool) -> opentelemetry::trace::Status {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(401).insert_header("www-authenticate", "Bearer realm=\"x\""),
            )
            .mount(&server)
            .await;

        let exported = ExportedSpans::default();
        let _guard = tracing::subscriber::set_default(subscriber_exporting(&fields(), &exported));
        let mut request = reqwest::Client::new().get(server.uri());
        if authenticate {
            request = request.bearer_auth("rejected-token");
        }
        send_upstream(request).await.expect("the mock answers");
        upstream_status(&exported)
    }

    #[tokio::test]
    async fn anonymous_bearer_challenge_is_not_exported_as_an_error() {
        assert_eq!(
            exported_status_of_401(false).await,
            opentelemetry::trace::Status::Unset
        );
    }

    #[tokio::test]
    async fn rejected_credentials_are_exported_as_an_error() {
        assert!(matches!(
            exported_status_of_401(true).await,
            opentelemetry::trace::Status::Error { .. }
        ));
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
        let fields = fields();
        let _guard = tracing::subscriber::set_default(subscriber(&fields));
        let err = send_upstream(reqwest::Client::new().get(format!("http://127.0.0.1:{port}/")))
            .await
            .expect_err("nothing listens on the port");
        assert_eq!(transport_error_type(&err), "connect");
        assert_eq!(fields.get("error.type").as_deref(), Some("connect"));
        assert_eq!(fields.get("otel.status_code").as_deref(), Some("error"));
    }

    #[tokio::test]
    async fn timeout_and_redirect_failures_are_classified() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/slow"))
            .respond_with(ResponseTemplate::new(200).set_delay(std::time::Duration::from_secs(5)))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/loop"))
            .respond_with(ResponseTemplate::new(302).insert_header("location", "/loop"))
            .mount(&server)
            .await;

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_millis(100))
            .redirect(reqwest::redirect::Policy::limited(2))
            .build()
            .unwrap();
        let slow = send_upstream(client.get(format!("{}/slow", server.uri())))
            .await
            .expect_err("the mock answers after the timeout");
        assert_eq!(transport_error_type(&slow), "timeout");
        let looping = send_upstream(client.get(format!("{}/loop", server.uri())))
            .await
            .expect_err("the redirect limit is exceeded");
        assert_eq!(transport_error_type(&looping), "redirect");
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

        let fields = fields();
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

        let fields = fields();
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
