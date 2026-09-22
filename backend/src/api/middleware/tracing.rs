//! Request tracing middleware with correlation ID and W3C Trace Context support.
//!
//! Provides correlation ID generation/propagation. The `http_request` span
//! itself is created by the outer `TraceLayer` in `main.rs` (which also
//! redacts sensitive query params, see #544); this middleware records the
//! correlation ID onto that ambient span rather than opening a second one.

use axum::{extract::Request, http::header::HeaderValue, middleware::Next, response::Response};
use uuid::Uuid;

/// The header name for correlation IDs.
pub const CORRELATION_ID_HEADER: &str = "X-Correlation-ID";

/// W3C Trace Context header.
const TRACEPARENT_HEADER: &str = "traceparent";

/// Hard cap on a correlation ID, in bytes (#2414).
///
/// The header is caller-controlled and unauthenticated, and audited public
/// paths (e.g. login failures) persist the value per event — an unbounded
/// value would let an attacker write hundreds of KB into the audit table,
/// tracing spans, and response headers on every request. 256 bytes is far
/// beyond any real correlation scheme (UUIDs are 36, W3C trace IDs 32).
/// Values over the cap are truncated, and the TRUNCATED value is the
/// canonical ID everywhere: request extension, task-local, trace span,
/// response-header echo, and audit row. Prefix truncation permits deliberate
/// collisions, but callers can already reuse arbitrary IDs — correlation
/// grouping is never authenticated evidence.
pub const CORRELATION_ID_MAX_BYTES: usize = 256;

/// Clamp a correlation value to [`CORRELATION_ID_MAX_BYTES`], cutting at a
/// UTF-8 character boundary. Header-derived values are ASCII (hyper rejects
/// non-visible-ASCII in `to_str`), but programmatic callers of
/// `AuditEntry::correlation` may pass arbitrary UTF-8. Borrows rather than
/// owns so callers copy only the bounded prefix — truncating an owned
/// String would keep the oversized allocation's full capacity alive for as
/// long as the value lives (a whole request scope, per request).
pub(crate) fn clamp_correlation_value(value: &str) -> &str {
    if value.len() > CORRELATION_ID_MAX_BYTES {
        let mut cut = CORRELATION_ID_MAX_BYTES;
        while !value.is_char_boundary(cut) {
            cut -= 1;
        }
        &value[..cut]
    } else {
        value
    }
}

/// Extension that holds the correlation ID for the current request.
///
/// The inner value is private (#2414): every construction path goes through
/// [`CorrelationId::new`]'s clamp, so no caller can smuggle an over-cap
/// value past it with a tuple literal.
#[derive(Debug, Clone)]
pub struct CorrelationId(String);

impl CorrelationId {
    /// Build a correlation ID from a caller-supplied value, clamping it to
    /// [`CORRELATION_ID_MAX_BYTES`] so one canonical (possibly truncated)
    /// value flows to the span, response header, task-local, and audit rows.
    /// Copies only the bounded prefix, never the caller's full buffer.
    pub fn new(id: impl AsRef<str>) -> Self {
        Self(clamp_correlation_value(id.as_ref()).to_owned())
    }

    pub fn generate() -> Self {
        Self(Uuid::new_v4().to_string())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

impl std::fmt::Display for CorrelationId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

tokio::task_local! {
    /// The correlation ID of the request currently being handled (#2414).
    ///
    /// `correlation_id_middleware` scopes this around the downstream request
    /// future, so anything `.await`ed while handling the request — handlers,
    /// service calls, audit emitters — observes the request's correlation ID
    /// without threading it through every signature. The scope wraps the
    /// future, not the OS task, so it is correct under HTTP/2 multiplexing.
    /// A future detached with `tokio::spawn` does NOT inherit the value;
    /// code that emits audit entries from a detached task must capture the
    /// ID first (no current emitter does).
    static CURRENT_CORRELATION: CorrelationId;
}

/// The correlation ID of the in-flight request, when called from within a
/// request future wrapped by [`correlation_id_middleware`]; `None` from
/// background jobs, startup code, and detached tasks (#2414).
pub fn current_correlation_id() -> Option<CorrelationId> {
    CURRENT_CORRELATION.try_with(Clone::clone).ok()
}

/// Runs `fut` with [`current_correlation_id`] resolving to `id` — the same
/// scoping the middleware applies to each request. Public so tests (and any
/// future non-HTTP entry point that has its own correlation handle, e.g. a
/// job runner) can establish a scope without standing up a router.
pub async fn with_correlation_scope<F: std::future::Future>(
    id: CorrelationId,
    fut: F,
) -> F::Output {
    CURRENT_CORRELATION.scope(id, fut).await
}

/// Whether a present `traceparent` carries W3C-conformant field widths.
///
/// `true` when the header is absent (there is nothing to reject; extraction
/// then yields an invalid context and the caller starts a new trace) or when
/// `trace-id` is exactly 32 and `parent-id` exactly 16 hex characters.
///
/// This exists because `TraceContextPropagator` does not check either width —
/// it delegates to `TraceId::from_hex` / `SpanId::from_hex`, which accept a
/// shorter string and zero-pad it. Without this guard,
/// `00-4bf92f3577b34da6-00f067aa0ba902b7-01` is accepted as trace-id
/// `00000000000000004bf92f3577b34da6`, silently parenting the request into a
/// trace nobody else is in.
fn traceparent_field_widths_are_valid(headers: &axum::http::HeaderMap) -> bool {
    const TRACE_ID_HEX_LEN: usize = 32;
    const PARENT_ID_HEX_LEN: usize = 16;

    let Some(raw) = headers.get(TRACEPARENT_HEADER) else {
        return true;
    };
    let Ok(value) = raw.to_str() else {
        // Non-visible-ASCII cannot be a conformant traceparent.
        return false;
    };

    let parts: Vec<&str> = value.trim().split('-').collect();
    if parts.len() < 4 {
        // Malformed in a way the propagator also rejects; let it say so.
        return false;
    }

    parts[1].len() == TRACE_ID_HEX_LEN && parts[2].len() == PARENT_ID_HEX_LEN
}

/// W3C `tracestate` caps: at most 32 list-members and 512 characters in total
/// (W3C Trace Context §3.3.1.1). `TraceState::from_str` in the SDK bounds each
/// key and value but not the member count or the total length, and the SDK
/// sampler copies the parent's `tracestate` into every child span, so an
/// oversized header would be deep-cloned onto — and exported with — every span
/// of the request. Same amplification class as the correlation-ID clamp
/// (#2414); the header is dropped rather than truncated, because a truncated
/// member list is not what the caller sent.
const TRACESTATE_MAX_BYTES: usize = 512;
const TRACESTATE_MAX_MEMBERS: usize = 32;
const TRACESTATE_HEADER: &str = "tracestate";

/// Whether a `tracestate` value is within the W3C size limits. Empty
/// list-members (`a=1,,b=2`) are allowed by the spec and are not counted.
fn tracestate_within_w3c_limits(value: &str) -> bool {
    value.len() <= TRACESTATE_MAX_BYTES
        && value.split(',').filter(|m| !m.trim().is_empty()).count() <= TRACESTATE_MAX_MEMBERS
}

/// The propagator's view of the inbound headers.
///
/// A local `Extractor` over axum's `HeaderMap` (rather than
/// `opentelemetry_http::HeaderExtractor`, which is the same few lines) so the
/// backend does not depend on `opentelemetry-http` for this. It also hides a
/// `tracestate` that exceeds the W3C limits, so an oversized one is dropped
/// while the `traceparent` beside it is still honoured.
struct InboundHeaderExtractor<'a>(&'a axum::http::HeaderMap);

impl opentelemetry::propagation::Extractor for InboundHeaderExtractor<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        let value = self.0.get(key)?.to_str().ok()?;
        if key.eq_ignore_ascii_case(TRACESTATE_HEADER) && !tracestate_within_w3c_limits(value) {
            return None;
        }
        Some(value)
    }

    fn keys(&self) -> Vec<&str> {
        self.0.keys().map(|name| name.as_str()).collect()
    }
}

/// Extract a W3C Trace Context remote parent from inbound request headers.
///
/// Returns `None` — meaning "start a new trace" — when there is no usable
/// remote parent. That covers every failure mode deliberately, because a
/// malformed or hostile header must never cost us a trace:
///
/// * no `traceparent` header at all (the common case for a direct client);
/// * a header the W3C propagator cannot parse (bad version, wrong field
///   count, non-hex digits, wrong lengths);
/// * a syntactically valid header carrying an all-zero trace-id or span-id,
///   which the spec defines as invalid — `SpanContext::is_valid` is what
///   rejects these, and it is the reason this returns `Option` rather than
///   handing the raw extracted `Context` to the caller. A non-remote or
///   invalid context passed to `set_parent` would produce a span parented to
///   nothing useful while *looking* parented.
///
/// `tracestate` is carried along with `traceparent` by the propagator, so
/// vendor-specific state survives this hop — unless it exceeds the W3C limits
/// of 32 members / 512 characters, in which case it is dropped and the
/// `traceparent` is still adopted (see `InboundHeaderExtractor`).
///
/// Requires a global propagator to be installed (see
/// [`crate::telemetry::init_tracing`]). Without one this returns `None` for
/// every request, which is exactly the behaviour before this function existed.
///
/// ## On trusting the header
///
/// The value is caller-controlled and unauthenticated. Two consequences, both
/// bounded:
///
/// * **Trace-id spoofing.** A caller can join, or claim to join, an arbitrary
///   trace. Trace correlation is a debugging aid, never authenticated
///   evidence — the same caveat [`CORRELATION_ID_MAX_BYTES`] already records
///   for correlation IDs, which are derived from this same header today.
/// * **Sampling.** The sampler is configurable (`OTEL_TRACES_SAMPLER`, see
///   `SamplerChoice` in `crate::telemetry`). Under the default,
///   `parentbased_always_on`, every root span is sampled, so honouring a
///   remote parent can only *reduce* export volume (a caller sending
///   `sampled=00` suppresses its own trace). Under `parentbased_always_off`
///   or `parentbased_traceidratio`, however, an untrusted `sampled=01` forces
///   export of a trace the sampler would have dropped. Extraction is
///   currently accepted from any peer; gating it on the trusted-proxy CIDR
///   list is the planned fix.
pub fn remote_trace_context(headers: &axum::http::HeaderMap) -> Option<opentelemetry::Context> {
    use opentelemetry::trace::TraceContextExt;

    // The SDK's W3C propagator validates the field count, the version and
    // lowercase-ness, but NOT the length of `trace-id` / `parent-id`: it parses
    // both with `from_hex`, which accepts a short value and zero-pads it. A
    // truncated `trace-id` therefore becomes a different, entirely valid-looking
    // id, and the request would silently join a trace that is not the caller's.
    // W3C fixes both lengths (32 and 16 hex characters), so enforce that here
    // before extraction rather than inheriting the leniency.
    if !traceparent_field_widths_are_valid(headers) {
        return None;
    }

    let cx = opentelemetry::global::get_text_map_propagator(|propagator| {
        propagator.extract(&InboundHeaderExtractor(headers))
    });

    // `extract` yields a Context regardless; only a valid, genuinely remote
    // span context is worth parenting to. The borrow is scoped so the decision
    // outlives the `SpanRef` without holding it across the move of `cx`.
    let usable = {
        let span_ref = cx.span();
        let span_context = span_ref.span_context();
        span_context.is_valid() && span_context.is_remote()
    };

    if usable {
        Some(cx)
    } else {
        None
    }
}

/// Build the `http_request` span for one inbound request.
///
/// Lives here rather than inline in `main.rs` so it is reachable from tests:
/// as a closure inside `run_server` the span's kind and its parent adoption
/// could only be verified by compiling, never by asserting.
///
/// Three things happen, and each is load-bearing:
///
/// * the URI is redacted (#544) before it reaches the span;
/// * the span is `otel.kind = "server"`, which `tracing-opentelemetry` maps to
///   `SpanKind::Server`. Left unset it defaults to `INTERNAL`, which trace UIs
///   and span metrics read as a standalone operation rather than a request
///   entry point;
/// * a usable inbound W3C context becomes the span's remote parent, so the
///   caller's trace and this one are a single trace.
///
/// The parent is set on THIS span rather than by opening a second one: #2308 /
/// #2309 removed a duplicate `http_request` span and the module docs above
/// record why it must stay removed.
pub fn make_http_request_span<B>(request: &axum::http::Request<B>) -> tracing::Span {
    let uri = request.uri();
    let sanitized = crate::api::redact_sensitive_params(uri.path(), uri.query());

    let span = tracing::info_span!(
        "http_request",
        otel.kind = "server",
        method = %request.method(),
        uri = %sanitized,
        correlation_id = tracing::field::Empty,
    );

    if let Some(parent) = remote_trace_context(request.headers()) {
        use tracing_opentelemetry::OpenTelemetrySpanExt;
        // The only failure mode is `SetParentError::LayerNotFound` (no OTel
        // layer installed). `remote_trace_context` already returns `None` in
        // that configuration, because the propagator is installed on the OTel
        // path only -- so this is unreachable in practice, and harmless if ever
        // reached: the span simply stays a root. Deliberately not logged; this
        // runs once per request and a line for an impossible condition is noise.
        let _ = span.set_parent(parent);
    }

    span
}

/// Correlation ID middleware with W3C Trace Context interop.
///
/// Priority for correlation ID:
/// 1. `X-Correlation-ID` header (explicit)
/// 2. `trace-id` extracted from `traceparent` header (W3C format: version-traceid-parentid-flags)
/// 3. Generate a new UUID
///
/// Records the correlation ID onto the ambient `http_request` span created by
/// the outer `TraceLayer` (see `main.rs`), rather than opening a second,
/// unredacted `http_request` span of its own. The outer span already applies
/// `redact_sensitive_params` to the URI (see #544); a second span built from
/// the raw `request.uri()` would bypass that redaction and double-emit every
/// request-scoped log line.
pub async fn correlation_id_middleware(mut request: Request, next: Next) -> Response {
    let correlation_id = request
        .headers()
        .get(CORRELATION_ID_HEADER)
        .and_then(|h| h.to_str().ok())
        .map(CorrelationId::new)
        .or_else(|| {
            // Extract trace-id from traceparent header
            request
                .headers()
                .get(TRACEPARENT_HEADER)
                .and_then(|h| h.to_str().ok())
                .and_then(|tp| {
                    let parts: Vec<&str> = tp.split('-').collect();
                    if parts.len() >= 2 {
                        Some(CorrelationId::new(parts[1]))
                    } else {
                        None
                    }
                })
        })
        .unwrap_or_else(CorrelationId::generate);

    request.extensions_mut().insert(correlation_id.clone());

    tracing::Span::current().record("correlation_id", tracing::field::display(&correlation_id));

    // Kubernetes polls the health/readiness/liveness probes on a tight loop
    // forever; their per-request "Request completed" lines bury real request
    // logs. They are suppressed unless the operator opts in via
    // LOG_PROBE_REQUESTS, except a non-success response always logs (see
    // should_log_completed). Decided after the response so the status is known.
    let is_probe = is_probe_path(request.uri().path());

    // Scope the task-local around the whole downstream future so audit
    // emitters anywhere under this request observe the same correlation ID
    // the span carries and the response header echoes (#2414).
    with_correlation_scope(correlation_id.clone(), async move {
        let mut response = next.run(request).await;

        if let Ok(value) = HeaderValue::from_str(correlation_id.as_str()) {
            response.headers_mut().insert(CORRELATION_ID_HEADER, value);
        }

        if should_log_completed(
            is_probe,
            log_probe_requests(),
            response.status().is_success(),
        ) {
            tracing::info!(
                correlation_id = %correlation_id,
                status = %response.status().as_u16(),
                "Request completed"
            );
        }

        response
    })
    .await
}

/// Health/readiness/liveness probe paths, exactly as wired in `api::routes`.
/// Kubernetes hits these continuously, so their per-request logs are pure noise.
/// Matched on the full, unstripped path because this middleware sits outside
/// every `nest()`.
///
/// `/metrics` is deliberately absent: the only such route is the admin-scoped
/// `/api/v1/admin/metrics`, and Prometheus in the chart scrapes the separate
/// unauthenticated `METRICS_PORT` listener, which carries no correlation
/// middleware and so never emits a "Request completed" line to suppress.
fn is_probe_path(path: &str) -> bool {
    matches!(
        path,
        "/health" | "/healthz" | "/ready" | "/readyz" | "/livez"
    )
}

/// Whether to emit the "Request completed" line for a request. Probe requests
/// are suppressed unless the operator opts in, but a non-success response
/// (e.g. `/readyz` 503 when Postgres is down) always logs: relying on
/// `TraceLayer`'s implicit ERROR emission would be silently lost to a future
/// `on_failure`/`EnvFilter` change. Pure, so it is unit testable.
fn should_log_completed(is_probe: bool, opt_in: bool, is_success: bool) -> bool {
    !is_probe || opt_in || !is_success
}

/// Force-resolve the `LOG_PROBE_REQUESTS` toggle at startup so an unrecognized
/// value (a typo like `treu`) is surfaced by a warning immediately, rather than
/// only when the first probe request happens to initialize the `OnceLock`.
/// Idempotent: the resolved value is memoised in [`log_probe_requests`].
pub fn init_probe_request_logging() {
    let _ = log_probe_requests();
}

/// Whether probe requests should still be logged. Defaults to off (silent);
/// set `LOG_PROBE_REQUESTS=1|true|yes|on` to restore per-probe request logging.
/// Read once — env is fixed for the process lifetime.
fn log_probe_requests() -> bool {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENABLED.get_or_init(|| {
        resolve_log_probe_requests(std::env::var("LOG_PROBE_REQUESTS").ok().as_deref())
    })
}

/// Resolve the toggle from the raw env value, warning once on a value that is
/// set but unrecognized (e.g. a typo) so it is not silently treated as off.
/// Unset or empty is the default (off, no warning).
fn resolve_log_probe_requests(value: Option<&str>) -> bool {
    match parse_log_probe_requests(value) {
        Some(enabled) => enabled,
        None => {
            if let Some(raw) = value {
                if !raw.trim().is_empty() {
                    tracing::warn!(
                        value = %raw,
                        "LOG_PROBE_REQUESTS is set to an unrecognized value; treating as off \
                         (expected one of 1/true/yes/on or 0/false/no/off)"
                    );
                }
            }
            false
        }
    }
}

/// Pure parse of the `LOG_PROBE_REQUESTS` toggle: `Some(true|false)` for a
/// recognized value, `None` when unset or set to something unrecognized. Split
/// out so it is unit testable without the environment or the `OnceLock`. The
/// truthy/falsy sets match the `env_bool` helper in `sync_worker`.
fn parse_log_probe_requests(value: Option<&str>) -> Option<bool> {
    match value.map(|v| v.trim().to_ascii_lowercase()).as_deref() {
        Some("1" | "true" | "yes" | "on") => Some(true),
        Some("0" | "false" | "no" | "off") => Some(false),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_correlation_id_generate() {
        let id = CorrelationId::generate();
        assert!(Uuid::parse_str(id.as_str()).is_ok());
    }

    #[test]
    fn probe_paths_match_routes_and_nothing_else() {
        // Exactly the health routes wired in api::routes.
        for p in ["/health", "/healthz", "/ready", "/readyz", "/livez"] {
            assert!(is_probe_path(p), "{p} should be treated as a probe");
        }
        // Never suppressed. `/api/v1/admin/metrics` is the real (admin) metrics
        // route: this asserts it stays logged, and fails loudly if the layer is
        // ever moved inside a nest() where the prefix would strip to `/metrics`.
        for p in [
            "/api/v1/admin/metrics",
            "/metrics",
            "/api/v1/packages",
            "/health/dashboard",
            "/",
            "/readyz/x",
        ] {
            assert!(!is_probe_path(p), "{p} must not be suppressed");
        }
    }

    #[test]
    fn parse_log_probe_requests_truthy_falsy_and_unrecognized() {
        for v in ["1", "true", "TRUE", "yes", "on", " on "] {
            assert_eq!(parse_log_probe_requests(Some(v)), Some(true), "{v:?}");
        }
        for v in ["0", "false", "no", "off", " off "] {
            assert_eq!(parse_log_probe_requests(Some(v)), Some(false), "{v:?}");
        }
        // Set-but-unrecognized and unset both parse to None; `resolve` tells
        // them apart (only the former warns).
        for v in ["", "treu", "nope"] {
            assert_eq!(parse_log_probe_requests(Some(v)), None, "{v:?}");
        }
        assert_eq!(parse_log_probe_requests(None), None);
    }

    #[test]
    fn resolve_log_probe_requests_defaults_off_and_warns_on_garbage() {
        assert!(!resolve_log_probe_requests(None)); // unset -> off
        assert!(resolve_log_probe_requests(Some("on"))); // recognized -> on
        assert!(!resolve_log_probe_requests(Some("off"))); // recognized -> off
        assert!(!resolve_log_probe_requests(Some("treu"))); // typo -> off (warns)
        assert!(!resolve_log_probe_requests(Some(""))); // empty -> off (no warn)
    }

    #[test]
    fn log_probe_requests_defaults_off_when_unset() {
        // LOG_PROBE_REQUESTS is unset in the test environment.
        assert!(!log_probe_requests());
    }

    #[test]
    fn should_log_completed_rules() {
        // Non-probe requests always log.
        assert!(should_log_completed(false, false, true));
        // Probe success is silenced unless the operator opts in.
        assert!(!should_log_completed(true, false, true));
        assert!(should_log_completed(true, true, true));
        // Probe failure (e.g. /readyz 503) always logs, opt-in or not.
        assert!(should_log_completed(true, false, false));
    }

    #[test]
    fn test_correlation_id_generate_is_unique() {
        let id1 = CorrelationId::generate();
        let id2 = CorrelationId::generate();
        assert_ne!(id1.as_str(), id2.as_str());
    }

    #[test]
    fn test_correlation_id_new() {
        let id = CorrelationId::new("my-custom-id");
        assert_eq!(id.as_str(), "my-custom-id");
    }

    #[test]
    fn test_correlation_id_display() {
        let id = CorrelationId::new("test-id");
        assert_eq!(format!("{}", id), "test-id");
    }

    #[test]
    fn test_correlation_id_clone() {
        let id = CorrelationId::new("clone-test");
        let cloned = id.clone();
        assert_eq!(id.as_str(), cloned.as_str());
    }

    // traceparent extraction tests

    /// Helper to extract trace-id from a traceparent header value.
    fn extract_trace_id(traceparent: &str) -> Option<String> {
        let parts: Vec<&str> = traceparent.split('-').collect();
        if parts.len() >= 2 {
            Some(parts[1].to_string())
        } else {
            None
        }
    }

    #[test]
    fn test_traceparent_valid_extraction() {
        // W3C format: version-traceid-parentid-flags
        let tp = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
        let trace_id = extract_trace_id(tp);
        assert_eq!(
            trace_id.as_deref(),
            Some("4bf92f3577b34da6a3ce929d0e0e4736")
        );
    }

    #[test]
    fn test_traceparent_version_00() {
        let tp = "00-abcdef1234567890abcdef1234567890-1234567890abcdef-00";
        let trace_id = extract_trace_id(tp);
        assert_eq!(
            trace_id.as_deref(),
            Some("abcdef1234567890abcdef1234567890")
        );
    }

    #[test]
    fn test_traceparent_future_version() {
        // Future versions with extra fields should still work
        let tp = "ff-abcdef1234567890abcdef1234567890-1234567890abcdef-01-extra";
        let trace_id = extract_trace_id(tp);
        assert_eq!(
            trace_id.as_deref(),
            Some("abcdef1234567890abcdef1234567890")
        );
    }

    #[test]
    fn test_traceparent_malformed_no_dashes() {
        let tp = "nohyphenshere";
        let trace_id = extract_trace_id(tp);
        assert_eq!(trace_id, None);
    }

    #[test]
    fn test_traceparent_single_field() {
        let tp = "00";
        let trace_id = extract_trace_id(tp);
        assert_eq!(trace_id, None);
    }

    #[test]
    fn test_traceparent_empty_string() {
        let tp = "";
        let trace_id = extract_trace_id(tp);
        assert_eq!(trace_id, None);
    }

    #[test]
    fn test_traceparent_two_fields_minimum() {
        let tp = "00-traceid";
        let trace_id = extract_trace_id(tp);
        assert_eq!(trace_id.as_deref(), Some("traceid"));
    }

    #[test]
    fn test_header_constants() {
        assert_eq!(CORRELATION_ID_HEADER, "X-Correlation-ID");
        assert_eq!(TRACEPARENT_HEADER, "traceparent");
    }

    // #2414: the 256-byte correlation cap.

    #[test]
    fn test_clamp_preserves_values_at_the_cap() {
        let exact = "x".repeat(CORRELATION_ID_MAX_BYTES);
        assert_eq!(clamp_correlation_value(&exact), exact);
        assert_eq!(
            clamp_correlation_value("audit-correlation-test"),
            "audit-correlation-test"
        );
    }

    #[test]
    fn test_clamp_truncates_values_over_the_cap() {
        let over = "y".repeat(CORRELATION_ID_MAX_BYTES + 100);
        let clamped = clamp_correlation_value(&over);
        assert_eq!(clamped.len(), CORRELATION_ID_MAX_BYTES);
        assert_eq!(clamped, &over[..CORRELATION_ID_MAX_BYTES]);
    }

    #[test]
    fn test_clamp_cuts_at_a_char_boundary() {
        // 'é' is 2 bytes. A leading ASCII byte shifts every 'é' boundary to
        // an odd offset, so the 256-byte cut lands mid-character and the
        // clamp must walk back to 255 instead of panicking on a non-boundary
        // slice.
        let s = format!("a{}", "é".repeat(129));
        let clamped = clamp_correlation_value(&s);
        assert_eq!(clamped.len(), CORRELATION_ID_MAX_BYTES - 1);
        assert_eq!(clamped, format!("a{}", "é".repeat(127)));
    }

    #[test]
    fn test_correlation_id_new_applies_the_cap_without_retaining_capacity() {
        let oversized = "z".repeat(CORRELATION_ID_MAX_BYTES * 100);
        let id = CorrelationId::new(&oversized);
        assert_eq!(id.as_str().len(), CORRELATION_ID_MAX_BYTES);
        // The point of the borrow-based clamp: only the bounded prefix is
        // copied. Truncating an owned String instead would retain the full
        // oversized capacity for the life of the request scope.
        assert!(id.0.capacity() <= CORRELATION_ID_MAX_BYTES);
    }

    // #2414: the request-scoped correlation task-local.

    #[tokio::test]
    async fn test_current_correlation_id_is_none_outside_a_scope() {
        assert!(current_correlation_id().is_none());
    }

    #[tokio::test]
    async fn test_with_correlation_scope_bounds_the_value() {
        let seen = with_correlation_scope(CorrelationId::new("scoped-id"), async {
            current_correlation_id().map(|c| c.0)
        })
        .await;
        assert_eq!(seen.as_deref(), Some("scoped-id"));
        // The value must not leak past the scope.
        assert!(current_correlation_id().is_none());
    }

    // -----------------------------------------------------------------------
    // #2414: audit entries built while handling a request must carry the
    // request's correlation ID — the same value the middleware resolves
    // (X-Correlation-ID header → traceparent trace-id → generated UUID),
    // stamps on the tracing span, and echoes in the response header. These
    // tests drive a real router through `correlation_id_middleware` with a
    // probe handler that constructs `AuditEntry`s exactly the way production
    // emitters do and reports the correlation value each entry captured.
    // -----------------------------------------------------------------------

    mod audit_correlation {
        use super::*;
        use crate::services::audit_service::{AuditAction, AuditEntry, ResourceType};
        use axum::{body::Body, extract::Request as AxumRequest, middleware, routing::get, Router};
        use tower::ServiceExt;

        /// Builds two `AuditEntry`s the way any production emitter does and
        /// returns the correlation value each captured, one per line. Two
        /// entries so tests can also pin the "N events from one request share
        /// one ID" contract from #2414.
        async fn audited_probe() -> String {
            let first = AuditEntry::new(AuditAction::RepositoryCreated, ResourceType::Repository);
            let second = AuditEntry::new(AuditAction::RepositoryUpdated, ResourceType::Repository);
            format!("{}\n{}", first.correlation_id(), second.correlation_id())
        }

        fn probe_app() -> Router {
            Router::new()
                .route("/probe", get(audited_probe))
                .layer(middleware::from_fn(correlation_id_middleware))
        }

        /// Runs one request through the middleware-wrapped probe and returns
        /// (echoed X-Correlation-ID response header, the two per-entry
        /// correlation values captured inside the handler).
        async fn run_probe(request: AxumRequest<Body>) -> (String, Vec<String>) {
            let response = probe_app().oneshot(request).await.expect("probe request");
            assert_eq!(response.status(), axum::http::StatusCode::OK);
            let echoed = response
                .headers()
                .get(CORRELATION_ID_HEADER)
                .expect("middleware echoes the correlation header")
                .to_str()
                .expect("echoed correlation header is ASCII")
                .to_string();
            #[allow(clippy::disallowed_methods)]
            // STREAMING-EXEMPT: bounded 4 KiB test-probe body (two correlation
            // values); not an artifact path (#1608)
            let body = axum::body::to_bytes(response.into_body(), 4096)
                .await
                .expect("read probe body");
            let entries = String::from_utf8(body.to_vec())
                .expect("probe body is UTF-8")
                .lines()
                .map(str::to_string)
                .collect();
            (echoed, entries)
        }

        #[tokio::test]
        async fn audit_entry_inherits_caller_supplied_correlation_id() {
            let supplied = "audit-correlation-test-2414";
            let request = AxumRequest::builder()
                .uri("/probe")
                .header(CORRELATION_ID_HEADER, supplied)
                .body(Body::empty())
                .unwrap();
            let (echoed, entries) = run_probe(request).await;
            assert_eq!(echoed, supplied, "middleware must echo the supplied ID");
            assert_eq!(
                entries,
                vec![supplied.to_string(), supplied.to_string()],
                "audit entries must preserve the caller-supplied correlation ID (#2414)"
            );
        }

        #[tokio::test]
        async fn audit_entry_inherits_traceparent_trace_id() {
            let trace_id = "4bf92f3577b34da6a3ce929d0e0e4736";
            let request = AxumRequest::builder()
                .uri("/probe")
                .header(
                    TRACEPARENT_HEADER,
                    format!("00-{trace_id}-00f067aa0ba902b7-01"),
                )
                .body(Body::empty())
                .unwrap();
            let (echoed, entries) = run_probe(request).await;
            assert_eq!(echoed, trace_id, "middleware must adopt the W3C trace-id");
            assert_eq!(
                entries,
                vec![trace_id.to_string(), trace_id.to_string()],
                "audit entries must preserve the W3C trace-id as their correlation ID (#2414)"
            );
        }

        /// #2414 hardening: an oversized caller-supplied header is truncated
        /// to [`CORRELATION_ID_MAX_BYTES`] and the TRUNCATED value is the one
        /// canonical ID — echoed to the caller and carried by every audit
        /// entry — so an unauthenticated caller cannot pump hundreds of KB
        /// per request into the audit table, spans, and response headers.
        #[tokio::test]
        async fn oversized_header_truncates_to_one_canonical_id() {
            let oversized = "h".repeat(CORRELATION_ID_MAX_BYTES + 44);
            let request = AxumRequest::builder()
                .uri("/probe")
                .header(CORRELATION_ID_HEADER, &oversized)
                .body(Body::empty())
                .unwrap();
            let (echoed, entries) = run_probe(request).await;
            let expected = &oversized[..CORRELATION_ID_MAX_BYTES];
            assert_eq!(echoed, expected, "echo must carry the truncated value");
            assert_eq!(
                entries,
                vec![expected.to_string(), expected.to_string()],
                "audit entries must carry the same truncated canonical value"
            );
        }

        #[tokio::test]
        async fn audit_entries_share_the_generated_id_when_no_header_supplied() {
            let request = AxumRequest::builder()
                .uri("/probe")
                .body(Body::empty())
                .unwrap();
            let (echoed, entries) = run_probe(request).await;
            assert_eq!(entries.len(), 2);
            assert_eq!(
                entries[0], entries[1],
                "two audit events from one request must share one correlation ID (#2414)"
            );
            assert_eq!(
                entries[0], echoed,
                "the shared audit correlation ID must be the one echoed to the caller (#2414)"
            );
        }
    }
}

#[cfg(test)]
mod remote_trace_context_tests {
    use super::*;
    use axum::http::header::HeaderName;
    use axum::http::{HeaderMap, HeaderValue};
    use opentelemetry::trace::TraceContextExt;

    /// The propagator is process-global. `cargo nextest` runs each test in its
    /// own process, so installing it per test is both safe and necessary —
    /// without it `get_text_map_propagator` yields the no-op propagator and
    /// every extraction returns `None`.
    fn install_propagator() {
        opentelemetry::global::set_text_map_propagator(
            opentelemetry_sdk::propagation::TraceContextPropagator::new(),
        );
    }

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            // Build an owned `HeaderName`: `insert` with a `&str` key requires
            // a `'static` lifetime, which a borrowed slice element is not.
            h.insert(
                HeaderName::from_bytes(k.as_bytes()).expect("valid header name"),
                HeaderValue::from_str(v).expect("valid header value"),
            );
        }
        h
    }

    const VALID: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";

    #[test]
    fn adopts_a_valid_traceparent() {
        install_propagator();
        let cx = remote_trace_context(&headers(&[("traceparent", VALID)]))
            .expect("a valid traceparent must yield a remote parent");
        let span = cx.span();
        let sc = span.span_context();
        assert_eq!(
            sc.trace_id().to_string(),
            "4bf92f3577b34da6a3ce929d0e0e4736"
        );
        assert_eq!(sc.span_id().to_string(), "00f067aa0ba902b7");
        assert!(sc.is_remote(), "the parent must be marked remote");
        assert!(sc.is_sampled(), "the sampled flag must survive the hop");
    }

    /// The sampled flag is load-bearing: with `ParentBased` sampling it is what
    /// a caller uses to suppress its own trace, so it must not be normalised.
    #[test]
    fn carries_an_unsampled_flag_through() {
        install_propagator();
        let unsampled = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00";
        let cx = remote_trace_context(&headers(&[("traceparent", unsampled)]))
            .expect("an unsampled traceparent is still a valid parent");
        assert!(!cx.span().span_context().is_sampled());
    }

    #[test]
    fn carries_tracestate_alongside_traceparent() {
        install_propagator();
        let cx = remote_trace_context(&headers(&[
            ("traceparent", VALID),
            ("tracestate", "vendor=opaque-value"),
        ]))
        .expect("valid traceparent");
        assert!(
            cx.span()
                .span_context()
                .trace_state()
                .get("vendor")
                .is_some(),
            "vendor tracestate must survive the hop"
        );
    }

    /// An oversized `tracestate` is dropped, not truncated, and the
    /// `traceparent` beside it is still adopted. Without the bound the SDK
    /// would copy an arbitrarily large caller-supplied value onto every span
    /// of the request.
    #[test]
    fn oversized_tracestate_is_dropped_but_traceparent_is_kept() {
        install_propagator();

        // 33 members, well under 512 bytes: over the member cap only.
        let too_many: String = (0..33)
            .map(|i| format!("v{i}=x"))
            .collect::<Vec<_>>()
            .join(",");
        assert!(too_many.len() <= TRACESTATE_MAX_BYTES);
        // 3 members, each value within the SDK's 256-byte per-value limit,
        // but 600+ bytes in total: over the byte cap only.
        let too_long = format!("a={v},b={v},c={v}", v = "x".repeat(200));
        assert!(too_long.len() > TRACESTATE_MAX_BYTES);

        for oversized in [&too_many, &too_long] {
            let cx = remote_trace_context(&headers(&[
                ("traceparent", VALID),
                ("tracestate", oversized),
            ]))
            .expect("an oversized tracestate must not cost the traceparent");
            let span = cx.span();
            let sc = span.span_context();
            assert_eq!(
                sc.trace_id().to_string(),
                "4bf92f3577b34da6a3ce929d0e0e4736"
            );
            assert_eq!(
                sc.trace_state().header(),
                "",
                "an over-limit tracestate must be dropped entirely"
            );
        }
    }

    /// The boundary itself is accepted: exactly 32 members survive the hop.
    /// Empty list-members are allowed by the spec and do not count towards
    /// the cap (the SDK parser itself then rejects them, which is its call).
    #[test]
    fn tracestate_at_the_w3c_limits_is_kept() {
        install_propagator();
        let at_cap: String = (0..32)
            .map(|i| format!("v{i}=x"))
            .collect::<Vec<_>>()
            .join(",");
        assert!(tracestate_within_w3c_limits(&at_cap));
        assert!(tracestate_within_w3c_limits(&format!("{at_cap},,")));
        let cx = remote_trace_context(&headers(&[("traceparent", VALID), ("tracestate", &at_cap)]))
            .expect("valid traceparent");
        assert!(cx.span().span_context().trace_state().get("v31").is_some());

        assert!(tracestate_within_w3c_limits(
            &"x".repeat(TRACESTATE_MAX_BYTES)
        ));
        assert!(!tracestate_within_w3c_limits(
            &"x".repeat(TRACESTATE_MAX_BYTES + 1)
        ));
    }

    #[test]
    fn no_traceparent_header_starts_a_new_trace() {
        install_propagator();
        assert!(remote_trace_context(&HeaderMap::new()).is_none());
    }

    /// Every malformed shape must degrade to "start a new trace" rather than
    /// producing a span parented to garbage. A hostile header must never cost
    /// us the trace.
    #[test]
    fn malformed_traceparent_starts_a_new_trace() {
        install_propagator();
        for bad in [
            "",
            "garbage",
            // too few fields
            "00-4bf92f3577b34da6a3ce929d0e0e4736",
            // trace-id too short
            "00-4bf92f3577b34da6-00f067aa0ba902b7-01",
            // span-id too short
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa-01",
            // trace-id too LONG (the other side of the width check)
            "00-4bf92f3577b34da6a3ce929d0e0e4736ff-00f067aa0ba902b7-01",
            // span-id too long
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7ff-01",
            // non-hex digits
            "00-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz-00f067aa0ba902b7-01",
            // unknown/invalid version
            "ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
        ] {
            assert!(
                remote_trace_context(&headers(&[("traceparent", bad)])).is_none(),
                "malformed traceparent {bad:?} must not become a parent"
            );
        }
    }

    /// All-zero ids are syntactically well-formed but defined as invalid by the
    /// W3C spec. `SpanContext::is_valid` is what rejects them, and this is the
    /// case that would otherwise produce a span that *looks* parented but is
    /// parented to nothing.
    #[test]
    fn all_zero_ids_are_rejected() {
        install_propagator();
        for zeroed in [
            "00-00000000000000000000000000000000-00f067aa0ba902b7-01",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01",
            "00-00000000000000000000000000000000-0000000000000000-00",
        ] {
            assert!(
                remote_trace_context(&headers(&[("traceparent", zeroed)])).is_none(),
                "all-zero id {zeroed:?} is invalid per the W3C spec"
            );
        }
    }

    /// Without a global propagator installed, extraction must be inert rather
    /// than panicking — this is the state of every process that runs with no
    /// OTLP endpoint configured.
    #[test]
    fn without_a_propagator_installed_extraction_is_inert() {
        opentelemetry::global::set_text_map_propagator(
            opentelemetry::propagation::composite::TextMapCompositePropagator::new(vec![]),
        );
        assert!(remote_trace_context(&headers(&[("traceparent", VALID)])).is_none());
    }
}

#[cfg(test)]
mod make_http_request_span_tests {
    use super::*;
    use axum::http::{header::HeaderName, HeaderValue, Request};
    use opentelemetry::trace::TraceContextExt;
    use tracing_opentelemetry::OpenTelemetrySpanExt;
    use tracing_subscriber::layer::SubscriberExt;

    const VALID: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";

    fn install_propagator() {
        opentelemetry::global::set_text_map_propagator(
            opentelemetry_sdk::propagation::TraceContextPropagator::new(),
        );
    }

    fn request_with(headers: &[(&str, &str)]) -> Request<()> {
        let mut builder = Request::builder().uri("/npm/some-repo/pkg?token=secret");
        for (k, v) in headers {
            builder = builder.header(
                HeaderName::from_bytes(k.as_bytes()).expect("valid header name"),
                HeaderValue::from_str(v).expect("valid header value"),
            );
        }
        builder.body(()).expect("request builds")
    }

    /// Run `f` under a subscriber carrying a real `tracing-opentelemetry`
    /// layer. Without an OTel layer `set_parent` returns `LayerNotFound` and
    /// `Span::context()` cannot observe a parent, so a test that skipped this
    /// would pass regardless of whether the wiring works.
    fn with_otel_layer<T>(f: impl FnOnce() -> T) -> T {
        use opentelemetry::trace::TracerProvider as _;
        let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder().build();
        let tracer = provider.tracer("test");
        let subscriber =
            tracing_subscriber::registry().with(tracing_opentelemetry::layer().with_tracer(tracer));
        tracing::subscriber::with_default(subscriber, f)
    }

    /// The wiring this whole change exists for: a request carrying a usable
    /// `traceparent` produces a span in the CALLER's trace.
    #[test]
    fn adopts_the_inbound_trace_as_the_span_parent() {
        install_propagator();
        with_otel_layer(|| {
            let span = make_http_request_span(&request_with(&[("traceparent", VALID)]));
            let cx = span.context();
            assert_eq!(
                cx.span().span_context().trace_id().to_string(),
                "4bf92f3577b34da6a3ce929d0e0e4736",
                "the span must join the caller's trace, not start its own"
            );
        });
    }

    /// No inbound context means a fresh trace — the pre-existing behaviour,
    /// which must not regress for direct (non-proxied) clients.
    #[test]
    fn without_an_inbound_context_the_span_starts_its_own_trace() {
        install_propagator();
        with_otel_layer(|| {
            let span = make_http_request_span(&request_with(&[]));
            let cx = span.context();
            assert_ne!(
                cx.span().span_context().trace_id().to_string(),
                "4bf92f3577b34da6a3ce929d0e0e4736"
            );
        });
    }

    /// A malformed header must not parent the span to garbage — this is the
    /// end-to-end counterpart of the width/validity checks on
    /// `remote_trace_context`, asserted through the builder callers actually use.
    #[test]
    fn a_truncated_trace_id_does_not_parent_the_span() {
        install_propagator();
        with_otel_layer(|| {
            // 16-char trace-id: the SDK propagator would zero-pad this into a
            // different, valid-looking id if it were not rejected first.
            let span = make_http_request_span(&request_with(&[(
                "traceparent",
                "00-4bf92f3577b34da6-00f067aa0ba902b7-01",
            )]));
            let trace_id = span.context().span().span_context().trace_id().to_string();
            // Rejecting the header does not leave the span parentless-and-invalid:
            // tracing-opentelemetry still gives it a fresh trace of its own. The
            // meaningful assertion is that it is NOT the id the unguarded SDK
            // propagator would have produced by zero-padding the short value.
            assert_ne!(
                trace_id, "00000000000000004bf92f3577b34da6",
                "a truncated trace-id must not be zero-padded into a parent"
            );
            assert_ne!(
                trace_id, "4bf92f3577b34da6a3ce929d0e0e4736",
                "nor silently widened into the full-length id"
            );
        });
    }

    /// The span must still redact its URI (#544). Guards against a future edit
    /// to this builder reintroducing the raw `request.uri()`: captures the
    /// `uri` field actually recorded on the `http_request` span.
    #[test]
    fn the_uri_is_redacted_before_it_reaches_the_span() {
        use std::sync::{Arc, Mutex};

        struct UriVisitor<'a>(&'a mut Option<String>);
        impl tracing::field::Visit for UriVisitor<'_> {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                if field.name() == "uri" {
                    *self.0 = Some(format!("{value:?}"));
                }
            }
        }

        struct CaptureUri(Arc<Mutex<Option<String>>>);
        impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for CaptureUri {
            fn on_new_span(
                &self,
                attrs: &tracing::span::Attributes<'_>,
                _id: &tracing::span::Id,
                _ctx: tracing_subscriber::layer::Context<'_, S>,
            ) {
                if attrs.metadata().name() == "http_request" {
                    attrs.record(&mut UriVisitor(&mut self.0.lock().unwrap()));
                }
            }
        }

        let captured = Arc::new(Mutex::new(None));
        let subscriber = tracing_subscriber::registry().with(CaptureUri(captured.clone()));
        tracing::subscriber::with_default(subscriber, || {
            let _span = make_http_request_span(&request_with(&[]));
        });

        let uri = captured
            .lock()
            .unwrap()
            .clone()
            .expect("make_http_request_span must record a uri field");
        assert!(
            uri.starts_with("/npm/some-repo/pkg"),
            "unexpected uri: {uri}"
        );
        assert!(
            !uri.contains("secret"),
            "the span's uri must be redacted, got {uri}"
        );
    }
}
