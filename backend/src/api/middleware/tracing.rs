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

    // Scope the task-local around the whole downstream future so audit
    // emitters anywhere under this request observe the same correlation ID
    // the span carries and the response header echoes (#2414).
    with_correlation_scope(correlation_id.clone(), async move {
        let mut response = next.run(request).await;

        if let Ok(value) = HeaderValue::from_str(correlation_id.as_str()) {
            response.headers_mut().insert(CORRELATION_ID_HEADER, value);
        }

        tracing::info!(
            correlation_id = %correlation_id,
            status = %response.status().as_u16(),
            "Request completed"
        );

        response
    })
    .await
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
