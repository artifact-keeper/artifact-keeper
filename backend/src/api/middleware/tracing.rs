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

/// Extension that holds the correlation ID for the current request.
#[derive(Debug, Clone)]
pub struct CorrelationId(pub String);

impl CorrelationId {
    pub fn new(id: String) -> Self {
        Self(id)
    }

    pub fn generate() -> Self {
        Self(Uuid::new_v4().to_string())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for CorrelationId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
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
        .map(|s| CorrelationId::new(s.to_string()))
        .or_else(|| {
            // Extract trace-id from traceparent header
            request
                .headers()
                .get(TRACEPARENT_HEADER)
                .and_then(|h| h.to_str().ok())
                .and_then(|tp| {
                    let parts: Vec<&str> = tp.split('-').collect();
                    if parts.len() >= 2 {
                        Some(CorrelationId::new(parts[1].to_string()))
                    } else {
                        None
                    }
                })
        })
        .unwrap_or_else(CorrelationId::generate);

    request.extensions_mut().insert(correlation_id.clone());

    tracing::Span::current().record("correlation_id", tracing::field::display(&correlation_id));

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
        let id = CorrelationId::new("my-custom-id".to_string());
        assert_eq!(id.as_str(), "my-custom-id");
    }

    #[test]
    fn test_correlation_id_display() {
        let id = CorrelationId::new("test-id".to_string());
        assert_eq!(format!("{}", id), "test-id");
    }

    #[test]
    fn test_correlation_id_clone() {
        let id = CorrelationId::new("clone-test".to_string());
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
}
