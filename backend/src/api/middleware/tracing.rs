//! Request tracing middleware with correlation ID support.
//!
//! Provides correlation ID generation and propagation for request tracing.

use axum::{
    extract::Request,
    http::header::HeaderValue,
    middleware::Next,
    response::Response,
};
use uuid::Uuid;

/// The header name for correlation IDs.
pub const CORRELATION_ID_HEADER: &str = "X-Correlation-ID";

/// Extension that holds the correlation ID for the current request.
///
/// This can be extracted in handlers to include the correlation ID in logs
/// or pass it to downstream services.
#[derive(Debug, Clone)]
pub struct CorrelationId(pub String);

impl CorrelationId {
    /// Create a new correlation ID from a string.
    pub fn new(id: String) -> Self {
        Self(id)
    }

    /// Generate a new random correlation ID.
    pub fn generate() -> Self {
        Self(Uuid::new_v4().to_string())
    }

    /// Get the correlation ID as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for CorrelationId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Correlation ID middleware.
///
/// This middleware:
/// 1. Extracts the X-Correlation-ID header from the request if present
/// 2. Generates a new UUID if the header is not present
/// 3. Adds the correlation ID to request extensions for handler access
/// 4. Includes the correlation ID in the response headers
/// 5. Logs the correlation ID with tracing
pub async fn correlation_id_middleware(
    mut request: Request,
    next: Next,
) -> Response {
    // Extract or generate correlation ID
    let correlation_id = request
        .headers()
        .get(CORRELATION_ID_HEADER)
        .and_then(|h| h.to_str().ok())
        .map(|s| CorrelationId::new(s.to_string()))
        .unwrap_or_else(CorrelationId::generate);

    // Log the correlation ID
    tracing::info!(
        correlation_id = %correlation_id,
        method = %request.method(),
        uri = %request.uri(),
        "Processing request"
    );

    // Add correlation ID to request extensions
    request.extensions_mut().insert(correlation_id.clone());

    // Process the request
    let mut response = next.run(request).await;

    // Add correlation ID to response headers
    if let Ok(value) = HeaderValue::from_str(correlation_id.as_str()) {
        response.headers_mut().insert(CORRELATION_ID_HEADER, value);
    }

    // Log response completion
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
        // Should be a valid UUID format
        assert!(Uuid::parse_str(id.as_str()).is_ok());
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
}
