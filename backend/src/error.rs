//! Application error types and result alias.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use thiserror::Error;

/// Application result type alias
pub type Result<T> = std::result::Result<T, AppError>;

/// Application error types.
#[derive(Error, Debug)]
pub enum AppError {
    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Database error: {0}")]
    Database(String),

    #[error("Database error: {0}")]
    Sqlx(#[from] sqlx::Error),

    #[error("Migration error: {0}")]
    Migration(#[from] sqlx::migrate::MigrateError),

    #[error("Authentication failed: {0}")]
    Authentication(String),

    /// Missing credentials
    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Access denied: {0}")]
    Authorization(String),

    #[error("Resource not found: {0}")]
    NotFound(String),

    /// Duplicate resource (e.g., artifact version already exists)
    #[error("Conflict: {0}")]
    Conflict(String),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Quota exceeded: {0}")]
    QuotaExceeded(String),

    #[error("Storage error: {0}")]
    Storage(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Address parse error: {0}")]
    AddrParse(#[from] std::net::AddrParseError),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("JWT error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),

    #[error("Internal error: {0}")]
    Internal(String),

    #[error("WASM error: {0}")]
    Wasm(#[from] crate::services::wasm_runtime::WasmError),

    #[error("Bad gateway: {0}")]
    BadGateway(String),

    /// A required dependency or feature is not configured / not enabled on
    /// this deployment. Distinct from `Internal` (which is "the server
    /// failed unexpectedly") because operators alert on 500s but not on
    /// 503s, and clients can distinguish "feature off" from "server bug"
    /// by status code alone.
    #[error("Service unavailable: {0}")]
    ServiceUnavailable(String),

    /// Service is temporarily over capacity. Maps to HTTP 503 with a
    /// `Retry-After` header telling the client how long to back off.
    /// Used by the proxy service when the upstream-fetch semaphore queue
    /// saturates and `proxy_queue_timeout_secs` fires before a permit
    /// becomes available.
    ///
    /// Distinct from `ServiceUnavailable` (which is "feature is turned
    /// off / dependency missing") so the error code differs and clients
    /// can decide whether to back off and retry (`OVERLOADED`) versus
    /// escalate to the operator (`SERVICE_UNAVAILABLE`).
    ///
    /// The `message` is the public user-facing string (must NOT include
    /// capacity tunables — those leak useful info for DoS planning); the
    /// concrete limit and timeout get logged server-side via tracing.
    /// The `retry_after_secs` populates the `Retry-After` response header
    /// so well-behaved clients (cargo, npm, pip, kubelet) back off rather
    /// than retry-storm the moment they receive 503.
    #[error("Service overloaded: {message}")]
    Overloaded {
        message: String,
        retry_after_secs: u64,
    },
}

impl AppError {
    /// Map error variant to HTTP status code and machine-readable error code.
    fn status_and_code(&self) -> (StatusCode, &'static str) {
        match self {
            Self::Config(_) => (StatusCode::INTERNAL_SERVER_ERROR, "CONFIG_ERROR"),
            Self::Database(_) | Self::Sqlx(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "DATABASE_ERROR")
            }
            Self::Migration(_) => (StatusCode::INTERNAL_SERVER_ERROR, "MIGRATION_ERROR"),
            Self::Authentication(_) => (StatusCode::UNAUTHORIZED, "AUTH_ERROR"),
            Self::Unauthorized(_) => (StatusCode::UNAUTHORIZED, "UNAUTHORIZED"),
            Self::Authorization(_) => (StatusCode::FORBIDDEN, "FORBIDDEN"),
            Self::NotFound(_) => (StatusCode::NOT_FOUND, "NOT_FOUND"),
            Self::Conflict(_) => (StatusCode::CONFLICT, "CONFLICT"),
            Self::Validation(_) => (StatusCode::BAD_REQUEST, "VALIDATION_ERROR"),
            Self::QuotaExceeded(_) => (StatusCode::INSUFFICIENT_STORAGE, "QUOTA_EXCEEDED"),
            Self::Storage(_) => (StatusCode::INTERNAL_SERVER_ERROR, "STORAGE_ERROR"),
            Self::Io(_) => (StatusCode::INTERNAL_SERVER_ERROR, "IO_ERROR"),
            Self::AddrParse(_) => (StatusCode::INTERNAL_SERVER_ERROR, "ADDR_PARSE_ERROR"),
            Self::Json(_) => (StatusCode::BAD_REQUEST, "JSON_ERROR"),
            Self::Jwt(_) => (StatusCode::UNAUTHORIZED, "JWT_ERROR"),
            Self::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR"),
            Self::Wasm(_) => (StatusCode::INTERNAL_SERVER_ERROR, "WASM_ERROR"),
            Self::BadGateway(_) => (StatusCode::BAD_GATEWAY, "BAD_GATEWAY"),
            Self::ServiceUnavailable(_) => (StatusCode::SERVICE_UNAVAILABLE, "SERVICE_UNAVAILABLE"),
            Self::Overloaded { .. } => (StatusCode::SERVICE_UNAVAILABLE, "OVERLOADED"),
        }
    }

    /// Return a user-facing message. Internal details are hidden for server-side
    /// errors to avoid leaking table names, SQL queries, file paths, or config
    /// values. The full error is still logged via `tracing::error!` in
    /// `into_response`.
    fn user_message(&self) -> String {
        match self {
            // Server-side errors: return generic messages (details are logged)
            Self::Database(_) | Self::Sqlx(_) => "Database operation failed".to_string(),
            Self::Migration(_) => "Database migration failed".to_string(),
            Self::Storage(_) => "Storage operation failed".to_string(),
            Self::Config(_) => "Server configuration error".to_string(),
            Self::Internal(_) => "Internal server error".to_string(),
            Self::Io(_) => "IO operation failed".to_string(),
            Self::AddrParse(_) => "Invalid address".to_string(),
            Self::Jwt(_) => "Invalid token".to_string(),
            Self::Wasm(_) => "Plugin execution failed".to_string(),
            // Client-facing errors: pass through their message
            Self::Authentication(msg)
            | Self::Unauthorized(msg)
            | Self::Authorization(msg)
            | Self::NotFound(msg)
            | Self::Conflict(msg)
            | Self::Validation(msg)
            | Self::QuotaExceeded(msg)
            | Self::BadGateway(msg)
            | Self::ServiceUnavailable(msg) => msg.clone(),
            Self::Overloaded { message, .. } => message.clone(),
            Self::Json(_) => "Invalid JSON".to_string(),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, code) = self.status_and_code();
        let message = self.user_message();

        tracing::error!(error = %self, code = code, "Request error");

        // Capacity-class errors (503 Overloaded) emit a Retry-After header
        // so well-behaved clients back off instead of retry-storming the
        // moment they receive 503. Without this, a saturated proxy turns
        // its own self-defense into a self-DoS via client retry loops.
        let retry_after = match &self {
            Self::Overloaded {
                retry_after_secs, ..
            } => Some(*retry_after_secs),
            _ => None,
        };

        let body = Json(json!({
            "code": code,
            "message": message,
        }));

        let mut response = (status, body).into_response();
        if let Some(secs) = retry_after {
            if let Ok(value) = axum::http::HeaderValue::from_str(&secs.to_string()) {
                response.headers_mut().insert("Retry-After", value);
            }
        }
        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Server-side errors: user_message must NOT leak internal details
    // -----------------------------------------------------------------------

    #[test]
    fn test_database_error_hides_details() {
        let err = AppError::Database("SELECT * FROM users WHERE id = 42".into());
        assert_eq!(err.user_message(), "Database operation failed");
        assert!(!err.user_message().contains("SELECT"));
    }

    #[test]
    fn test_storage_error_hides_details() {
        let err = AppError::Storage("/var/data/artifacts/secret-file.tar".into());
        assert_eq!(err.user_message(), "Storage operation failed");
        assert!(!err.user_message().contains("/var"));
    }

    #[test]
    fn test_config_error_hides_details() {
        let err = AppError::Config("AWS_SECRET_KEY is invalid".into());
        assert_eq!(err.user_message(), "Server configuration error");
        assert!(!err.user_message().contains("AWS"));
    }

    #[test]
    fn test_internal_error_hides_details() {
        let err = AppError::Internal("stack trace at 0x7fff".into());
        assert_eq!(err.user_message(), "Internal server error");
        assert!(!err.user_message().contains("stack"));
    }

    #[test]
    fn test_io_error_hides_details() {
        let err = AppError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "/etc/shadow: permission denied",
        ));
        assert_eq!(err.user_message(), "IO operation failed");
        assert!(!err.user_message().contains("/etc"));
    }

    #[test]
    fn test_jwt_error_hides_details() {
        // Construct a JWT error by decoding garbage
        let err: jsonwebtoken::errors::Error = jsonwebtoken::decode::<serde_json::Value>(
            "not-a-token",
            &jsonwebtoken::DecodingKey::from_secret(b"x"),
            &jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256),
        )
        .unwrap_err();
        let app_err = AppError::Jwt(err);
        assert_eq!(app_err.user_message(), "Invalid token");
    }

    // -----------------------------------------------------------------------
    // Client-facing errors: user_message passes through
    // -----------------------------------------------------------------------

    #[test]
    fn test_authentication_passes_through() {
        let err = AppError::Authentication("bad credentials".into());
        assert_eq!(err.user_message(), "bad credentials");
    }

    #[test]
    fn test_not_found_passes_through() {
        let err = AppError::NotFound("artifact foo:1.0 not found".into());
        assert_eq!(err.user_message(), "artifact foo:1.0 not found");
    }

    #[test]
    fn test_validation_passes_through() {
        let err = AppError::Validation("name is required".into());
        assert_eq!(err.user_message(), "name is required");
    }

    #[test]
    fn test_conflict_passes_through() {
        let err = AppError::Conflict("version already exists".into());
        assert_eq!(err.user_message(), "version already exists");
    }

    #[test]
    fn test_quota_exceeded_passes_through() {
        let err = AppError::QuotaExceeded("storage limit reached".into());
        assert_eq!(err.user_message(), "storage limit reached");
    }

    #[test]
    fn test_service_unavailable_passes_through() {
        let err = AppError::ServiceUnavailable("Scanner service not configured".into());
        assert_eq!(err.user_message(), "Scanner service not configured");
        assert_eq!(
            err.to_string(),
            "Service unavailable: Scanner service not configured"
        );
    }

    // -----------------------------------------------------------------------
    // HTTP status codes
    // -----------------------------------------------------------------------

    #[test]
    fn test_status_codes() {
        assert_eq!(
            AppError::Database("x".into()).status_and_code().0,
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            AppError::Authentication("x".into()).status_and_code().0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            AppError::Authorization("x".into()).status_and_code().0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            AppError::NotFound("x".into()).status_and_code().0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            AppError::Conflict("x".into()).status_and_code().0,
            StatusCode::CONFLICT
        );
        assert_eq!(
            AppError::Validation("x".into()).status_and_code().0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            AppError::QuotaExceeded("x".into()).status_and_code().0,
            StatusCode::INSUFFICIENT_STORAGE
        );
        assert_eq!(
            AppError::BadGateway("x".into()).status_and_code().0,
            StatusCode::BAD_GATEWAY
        );
        assert_eq!(
            AppError::BadGateway("x".into()).status_and_code().1,
            "BAD_GATEWAY"
        );
        assert_eq!(
            AppError::ServiceUnavailable("x".into()).status_and_code().0,
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            AppError::ServiceUnavailable("x".into()).status_and_code().1,
            "SERVICE_UNAVAILABLE"
        );
    }

    #[test]
    fn test_bad_gateway_message() {
        let err = AppError::BadGateway("upstream failed".to_string());
        assert_eq!(err.user_message(), "upstream failed");
        assert_eq!(err.to_string(), "Bad gateway: upstream failed");
    }
}
