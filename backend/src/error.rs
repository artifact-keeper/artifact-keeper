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
            | Self::QuotaExceeded(msg) => msg.clone(),
            Self::Json(_) => "Invalid JSON".to_string(),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, code) = self.status_and_code();
        let message = self.user_message();

        tracing::error!(error = %self, code = code, "Request error");

        let body = Json(json!({
            "code": code,
            "message": message,
        }));

        (status, body).into_response()
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
            &jsonwebtoken::Validation::default(),
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
    }
}
