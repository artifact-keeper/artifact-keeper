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

/// Application error types
#[derive(Error, Debug)]
pub enum AppError {
    /// Configuration error
    #[error("Configuration error: {0}")]
    Config(String),

    /// Database error
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    /// Migration error
    #[error("Migration error: {0}")]
    Migration(#[from] sqlx::migrate::MigrateError),

    /// Authentication error
    #[error("Authentication failed: {0}")]
    Authentication(String),

    /// Authorization error
    #[error("Access denied: {0}")]
    Authorization(String),

    /// Not found error
    #[error("Resource not found: {0}")]
    NotFound(String),

    /// Conflict error (e.g., duplicate artifact version)
    #[error("Conflict: {0}")]
    Conflict(String),

    /// Validation error
    #[error("Validation error: {0}")]
    Validation(String),

    /// Quota exceeded error
    #[error("Quota exceeded: {0}")]
    QuotaExceeded(String),

    /// Storage error
    #[error("Storage error: {0}")]
    Storage(String),

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Address parse error
    #[error("Address parse error: {0}")]
    AddrParse(#[from] std::net::AddrParseError),

    /// JSON error
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// JWT error
    #[error("JWT error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),

    /// Internal server error
    #[error("Internal error: {0}")]
    Internal(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, code, message) = match &self {
            AppError::Config(msg) => (StatusCode::INTERNAL_SERVER_ERROR, "CONFIG_ERROR", msg.clone()),
            AppError::Database(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "DATABASE_ERROR",
                "Database operation failed".to_string(),
            ),
            AppError::Migration(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "MIGRATION_ERROR",
                "Database migration failed".to_string(),
            ),
            AppError::Authentication(msg) => (StatusCode::UNAUTHORIZED, "AUTH_ERROR", msg.clone()),
            AppError::Authorization(msg) => (StatusCode::FORBIDDEN, "FORBIDDEN", msg.clone()),
            AppError::NotFound(msg) => (StatusCode::NOT_FOUND, "NOT_FOUND", msg.clone()),
            AppError::Conflict(msg) => (StatusCode::CONFLICT, "CONFLICT", msg.clone()),
            AppError::Validation(msg) => (StatusCode::BAD_REQUEST, "VALIDATION_ERROR", msg.clone()),
            AppError::QuotaExceeded(msg) => (StatusCode::INSUFFICIENT_STORAGE, "QUOTA_EXCEEDED", msg.clone()),
            AppError::Storage(msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "STORAGE_ERROR",
                msg.clone(),
            ),
            AppError::Io(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "IO_ERROR",
                "IO operation failed".to_string(),
            ),
            AppError::AddrParse(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "ADDR_PARSE_ERROR",
                "Invalid address".to_string(),
            ),
            AppError::Json(_) => (
                StatusCode::BAD_REQUEST,
                "JSON_ERROR",
                "Invalid JSON".to_string(),
            ),
            AppError::Jwt(_) => (StatusCode::UNAUTHORIZED, "JWT_ERROR", "Invalid token".to_string()),
            AppError::Internal(msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                msg.clone(),
            ),
        };

        // Log the error
        tracing::error!(error = %self, code = code, "Request error");

        let body = Json(json!({
            "code": code,
            "message": message,
        }));

        (status, body).into_response()
    }
}
