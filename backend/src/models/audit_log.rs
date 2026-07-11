//! Audit log model.

use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::FromRow;
use uuid::Uuid;

/// Audit log entry
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct AuditLog {
    pub id: Uuid,
    pub user_id: Option<Uuid>,
    pub action: String,
    pub resource_type: String,
    pub resource_id: Option<Uuid>,
    pub details: Option<serde_json::Value>,
    pub ip_address: Option<String>,
    /// Request correlation ID (#2414): a caller-supplied `X-Correlation-ID`
    /// value, a W3C trace ID, or a generated UUID — a string, not a UUID.
    pub correlation_id: String,
    pub created_at: DateTime<Utc>,
}
