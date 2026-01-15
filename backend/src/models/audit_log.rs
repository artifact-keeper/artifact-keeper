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
    pub correlation_id: Uuid,
    pub created_at: DateTime<Utc>,
}
