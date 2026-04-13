//! Repository notification subscription handlers.
//!
//! Allows repository administrators to create, list, and delete notification
//! subscriptions scoped to a repository. Each subscription specifies a delivery
//! channel (email or webhook), a set of event types to listen for, and
//! channel-specific configuration (recipient addresses, webhook URLs, etc.).

use axum::{
    extract::{Path, State},
    routing::get,
    Json, Router,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use utoipa::{OpenApi, ToSchema};
use uuid::Uuid;

use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::error::{AppError, Result};
use crate::services::repository_service::RepositoryService;

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

/// Routes nested under /api/v1/repositories/:key/notifications
pub fn repo_notifications_router() -> Router<SharedState> {
    Router::new()
        .route(
            "/:key/notifications",
            get(list_subscriptions).post(create_subscription),
        )
        .route(
            "/:key/notifications/:subscription_id",
            axum::routing::delete(delete_subscription),
        )
}

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

/// Supported notification delivery channels.
pub const VALID_CHANNELS: &[&str] = &["email", "webhook"];

/// Event types that can trigger notifications.
pub const VALID_EVENT_TYPES: &[&str] = &[
    "artifact.uploaded",
    "artifact.deleted",
    "scan.completed",
    "scan.vulnerability_found",
    "repository.updated",
    "repository.deleted",
    "build.completed",
    "build.failed",
];

/// Request to create a notification subscription on a repository.
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateNotificationSubscriptionRequest {
    /// Delivery channel: "email" or "webhook".
    pub channel: String,
    /// Event types that trigger this notification (e.g. "artifact.uploaded").
    pub event_types: Vec<String>,
    /// Channel-specific configuration.
    /// For email: `{"recipients": ["admin@example.com"]}`.
    /// For webhook: `{"url": "https://hooks.example.com/notify", "secret": "..."}`.
    #[schema(value_type = Object)]
    pub config: serde_json::Value,
}

/// A notification subscription record.
#[derive(Debug, Serialize, ToSchema)]
pub struct NotificationSubscriptionResponse {
    pub id: Uuid,
    pub repository_id: Option<Uuid>,
    pub channel: String,
    pub event_types: Vec<String>,
    #[schema(value_type = Object)]
    pub config: serde_json::Value,
    pub enabled: bool,
    pub created_by: Uuid,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// List of notification subscriptions on a repository.
#[derive(Debug, Serialize, ToSchema)]
pub struct NotificationSubscriptionListResponse {
    pub items: Vec<NotificationSubscriptionResponse>,
}

// ---------------------------------------------------------------------------
// Pure validation helpers
// ---------------------------------------------------------------------------

/// Validate that the channel is one of the supported values.
pub(crate) fn validate_channel(channel: &str) -> Result<()> {
    if VALID_CHANNELS.contains(&channel) {
        Ok(())
    } else {
        Err(AppError::Validation(format!(
            "Invalid channel '{}'. Must be one of: {}",
            channel,
            VALID_CHANNELS.join(", ")
        )))
    }
}

/// Validate that all event types are recognized.
pub(crate) fn validate_event_types(event_types: &[String]) -> Result<()> {
    if event_types.is_empty() {
        return Err(AppError::Validation(
            "At least one event type is required".to_string(),
        ));
    }
    for et in event_types {
        if !VALID_EVENT_TYPES.contains(&et.as_str()) {
            return Err(AppError::Validation(format!(
                "Unknown event type '{}'. Valid types: {}",
                et,
                VALID_EVENT_TYPES.join(", ")
            )));
        }
    }
    Ok(())
}

/// Validate channel-specific config fields.
pub(crate) fn validate_config(channel: &str, config: &serde_json::Value) -> Result<()> {
    match channel {
        "email" => {
            let recipients = config
                .get("recipients")
                .and_then(|v| v.as_array())
                .ok_or_else(|| {
                    AppError::Validation(
                        "Email config must include a 'recipients' array".to_string(),
                    )
                })?;
            if recipients.is_empty() {
                return Err(AppError::Validation(
                    "At least one email recipient is required".to_string(),
                ));
            }
            for r in recipients {
                if r.as_str().map_or(true, |s| !s.contains('@')) {
                    return Err(AppError::Validation(format!(
                        "Invalid email recipient: {}",
                        r
                    )));
                }
            }
            Ok(())
        }
        "webhook" => {
            let url = config.get("url").and_then(|v| v.as_str()).ok_or_else(|| {
                AppError::Validation("Webhook config must include a 'url' string".to_string())
            })?;
            if !url.starts_with("http://") && !url.starts_with("https://") {
                return Err(AppError::Validation(
                    "Webhook URL must start with http:// or https://".to_string(),
                ));
            }
            Ok(())
        }
        _ => Err(AppError::Validation(format!(
            "Unknown channel '{}'",
            channel
        ))),
    }
}

/// Require that the request is authenticated with write access or admin.
fn require_repo_write(auth: Option<AuthExtension>) -> Result<AuthExtension> {
    let auth =
        auth.ok_or_else(|| AppError::Authentication("Authentication required".to_string()))?;
    if auth.is_admin {
        return Ok(auth);
    }
    auth.require_scope("write:repositories")?;
    Ok(auth)
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// List notification subscriptions for a repository.
#[utoipa::path(
    get,
    path = "/{key}/notifications",
    context_path = "/api/v1/repositories",
    tag = "notifications",
    params(("key" = String, Path, description = "Repository key")),
    responses(
        (status = 200, description = "List of notification subscriptions", body = NotificationSubscriptionListResponse),
        (status = 401, description = "Not authenticated"),
        (status = 404, description = "Repository not found"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_subscriptions(
    State(state): State<SharedState>,
    auth: Option<axum::extract::Extension<AuthExtension>>,
    Path(key): Path<String>,
) -> Result<Json<NotificationSubscriptionListResponse>> {
    let _auth = require_repo_write(auth.map(|e| e.0))?;

    let repo_service = RepositoryService::new(state.db.clone());
    let repo = repo_service.get_by_key(&key).await?;

    let rows = sqlx::query(
        r#"
        SELECT id, repository_id, channel, event_types, config, enabled,
               created_by, created_at, updated_at
        FROM notification_subscriptions
        WHERE repository_id = $1
        ORDER BY created_at DESC
        "#,
    )
    .bind(repo.id)
    .fetch_all(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let items = rows
        .into_iter()
        .map(|row| NotificationSubscriptionResponse {
            id: row.get("id"),
            repository_id: row.get("repository_id"),
            channel: row.get("channel"),
            event_types: row.get("event_types"),
            config: row.get("config"),
            enabled: row.get("enabled"),
            created_by: row.get("created_by"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        })
        .collect();

    Ok(Json(NotificationSubscriptionListResponse { items }))
}

/// Create a notification subscription on a repository.
#[utoipa::path(
    post,
    path = "/{key}/notifications",
    context_path = "/api/v1/repositories",
    tag = "notifications",
    params(("key" = String, Path, description = "Repository key")),
    request_body = CreateNotificationSubscriptionRequest,
    responses(
        (status = 201, description = "Subscription created", body = NotificationSubscriptionResponse),
        (status = 400, description = "Validation error"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Insufficient permissions"),
        (status = 404, description = "Repository not found"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_subscription(
    State(state): State<SharedState>,
    auth: Option<axum::extract::Extension<AuthExtension>>,
    Path(key): Path<String>,
    Json(req): Json<CreateNotificationSubscriptionRequest>,
) -> Result<(
    axum::http::StatusCode,
    Json<NotificationSubscriptionResponse>,
)> {
    let auth = require_repo_write(auth.map(|e| e.0))?;

    validate_channel(&req.channel)?;
    validate_event_types(&req.event_types)?;
    validate_config(&req.channel, &req.config)?;

    let repo_service = RepositoryService::new(state.db.clone());
    let repo = repo_service.get_by_key(&key).await?;

    let id = Uuid::new_v4();
    let now = Utc::now();

    sqlx::query(
        r#"
        INSERT INTO notification_subscriptions
            (id, repository_id, channel, event_types, config, enabled, created_by, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, true, $6, $7, $7)
        "#,
    )
    .bind(id)
    .bind(repo.id)
    .bind(&req.channel)
    .bind(&req.event_types)
    .bind(&req.config)
    .bind(auth.user_id)
    .bind(now)
    .execute(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let response = NotificationSubscriptionResponse {
        id,
        repository_id: Some(repo.id),
        channel: req.channel,
        event_types: req.event_types,
        config: req.config,
        enabled: true,
        created_by: auth.user_id,
        created_at: now,
        updated_at: now,
    };

    Ok((axum::http::StatusCode::CREATED, Json(response)))
}

/// Delete a notification subscription from a repository.
#[utoipa::path(
    delete,
    path = "/{key}/notifications/{subscription_id}",
    context_path = "/api/v1/repositories",
    tag = "notifications",
    params(
        ("key" = String, Path, description = "Repository key"),
        ("subscription_id" = Uuid, Path, description = "Subscription ID"),
    ),
    responses(
        (status = 204, description = "Subscription deleted"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Insufficient permissions"),
        (status = 404, description = "Subscription or repository not found"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_subscription(
    State(state): State<SharedState>,
    auth: Option<axum::extract::Extension<AuthExtension>>,
    Path((key, subscription_id)): Path<(String, Uuid)>,
) -> Result<axum::http::StatusCode> {
    let _auth = require_repo_write(auth.map(|e| e.0))?;

    let repo_service = RepositoryService::new(state.db.clone());
    let repo = repo_service.get_by_key(&key).await?;

    let result =
        sqlx::query("DELETE FROM notification_subscriptions WHERE id = $1 AND repository_id = $2")
            .bind(subscription_id)
            .bind(repo.id)
            .execute(&state.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound(
            "Notification subscription not found".to_string(),
        ));
    }

    Ok(axum::http::StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// OpenAPI
// ---------------------------------------------------------------------------

#[derive(OpenApi)]
#[openapi(
    paths(
        list_subscriptions,
        create_subscription,
        delete_subscription,
    ),
    components(schemas(
        CreateNotificationSubscriptionRequest,
        NotificationSubscriptionResponse,
        NotificationSubscriptionListResponse,
    )),
    tags(
        (name = "notifications", description = "Repository notification subscription management"),
    )
)]
pub struct NotificationsApiDoc;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // validate_channel
    // -----------------------------------------------------------------------

    #[test]
    fn test_validate_channel_email() {
        assert!(validate_channel("email").is_ok());
    }

    #[test]
    fn test_validate_channel_webhook() {
        assert!(validate_channel("webhook").is_ok());
    }

    #[test]
    fn test_validate_channel_invalid() {
        let err = validate_channel("sms").unwrap_err();
        assert!(err.to_string().contains("Invalid channel"));
    }

    #[test]
    fn test_validate_channel_empty() {
        assert!(validate_channel("").is_err());
    }

    // -----------------------------------------------------------------------
    // validate_event_types
    // -----------------------------------------------------------------------

    #[test]
    fn test_validate_event_types_valid() {
        let types = vec![
            "artifact.uploaded".to_string(),
            "scan.completed".to_string(),
        ];
        assert!(validate_event_types(&types).is_ok());
    }

    #[test]
    fn test_validate_event_types_empty() {
        let err = validate_event_types(&[]).unwrap_err();
        assert!(err.to_string().contains("At least one event type"));
    }

    #[test]
    fn test_validate_event_types_unknown() {
        let types = vec!["artifact.uploaded".to_string(), "unknown.event".to_string()];
        let err = validate_event_types(&types).unwrap_err();
        assert!(err.to_string().contains("Unknown event type"));
    }

    #[test]
    fn test_validate_event_types_all_valid() {
        let types: Vec<String> = VALID_EVENT_TYPES.iter().map(|s| s.to_string()).collect();
        assert!(validate_event_types(&types).is_ok());
    }

    // -----------------------------------------------------------------------
    // validate_config - email
    // -----------------------------------------------------------------------

    #[test]
    fn test_validate_config_email_valid() {
        let config = serde_json::json!({"recipients": ["admin@example.com"]});
        assert!(validate_config("email", &config).is_ok());
    }

    #[test]
    fn test_validate_config_email_multiple_recipients() {
        let config = serde_json::json!({"recipients": ["a@b.com", "c@d.com"]});
        assert!(validate_config("email", &config).is_ok());
    }

    #[test]
    fn test_validate_config_email_missing_recipients() {
        let config = serde_json::json!({});
        let err = validate_config("email", &config).unwrap_err();
        assert!(err.to_string().contains("recipients"));
    }

    #[test]
    fn test_validate_config_email_empty_recipients() {
        let config = serde_json::json!({"recipients": []});
        let err = validate_config("email", &config).unwrap_err();
        assert!(err.to_string().contains("At least one email recipient"));
    }

    #[test]
    fn test_validate_config_email_invalid_address() {
        let config = serde_json::json!({"recipients": ["not-an-email"]});
        let err = validate_config("email", &config).unwrap_err();
        assert!(err.to_string().contains("Invalid email recipient"));
    }

    // -----------------------------------------------------------------------
    // validate_config - webhook
    // -----------------------------------------------------------------------

    #[test]
    fn test_validate_config_webhook_valid_https() {
        let config = serde_json::json!({"url": "https://hooks.example.com/notify"});
        assert!(validate_config("webhook", &config).is_ok());
    }

    #[test]
    fn test_validate_config_webhook_valid_http() {
        let config = serde_json::json!({"url": "http://internal.example.com/hook"});
        assert!(validate_config("webhook", &config).is_ok());
    }

    #[test]
    fn test_validate_config_webhook_missing_url() {
        let config = serde_json::json!({});
        let err = validate_config("webhook", &config).unwrap_err();
        assert!(err.to_string().contains("url"));
    }

    #[test]
    fn test_validate_config_webhook_invalid_url() {
        let config = serde_json::json!({"url": "ftp://invalid.com"});
        let err = validate_config("webhook", &config).unwrap_err();
        assert!(err.to_string().contains("http://"));
    }

    #[test]
    fn test_validate_config_webhook_with_secret() {
        let config = serde_json::json!({
            "url": "https://hooks.example.com/notify",
            "secret": "my-secret-value"
        });
        assert!(validate_config("webhook", &config).is_ok());
    }

    // -----------------------------------------------------------------------
    // validate_config - unknown channel
    // -----------------------------------------------------------------------

    #[test]
    fn test_validate_config_unknown_channel() {
        let config = serde_json::json!({});
        assert!(validate_config("sms", &config).is_err());
    }

    // -----------------------------------------------------------------------
    // Constants coverage
    // -----------------------------------------------------------------------

    #[test]
    fn test_valid_channels_contains_expected() {
        assert!(VALID_CHANNELS.contains(&"email"));
        assert!(VALID_CHANNELS.contains(&"webhook"));
        assert_eq!(VALID_CHANNELS.len(), 2);
    }

    #[test]
    fn test_valid_event_types_not_empty() {
        assert!(!VALID_EVENT_TYPES.is_empty());
        assert!(VALID_EVENT_TYPES.len() >= 8);
    }

    #[test]
    fn test_valid_event_types_contain_core_events() {
        assert!(VALID_EVENT_TYPES.contains(&"artifact.uploaded"));
        assert!(VALID_EVENT_TYPES.contains(&"artifact.deleted"));
        assert!(VALID_EVENT_TYPES.contains(&"scan.completed"));
        assert!(VALID_EVENT_TYPES.contains(&"scan.vulnerability_found"));
    }

    // -----------------------------------------------------------------------
    // Response serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_subscription_response_serializes() {
        let resp = NotificationSubscriptionResponse {
            id: Uuid::nil(),
            repository_id: Some(Uuid::nil()),
            channel: "email".to_string(),
            event_types: vec!["artifact.uploaded".to_string()],
            config: serde_json::json!({"recipients": ["admin@example.com"]}),
            enabled: true,
            created_by: Uuid::nil(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("email"));
        assert!(json.contains("artifact.uploaded"));
        assert!(json.contains("admin@example.com"));
    }

    #[test]
    fn test_list_response_serializes() {
        let list = NotificationSubscriptionListResponse { items: vec![] };
        let json = serde_json::to_string(&list).unwrap();
        assert!(json.contains("items"));
    }

    #[test]
    fn test_create_request_deserializes() {
        let json = r#"{
            "channel": "email",
            "event_types": ["artifact.uploaded"],
            "config": {"recipients": ["user@example.com"]}
        }"#;
        let req: CreateNotificationSubscriptionRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.channel, "email");
        assert_eq!(req.event_types.len(), 1);
    }

    #[test]
    fn test_create_request_webhook_deserializes() {
        let json = r#"{
            "channel": "webhook",
            "event_types": ["build.completed", "build.failed"],
            "config": {"url": "https://hooks.example.com/notify"}
        }"#;
        let req: CreateNotificationSubscriptionRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.channel, "webhook");
        assert_eq!(req.event_types.len(), 2);
    }
}
