//! Webhook management handlers.

use axum::{
    extract::{Extension, Path, Query, State},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, OpenApi, ToSchema};
use uuid::Uuid;

use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::error::{AppError, Result};

/// Create webhook routes
pub fn router() -> Router<SharedState> {
    Router::new()
        .route("/", get(list_webhooks).post(create_webhook))
        .route("/:id", get(get_webhook).delete(delete_webhook))
        .route("/:id/enable", post(enable_webhook))
        .route("/:id/disable", post(disable_webhook))
        .route("/:id/test", post(test_webhook))
        .route("/:id/deliveries", get(list_deliveries))
        .route("/:id/deliveries/:delivery_id/redeliver", post(redeliver))
}

/// Webhook event types
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum WebhookEvent {
    ArtifactUploaded,
    ArtifactDeleted,
    RepositoryCreated,
    RepositoryDeleted,
    UserCreated,
    UserDeleted,
    BuildStarted,
    BuildCompleted,
    BuildFailed,
}

impl std::fmt::Display for WebhookEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WebhookEvent::ArtifactUploaded => write!(f, "artifact_uploaded"),
            WebhookEvent::ArtifactDeleted => write!(f, "artifact_deleted"),
            WebhookEvent::RepositoryCreated => write!(f, "repository_created"),
            WebhookEvent::RepositoryDeleted => write!(f, "repository_deleted"),
            WebhookEvent::UserCreated => write!(f, "user_created"),
            WebhookEvent::UserDeleted => write!(f, "user_deleted"),
            WebhookEvent::BuildStarted => write!(f, "build_started"),
            WebhookEvent::BuildCompleted => write!(f, "build_completed"),
            WebhookEvent::BuildFailed => write!(f, "build_failed"),
        }
    }
}

#[derive(Debug, Deserialize, IntoParams)]
pub struct ListWebhooksQuery {
    pub repository_id: Option<Uuid>,
    pub enabled: Option<bool>,
    pub page: Option<u32>,
    pub per_page: Option<u32>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateWebhookRequest {
    pub name: String,
    pub url: String,
    pub events: Vec<String>,
    pub secret: Option<String>,
    pub repository_id: Option<Uuid>,
    #[schema(value_type = Option<Object>)]
    pub headers: Option<serde_json::Value>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct WebhookResponse {
    pub id: Uuid,
    pub name: String,
    pub url: String,
    pub events: Vec<String>,
    pub is_enabled: bool,
    pub repository_id: Option<Uuid>,
    #[schema(value_type = Option<Object>)]
    pub headers: Option<serde_json::Value>,
    pub last_triggered_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct WebhookListResponse {
    pub items: Vec<WebhookResponse>,
    pub total: i64,
}

/// List webhooks
#[utoipa::path(
    get,
    path = "",
    context_path = "/api/v1/webhooks",
    tag = "webhooks",
    params(ListWebhooksQuery),
    responses(
        (status = 200, description = "List of webhooks", body = WebhookListResponse),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_webhooks(
    State(state): State<SharedState>,
    Query(query): Query<ListWebhooksQuery>,
) -> Result<Json<WebhookListResponse>> {
    let page = query.page.unwrap_or(1).max(1);
    let per_page = query.per_page.unwrap_or(20).min(100);
    let offset = ((page - 1) * per_page) as i64;

    let webhooks = sqlx::query!(
        r#"
        SELECT id, name, url, events, is_enabled, repository_id, headers, last_triggered_at, created_at
        FROM webhooks
        WHERE ($1::uuid IS NULL OR repository_id = $1)
          AND ($2::boolean IS NULL OR is_enabled = $2)
        ORDER BY name
        OFFSET $3
        LIMIT $4
        "#,
        query.repository_id,
        query.enabled,
        offset,
        per_page as i64
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let total = sqlx::query_scalar!(
        r#"
        SELECT COUNT(*) as "count!"
        FROM webhooks
        WHERE ($1::uuid IS NULL OR repository_id = $1)
          AND ($2::boolean IS NULL OR is_enabled = $2)
        "#,
        query.repository_id,
        query.enabled
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let items = webhooks
        .into_iter()
        .map(|w| WebhookResponse {
            id: w.id,
            name: w.name,
            url: w.url,
            events: w.events,
            is_enabled: w.is_enabled,
            repository_id: w.repository_id,
            headers: w.headers,
            last_triggered_at: w.last_triggered_at,
            created_at: w.created_at,
        })
        .collect();

    Ok(Json(WebhookListResponse { items, total }))
}

/// Create webhook
#[utoipa::path(
    post,
    path = "",
    context_path = "/api/v1/webhooks",
    tag = "webhooks",
    request_body = CreateWebhookRequest,
    responses(
        (status = 200, description = "Webhook created successfully", body = WebhookResponse),
        (status = 422, description = "Validation error"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_webhook(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
    Json(payload): Json<CreateWebhookRequest>,
) -> Result<Json<WebhookResponse>> {
    // Validate URL (SSRF prevention)
    validate_webhook_url(&payload.url)?;

    // Validate events
    if payload.events.is_empty() {
        return Err(AppError::Validation(
            "At least one event required".to_string(),
        ));
    }

    // Hash secret if provided
    let secret_hash = if let Some(ref secret) = payload.secret {
        Some(crate::services::auth_service::AuthService::hash_password(
            secret,
        )?)
    } else {
        None
    };

    let webhook = sqlx::query!(
        r#"
        INSERT INTO webhooks (name, url, events, secret_hash, repository_id, headers)
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING id, name, url, events, is_enabled, repository_id, headers, last_triggered_at, created_at
        "#,
        payload.name,
        payload.url,
        &payload.events,
        secret_hash,
        payload.repository_id,
        payload.headers
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(Json(WebhookResponse {
        id: webhook.id,
        name: webhook.name,
        url: webhook.url,
        events: webhook.events,
        is_enabled: webhook.is_enabled,
        repository_id: webhook.repository_id,
        headers: webhook.headers,
        last_triggered_at: webhook.last_triggered_at,
        created_at: webhook.created_at,
    }))
}

/// Get webhook by ID
#[utoipa::path(
    get,
    path = "/{id}",
    context_path = "/api/v1/webhooks",
    tag = "webhooks",
    params(
        ("id" = Uuid, Path, description = "Webhook ID")
    ),
    responses(
        (status = 200, description = "Webhook details", body = WebhookResponse),
        (status = 404, description = "Webhook not found")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_webhook(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
) -> Result<Json<WebhookResponse>> {
    let webhook = sqlx::query!(
        r#"
        SELECT id, name, url, events, is_enabled, repository_id, headers, last_triggered_at, created_at
        FROM webhooks
        WHERE id = $1
        "#,
        id
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?
    .ok_or_else(|| AppError::NotFound("Webhook not found".to_string()))?;

    Ok(Json(WebhookResponse {
        id: webhook.id,
        name: webhook.name,
        url: webhook.url,
        events: webhook.events,
        is_enabled: webhook.is_enabled,
        repository_id: webhook.repository_id,
        headers: webhook.headers,
        last_triggered_at: webhook.last_triggered_at,
        created_at: webhook.created_at,
    }))
}

/// Delete webhook
#[utoipa::path(
    delete,
    path = "/{id}",
    context_path = "/api/v1/webhooks",
    tag = "webhooks",
    params(
        ("id" = Uuid, Path, description = "Webhook ID")
    ),
    responses(
        (status = 200, description = "Webhook deleted successfully"),
        (status = 404, description = "Webhook not found")
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_webhook(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<()> {
    let result = sqlx::query!("DELETE FROM webhooks WHERE id = $1", id)
        .execute(&state.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound("Webhook not found".to_string()));
    }

    Ok(())
}

/// Set webhook enabled state, returning NotFound if the webhook does not exist.
async fn set_webhook_enabled(state: &SharedState, id: Uuid, enabled: bool) -> Result<()> {
    let result = sqlx::query("UPDATE webhooks SET is_enabled = $2 WHERE id = $1")
        .bind(id)
        .bind(enabled)
        .execute(&state.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound("Webhook not found".to_string()));
    }

    Ok(())
}

/// Enable webhook
#[utoipa::path(
    post,
    path = "/{id}/enable",
    context_path = "/api/v1/webhooks",
    tag = "webhooks",
    params(
        ("id" = Uuid, Path, description = "Webhook ID")
    ),
    responses(
        (status = 200, description = "Webhook enabled successfully"),
        (status = 404, description = "Webhook not found")
    ),
    security(("bearer_auth" = []))
)]
pub async fn enable_webhook(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<()> {
    set_webhook_enabled(&state, id, true).await
}

/// Disable webhook
#[utoipa::path(
    post,
    path = "/{id}/disable",
    context_path = "/api/v1/webhooks",
    tag = "webhooks",
    params(
        ("id" = Uuid, Path, description = "Webhook ID")
    ),
    responses(
        (status = 200, description = "Webhook disabled successfully"),
        (status = 404, description = "Webhook not found")
    ),
    security(("bearer_auth" = []))
)]
pub async fn disable_webhook(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<()> {
    set_webhook_enabled(&state, id, false).await
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TestWebhookResponse {
    pub success: bool,
    pub status_code: Option<u16>,
    pub response_body: Option<String>,
    pub error: Option<String>,
}

/// Test webhook by sending a test payload
#[utoipa::path(
    post,
    path = "/{id}/test",
    context_path = "/api/v1/webhooks",
    tag = "webhooks",
    params(
        ("id" = Uuid, Path, description = "Webhook ID")
    ),
    responses(
        (status = 200, description = "Test delivery result", body = TestWebhookResponse),
        (status = 404, description = "Webhook not found")
    ),
    security(("bearer_auth" = []))
)]
pub async fn test_webhook(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<Json<TestWebhookResponse>> {
    let webhook = sqlx::query!(
        "SELECT url, headers, secret_hash FROM webhooks WHERE id = $1",
        id
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?
    .ok_or_else(|| AppError::NotFound("Webhook not found".to_string()))?;

    // Create test payload
    let payload = serde_json::json!({
        "event": "test",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "data": {
            "message": "This is a test webhook delivery"
        }
    });

    // Re-validate URL at delivery time to prevent DNS rebinding attacks
    validate_webhook_url(&webhook.url)?;

    // Send webhook
    let client = reqwest::Client::new();
    let mut request = client
        .post(&webhook.url)
        .header("Content-Type", "application/json")
        .header("X-Webhook-Event", "test");

    // Add custom headers
    if let Some(headers) = webhook.headers {
        if let Some(obj) = headers.as_object() {
            for (key, value) in obj {
                if let Some(v) = value.as_str() {
                    request = request.header(key.as_str(), v);
                }
            }
        }
    }

    // Add signature if secret exists
    if let Some(ref _secret_hash) = webhook.secret_hash {
        // In production, would sign payload with HMAC-SHA256
        request = request.header("X-Webhook-Signature", "test-signature");
    }

    match request.json(&payload).send().await {
        Ok(response) => {
            let status = response.status().as_u16();
            let body = response.text().await.ok();

            Ok(Json(TestWebhookResponse {
                success: (200..300).contains(&status),
                status_code: Some(status),
                response_body: body,
                error: None,
            }))
        }
        Err(e) => Ok(Json(TestWebhookResponse {
            success: false,
            status_code: None,
            response_body: None,
            error: Some(e.to_string()),
        })),
    }
}

#[derive(Debug, Deserialize, IntoParams)]
pub struct ListDeliveriesQuery {
    pub status: Option<String>,
    pub page: Option<u32>,
    pub per_page: Option<u32>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct DeliveryResponse {
    pub id: Uuid,
    pub webhook_id: Uuid,
    pub event: String,
    #[schema(value_type = Object)]
    pub payload: serde_json::Value,
    pub response_status: Option<i32>,
    pub response_body: Option<String>,
    pub success: bool,
    pub attempts: i32,
    pub delivered_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct DeliveryListResponse {
    pub items: Vec<DeliveryResponse>,
    pub total: i64,
}

/// List webhook deliveries
#[utoipa::path(
    get,
    path = "/{id}/deliveries",
    context_path = "/api/v1/webhooks",
    tag = "webhooks",
    params(
        ("id" = Uuid, Path, description = "Webhook ID"),
        ListDeliveriesQuery,
    ),
    responses(
        (status = 200, description = "List of webhook deliveries", body = DeliveryListResponse),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_deliveries(
    State(state): State<SharedState>,
    Path(webhook_id): Path<Uuid>,
    Query(query): Query<ListDeliveriesQuery>,
) -> Result<Json<DeliveryListResponse>> {
    let page = query.page.unwrap_or(1).max(1);
    let per_page = query.per_page.unwrap_or(20).min(100);
    let offset = ((page - 1) * per_page) as i64;

    let success_filter = query.status.as_ref().map(|s| s == "success");

    let deliveries = sqlx::query!(
        r#"
        SELECT id, webhook_id, event, payload, response_status, response_body, success, attempts, delivered_at, created_at
        FROM webhook_deliveries
        WHERE webhook_id = $1
          AND ($2::boolean IS NULL OR success = $2)
        ORDER BY created_at DESC
        OFFSET $3
        LIMIT $4
        "#,
        webhook_id,
        success_filter,
        offset,
        per_page as i64
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let total = sqlx::query_scalar!(
        r#"
        SELECT COUNT(*) as "count!"
        FROM webhook_deliveries
        WHERE webhook_id = $1
          AND ($2::boolean IS NULL OR success = $2)
        "#,
        webhook_id,
        success_filter
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let items = deliveries
        .into_iter()
        .map(|d| DeliveryResponse {
            id: d.id,
            webhook_id: d.webhook_id,
            event: d.event,
            payload: d.payload,
            response_status: d.response_status,
            response_body: d.response_body,
            success: d.success,
            attempts: d.attempts,
            delivered_at: d.delivered_at,
            created_at: d.created_at,
        })
        .collect();

    Ok(Json(DeliveryListResponse { items, total }))
}

/// Redeliver a failed webhook
#[utoipa::path(
    post,
    path = "/{id}/deliveries/{delivery_id}/redeliver",
    context_path = "/api/v1/webhooks",
    tag = "webhooks",
    params(
        ("id" = Uuid, Path, description = "Webhook ID"),
        ("delivery_id" = Uuid, Path, description = "Delivery ID"),
    ),
    responses(
        (status = 200, description = "Redelivery result", body = DeliveryResponse),
        (status = 404, description = "Webhook or delivery not found")
    ),
    security(("bearer_auth" = []))
)]
pub async fn redeliver(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
    Path((webhook_id, delivery_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<DeliveryResponse>> {
    // Get original delivery
    let delivery = sqlx::query!(
        r#"
        SELECT id, webhook_id, event, payload
        FROM webhook_deliveries
        WHERE id = $1 AND webhook_id = $2
        "#,
        delivery_id,
        webhook_id
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?
    .ok_or_else(|| AppError::NotFound("Delivery not found".to_string()))?;

    // Get webhook details
    let webhook = sqlx::query!(
        "SELECT url, headers, secret_hash FROM webhooks WHERE id = $1",
        webhook_id
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?
    .ok_or_else(|| AppError::NotFound("Webhook not found".to_string()))?;

    // Re-validate URL at delivery time to prevent DNS rebinding attacks
    validate_webhook_url(&webhook.url)?;

    // Send webhook
    let client = reqwest::Client::new();
    let mut request = client
        .post(&webhook.url)
        .header("Content-Type", "application/json")
        .header("X-Webhook-Event", &delivery.event)
        .header("X-Webhook-Delivery", delivery_id.to_string());

    if let Some(headers) = webhook.headers {
        if let Some(obj) = headers.as_object() {
            for (key, value) in obj {
                if let Some(v) = value.as_str() {
                    request = request.header(key.as_str(), v);
                }
            }
        }
    }

    let (success, response_status, response_body) =
        match request.json(&delivery.payload).send().await {
            Ok(response) => {
                let status = response.status().as_u16() as i32;
                let body = response.text().await.ok();
                ((200..300).contains(&status), Some(status), body)
            }
            Err(e) => (false, None, Some(e.to_string())),
        };

    // Update delivery record
    let updated = sqlx::query!(
        r#"
        UPDATE webhook_deliveries
        SET
            response_status = $2,
            response_body = $3,
            success = $4,
            attempts = attempts + 1,
            delivered_at = CASE WHEN $4 THEN NOW() ELSE delivered_at END
        WHERE id = $1
        RETURNING id, webhook_id, event, payload, response_status, response_body, success, attempts, delivered_at, created_at
        "#,
        delivery_id,
        response_status,
        response_body,
        success
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(Json(DeliveryResponse {
        id: updated.id,
        webhook_id: updated.webhook_id,
        event: updated.event,
        payload: updated.payload,
        response_status: updated.response_status,
        response_body: updated.response_body,
        success: updated.success,
        attempts: updated.attempts,
        delivered_at: updated.delivered_at,
        created_at: updated.created_at,
    }))
}

/// Validate a webhook URL to prevent SSRF attacks.
///
/// Blocks URLs pointing to private/internal networks, loopback addresses,
/// link-local addresses (AWS/cloud metadata), and known internal hostnames.
pub(crate) fn validate_webhook_url(url_str: &str) -> Result<()> {
    crate::api::validation::validate_outbound_url(url_str, "Webhook URL")
}

#[derive(OpenApi)]
#[openapi(
    paths(
        list_webhooks,
        create_webhook,
        get_webhook,
        delete_webhook,
        enable_webhook,
        disable_webhook,
        test_webhook,
        list_deliveries,
        redeliver,
    ),
    components(schemas(
        WebhookEvent,
        CreateWebhookRequest,
        WebhookResponse,
        WebhookListResponse,
        TestWebhookResponse,
        DeliveryResponse,
        DeliveryListResponse,
    ))
)]
pub struct WebhooksApiDoc;

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // WebhookEvent Display
    // -----------------------------------------------------------------------

    #[test]
    fn test_webhook_event_display_artifact_uploaded() {
        assert_eq!(
            WebhookEvent::ArtifactUploaded.to_string(),
            "artifact_uploaded"
        );
    }

    #[test]
    fn test_webhook_event_display_artifact_deleted() {
        assert_eq!(
            WebhookEvent::ArtifactDeleted.to_string(),
            "artifact_deleted"
        );
    }

    #[test]
    fn test_webhook_event_display_repository_created() {
        assert_eq!(
            WebhookEvent::RepositoryCreated.to_string(),
            "repository_created"
        );
    }

    #[test]
    fn test_webhook_event_display_repository_deleted() {
        assert_eq!(
            WebhookEvent::RepositoryDeleted.to_string(),
            "repository_deleted"
        );
    }

    #[test]
    fn test_webhook_event_display_user_created() {
        assert_eq!(WebhookEvent::UserCreated.to_string(), "user_created");
    }

    #[test]
    fn test_webhook_event_display_user_deleted() {
        assert_eq!(WebhookEvent::UserDeleted.to_string(), "user_deleted");
    }

    #[test]
    fn test_webhook_event_display_build_events() {
        assert_eq!(WebhookEvent::BuildStarted.to_string(), "build_started");
        assert_eq!(WebhookEvent::BuildCompleted.to_string(), "build_completed");
        assert_eq!(WebhookEvent::BuildFailed.to_string(), "build_failed");
    }

    // -----------------------------------------------------------------------
    // WebhookEvent serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_webhook_event_serialization() {
        let json = serde_json::to_string(&WebhookEvent::ArtifactUploaded).unwrap();
        assert_eq!(json, "\"artifact_uploaded\"");
    }

    #[test]
    fn test_webhook_event_deserialization() {
        let event: WebhookEvent = serde_json::from_str("\"build_failed\"").unwrap();
        assert_eq!(event.to_string(), "build_failed");
    }

    #[test]
    fn test_webhook_event_roundtrip() {
        let original = WebhookEvent::RepositoryCreated;
        let json = serde_json::to_string(&original).unwrap();
        let parsed: WebhookEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.to_string(), original.to_string());
    }

    // -----------------------------------------------------------------------
    // validate_webhook_url
    // -----------------------------------------------------------------------

    #[test]
    fn test_validate_webhook_url_valid_https() {
        assert!(validate_webhook_url("https://hooks.example.com/webhook").is_ok());
    }

    #[test]
    fn test_validate_webhook_url_valid_http() {
        assert!(validate_webhook_url("http://hooks.example.com/webhook").is_ok());
    }

    #[test]
    fn test_validate_webhook_url_invalid_scheme_ftp() {
        assert!(validate_webhook_url("ftp://example.com/path").is_err());
    }

    #[test]
    fn test_validate_webhook_url_invalid_scheme_file() {
        assert!(validate_webhook_url("file:///etc/passwd").is_err());
    }

    #[test]
    fn test_validate_webhook_url_invalid_format() {
        assert!(validate_webhook_url("not-a-url").is_err());
    }

    #[test]
    fn test_validate_webhook_url_blocks_localhost() {
        assert!(validate_webhook_url("http://localhost/hook").is_err());
    }

    #[test]
    fn test_validate_webhook_url_blocks_metadata_google() {
        assert!(validate_webhook_url("http://metadata.google.internal/computeMetadata").is_err());
    }

    #[test]
    fn test_validate_webhook_url_blocks_metadata_azure() {
        assert!(validate_webhook_url("http://metadata.azure.com/instance").is_err());
    }

    #[test]
    fn test_validate_webhook_url_blocks_aws_metadata_ip() {
        assert!(validate_webhook_url("http://169.254.169.254/latest/meta-data").is_err());
    }

    #[test]
    fn test_validate_webhook_url_blocks_internal_hosts() {
        assert!(validate_webhook_url("http://backend/api").is_err());
        assert!(validate_webhook_url("http://postgres/").is_err());
        assert!(validate_webhook_url("http://redis/").is_err());
        assert!(validate_webhook_url("http://meilisearch/").is_err());
        assert!(validate_webhook_url("http://trivy/").is_err());
    }

    #[test]
    fn test_validate_webhook_url_blocks_loopback_ip() {
        assert!(validate_webhook_url("http://127.0.0.1/hook").is_err());
    }

    #[test]
    fn test_validate_webhook_url_blocks_private_ip_10() {
        assert!(validate_webhook_url("http://10.0.0.1/hook").is_err());
    }

    #[test]
    fn test_validate_webhook_url_blocks_private_ip_172() {
        assert!(validate_webhook_url("http://172.16.0.1/hook").is_err());
    }

    #[test]
    fn test_validate_webhook_url_blocks_private_ip_192() {
        assert!(validate_webhook_url("http://192.168.1.1/hook").is_err());
    }

    #[test]
    fn test_validate_webhook_url_blocks_unspecified() {
        assert!(validate_webhook_url("http://0.0.0.0/hook").is_err());
    }

    #[test]
    fn test_validate_webhook_url_allows_public_ip() {
        assert!(validate_webhook_url("http://8.8.8.8/hook").is_ok());
    }

    // -----------------------------------------------------------------------
    // Request/Response serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_create_webhook_request_deserialization() {
        let json = r#"{
            "name": "deploy",
            "url": "https://hooks.example.com/deploy",
            "events": ["artifact_uploaded"]
        }"#;
        let req: CreateWebhookRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.name, "deploy");
        assert_eq!(req.url, "https://hooks.example.com/deploy");
        assert_eq!(req.events.len(), 1);
        assert!(req.secret.is_none());
        assert!(req.repository_id.is_none());
    }

    #[test]
    fn test_create_webhook_request_with_all_fields() {
        let json = serde_json::json!({
            "name": "full",
            "url": "https://hooks.example.com/full",
            "events": ["artifact_uploaded", "artifact_deleted"],
            "secret": "my-secret-key",
            "repository_id": Uuid::new_v4(),
            "headers": {"X-Custom": "value"}
        });
        let req: CreateWebhookRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.events.len(), 2);
        assert!(req.secret.is_some());
        assert!(req.repository_id.is_some());
        assert!(req.headers.is_some());
    }

    #[test]
    fn test_webhook_response_serialization() {
        let resp = WebhookResponse {
            id: Uuid::nil(),
            name: "test".to_string(),
            url: "https://example.com/hook".to_string(),
            events: vec!["artifact_uploaded".to_string()],
            is_enabled: true,
            repository_id: None,
            headers: None,
            last_triggered_at: None,
            created_at: chrono::Utc::now(),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["name"], "test");
        assert_eq!(json["is_enabled"], true);
        assert_eq!(json["events"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn test_test_webhook_response_serialization() {
        let resp = TestWebhookResponse {
            success: true,
            status_code: Some(200),
            response_body: Some("OK".to_string()),
            error: None,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["success"], true);
        assert_eq!(json["status_code"], 200);
    }

    #[test]
    fn test_test_webhook_response_failure() {
        let resp = TestWebhookResponse {
            success: false,
            status_code: None,
            response_body: None,
            error: Some("Connection refused".to_string()),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["success"], false);
        assert!(json["error"]
            .as_str()
            .unwrap()
            .contains("Connection refused"));
    }

    #[test]
    fn test_delivery_response_serialization() {
        let resp = DeliveryResponse {
            id: Uuid::nil(),
            webhook_id: Uuid::nil(),
            event: "artifact_uploaded".to_string(),
            payload: serde_json::json!({"key": "value"}),
            response_status: Some(200),
            response_body: Some("OK".to_string()),
            success: true,
            attempts: 1,
            delivered_at: Some(chrono::Utc::now()),
            created_at: chrono::Utc::now(),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["success"], true);
        assert_eq!(json["attempts"], 1);
    }

    // -----------------------------------------------------------------------
    // validate_webhook_url (delegates to validation::validate_outbound_url)
    // -----------------------------------------------------------------------

    #[test]
    fn test_validate_webhook_url_allows_valid() {
        assert!(validate_webhook_url("https://hooks.example.com/notify").is_ok());
    }

    #[test]
    fn test_validate_webhook_url_rejects_localhost() {
        assert!(validate_webhook_url("http://localhost/hook").is_err());
    }

    #[test]
    fn test_validate_webhook_url_rejects_private_ip() {
        assert!(validate_webhook_url("http://10.0.0.1/hook").is_err());
    }
}
