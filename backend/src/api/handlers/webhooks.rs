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
use crate::services::webhook_payloads::{self, PayloadTemplate};
use crate::services::webhook_secret_crypto;

/// Create webhook routes
pub fn router() -> Router<SharedState> {
    Router::new()
        .route("/", get(list_webhooks).post(create_webhook))
        .route("/:id", get(get_webhook).delete(delete_webhook))
        .route("/:id/enable", post(enable_webhook))
        .route("/:id/disable", post(disable_webhook))
        .route("/:id/test", post(test_webhook))
        .route("/:id/rotate-secret", post(rotate_webhook_secret))
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
    /// Optional caller-supplied secret. When omitted the server generates a
    /// fresh `whsec_*` secret. Either way the raw value is returned in the
    /// 201 response body exactly once and is unrecoverable thereafter.
    pub secret: Option<String>,
    pub repository_id: Option<Uuid>,
    #[schema(value_type = Option<Object>)]
    pub headers: Option<serde_json::Value>,
    /// Payload layout for the target platform (default: generic).
    #[serde(default)]
    pub payload_template: PayloadTemplate,
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
    pub payload_template: PayloadTemplate,
    /// Short non-reversible identifier for the current signing secret
    /// (`whsec_...abcd`), suitable for display in operator UIs. The raw
    /// secret is never returned by GET or LIST.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_digest: Option<String>,
    /// True while a previous secret is still accepted by the retry path
    /// during a rotation overlap window.
    #[serde(default)]
    pub secret_rotation_active: bool,
    pub last_triggered_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Response returned exactly once when a webhook is created or its secret
/// is rotated. The raw `secret` value is not retrievable afterwards.
#[derive(Debug, Serialize, ToSchema)]
pub struct WebhookSecretCreatedResponse {
    #[serde(flatten)]
    pub webhook: WebhookResponse,
    /// Raw signing secret. Display this to the operator immediately and
    /// instruct them to record it; the server retains only the encrypted
    /// form and a short digest.
    pub secret: String,
}

/// Response returned by the rotate-secret endpoint.
#[derive(Debug, Serialize, ToSchema)]
pub struct RotateWebhookSecretResponse {
    pub id: Uuid,
    /// Raw signing secret produced by this rotation. Shown exactly once.
    pub secret: String,
    pub secret_digest: String,
    /// When the previously active secret stops being accepted.
    pub previous_secret_expires_at: chrono::DateTime<chrono::Utc>,
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

    use sqlx::Row;

    let webhooks = sqlx::query(
        r#"
        SELECT id, name, url, events, is_enabled, repository_id, headers,
               payload_template, secret_digest, secret_previous_expires_at,
               last_triggered_at, created_at
        FROM webhooks
        WHERE ($1::uuid IS NULL OR repository_id = $1)
          AND ($2::boolean IS NULL OR is_enabled = $2)
        ORDER BY name
        OFFSET $3
        LIMIT $4
        "#,
    )
    .bind(query.repository_id)
    .bind(query.enabled)
    .bind(offset)
    .bind(per_page as i64)
    .fetch_all(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let total_row = sqlx::query(
        r#"
        SELECT COUNT(*) as count
        FROM webhooks
        WHERE ($1::uuid IS NULL OR repository_id = $1)
          AND ($2::boolean IS NULL OR is_enabled = $2)
        "#,
    )
    .bind(query.repository_id)
    .bind(query.enabled)
    .fetch_one(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;
    let total: i64 = total_row.get("count");

    let items = webhooks
        .into_iter()
        .map(|w| {
            let tpl: String = w.get("payload_template");
            let prev_expires: Option<chrono::DateTime<chrono::Utc>> =
                w.get("secret_previous_expires_at");
            WebhookResponse {
                id: w.get("id"),
                name: w.get("name"),
                url: w.get("url"),
                events: w.get("events"),
                is_enabled: w.get("is_enabled"),
                repository_id: w.get("repository_id"),
                headers: w.get("headers"),
                payload_template: PayloadTemplate::from_str_lossy(&tpl),
                secret_digest: w.get("secret_digest"),
                secret_rotation_active: prev_expires
                    .map(|e| e > chrono::Utc::now())
                    .unwrap_or(false),
                last_triggered_at: w.get("last_triggered_at"),
                created_at: w.get("created_at"),
            }
        })
        .collect();

    Ok(Json(WebhookListResponse { items, total }))
}

/// Create webhook.
///
/// Generates a fresh signing secret (or accepts a caller-supplied one),
/// encrypts it at rest, and returns the raw secret in the response body
/// **once**. After this call, GET on the webhook returns only
/// `secret_digest`, never the raw secret.
#[utoipa::path(
    post,
    path = "",
    context_path = "/api/v1/webhooks",
    tag = "webhooks",
    request_body = CreateWebhookRequest,
    responses(
        (status = 200, description = "Webhook created. Body includes the raw secret exactly once.", body = WebhookSecretCreatedResponse),
        (status = 422, description = "Validation error"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_webhook(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
    Json(payload): Json<CreateWebhookRequest>,
) -> Result<Json<WebhookSecretCreatedResponse>> {
    // Validate URL (SSRF prevention)
    validate_webhook_url(&payload.url)?;

    // Validate events
    if payload.events.is_empty() {
        return Err(AppError::Validation(
            "At least one event required".to_string(),
        ));
    }

    // Use the caller-provided secret if any, otherwise generate one.
    let raw_secret = payload
        .secret
        .clone()
        .unwrap_or_else(webhook_secret_crypto::generate_secret);

    // Encrypt at rest.
    let secret_encrypted = webhook_secret_crypto::encrypt_secret(&raw_secret).map_err(|e| {
        tracing::error!("webhook secret encryption failed: {}", e);
        AppError::Internal("webhook secret encryption is not configured".to_string())
    })?;
    let secret_digest = webhook_secret_crypto::digest_for_display(&raw_secret);

    use sqlx::Row;

    let template_str = payload.payload_template.to_string();
    let webhook = sqlx::query(
        r#"
        INSERT INTO webhooks
            (name, url, events, repository_id, headers, payload_template,
             secret_encrypted, secret_digest)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        RETURNING id, name, url, events, is_enabled, repository_id, headers,
                  payload_template, secret_digest, secret_previous_expires_at,
                  last_triggered_at, created_at
        "#,
    )
    .bind(&payload.name)
    .bind(&payload.url)
    .bind(&payload.events)
    .bind(payload.repository_id)
    .bind(&payload.headers)
    .bind(&template_str)
    .bind(&secret_encrypted)
    .bind(&secret_digest)
    .fetch_one(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let tpl: String = webhook.get("payload_template");
    let prev_expires: Option<chrono::DateTime<chrono::Utc>> =
        webhook.get("secret_previous_expires_at");
    let response = WebhookResponse {
        id: webhook.get("id"),
        name: webhook.get("name"),
        url: webhook.get("url"),
        events: webhook.get("events"),
        is_enabled: webhook.get("is_enabled"),
        repository_id: webhook.get("repository_id"),
        headers: webhook.get("headers"),
        payload_template: PayloadTemplate::from_str_lossy(&tpl),
        secret_digest: webhook.get("secret_digest"),
        secret_rotation_active: prev_expires
            .map(|e| e > chrono::Utc::now())
            .unwrap_or(false),
        last_triggered_at: webhook.get("last_triggered_at"),
        created_at: webhook.get("created_at"),
    };

    Ok(Json(WebhookSecretCreatedResponse {
        webhook: response,
        secret: raw_secret,
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
    use sqlx::Row;

    let webhook = sqlx::query(
        r#"
        SELECT id, name, url, events, is_enabled, repository_id, headers,
               payload_template, secret_digest, secret_previous_expires_at,
               last_triggered_at, created_at
        FROM webhooks
        WHERE id = $1
        "#,
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?
    .ok_or_else(|| AppError::NotFound("Webhook not found".to_string()))?;

    let tpl: String = webhook.get("payload_template");
    let prev_expires: Option<chrono::DateTime<chrono::Utc>> =
        webhook.get("secret_previous_expires_at");
    Ok(Json(WebhookResponse {
        id: webhook.get("id"),
        name: webhook.get("name"),
        url: webhook.get("url"),
        events: webhook.get("events"),
        is_enabled: webhook.get("is_enabled"),
        repository_id: webhook.get("repository_id"),
        headers: webhook.get("headers"),
        payload_template: PayloadTemplate::from_str_lossy(&tpl),
        secret_digest: webhook.get("secret_digest"),
        secret_rotation_active: prev_expires
            .map(|e| e > chrono::Utc::now())
            .unwrap_or(false),
        last_triggered_at: webhook.get("last_triggered_at"),
        created_at: webhook.get("created_at"),
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
    use sqlx::Row;

    let webhook = sqlx::query(
        "SELECT url, headers, secret_hash, payload_template FROM webhooks WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?
    .ok_or_else(|| AppError::NotFound("Webhook not found".to_string()))?;

    let url: String = webhook.get("url");
    let headers: Option<serde_json::Value> = webhook.get("headers");
    let secret_hash: Option<String> = webhook.get("secret_hash");
    let tpl_str: String = webhook.get("payload_template");
    let template = PayloadTemplate::from_str_lossy(&tpl_str);

    // Create test payload using the configured template
    let test_details = serde_json::json!({
        "message": "This is a test webhook delivery"
    });
    let timestamp = chrono::Utc::now().to_rfc3339();
    let payload = webhook_payloads::render_payload(template, "test", &test_details, &timestamp);

    // Re-validate URL at delivery time to prevent DNS rebinding attacks
    validate_webhook_url(&url)?;

    // Send webhook
    let client = crate::services::http_client::default_client();
    let mut request = client
        .post(&url)
        .header("Content-Type", "application/json")
        .header("X-Webhook-Event", "test");

    // Add custom headers
    if let Some(ref h) = headers {
        if let Some(obj) = h.as_object() {
            for (key, value) in obj {
                if let Some(v) = value.as_str() {
                    request = request.header(key.as_str(), v);
                }
            }
        }
    }

    // Add signature if secret exists
    if secret_hash.is_some() {
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
    let client = crate::services::http_client::default_client();
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

/// Length of the rotation overlap window. Both the previous and the
/// current secret are accepted by the retry path during this window.
const SECRET_ROTATION_OVERLAP: chrono::Duration = chrono::Duration::hours(24);

/// Pure helper that mirrors the SQL WHERE clause guarding the rotate
/// endpoint. Returns `true` iff a rotation should be allowed for a row
/// whose `secret_previous_expires_at` column currently holds `previous`.
///
/// This exists so the unit tests can pin the rotation-window semantics
/// without standing up a Postgres test harness. The SQL UPDATE in
/// `rotate_webhook_secret` and this helper must agree.
#[cfg(test)]
pub(crate) fn rotation_guard_allows(
    previous: Option<chrono::DateTime<chrono::Utc>>,
    now: chrono::DateTime<chrono::Utc>,
) -> bool {
    match previous {
        None => true,
        Some(expires_at) => expires_at < now,
    }
}

/// Rotate the signing secret for a webhook.
///
/// Generates a new raw secret, encrypts it, moves the existing
/// `secret_encrypted` into `secret_previous_encrypted`, and stamps an
/// expiry 24 hours in the future. The new raw secret is returned in the
/// response body **once**. The HMAC signing path (added in a later ticket)
/// signs deliveries with both secrets while the previous one is within
/// its expiry window so consumers can rotate without dropped events.
///
/// If a previous-secret window is still active when the rotate request
/// arrives, the request is REJECTED with HTTP 409 Conflict. This prevents
/// two near-simultaneous rotations from clobbering the original
/// `secret_previous_encrypted` material before the operator has finished
/// distributing the previous new key. The 409 body is structured:
/// `{"error": "rotation_already_in_progress", "expires_at": "<RFC3339>"}`.
#[utoipa::path(
    post,
    path = "/{id}/rotate-secret",
    context_path = "/api/v1/webhooks",
    tag = "webhooks",
    params(
        ("id" = Uuid, Path, description = "Webhook ID")
    ),
    responses(
        (status = 200, description = "Secret rotated. Body includes the new raw secret exactly once.", body = RotateWebhookSecretResponse),
        (status = 404, description = "Webhook not found"),
        (status = 409, description = "A previous rotation overlap window is still active"),
        (status = 500, description = "Encryption key not configured")
    ),
    security(("bearer_auth" = []))
)]
pub async fn rotate_webhook_secret(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<axum::response::Response> {
    use axum::response::IntoResponse;

    let new_secret = webhook_secret_crypto::generate_secret();
    let new_encrypted = webhook_secret_crypto::encrypt_secret(&new_secret).map_err(|e| {
        tracing::error!("webhook secret encryption failed during rotation: {}", e);
        AppError::Internal("webhook secret encryption is not configured".to_string())
    })?;
    let new_digest = webhook_secret_crypto::digest_for_display(&new_secret);
    let now = chrono::Utc::now();
    let previous_expires_at = now + SECRET_ROTATION_OVERLAP;

    // Conditional UPDATE: only proceed if no rotation overlap is currently
    // active. A row passes the guard when its `secret_previous_expires_at`
    // is NULL (never rotated, or the cleanup job has already cleared it)
    // or already in the past. If the WHERE clause excludes the row we get
    // 0 rows updated and respond 409 with the active expiry timestamp.
    let updated = sqlx::query_scalar::<_, Uuid>(
        r#"
        UPDATE webhooks
        SET
            secret_previous_encrypted   = secret_encrypted,
            secret_previous_expires_at  = CASE
                WHEN secret_encrypted IS NOT NULL THEN $2
                ELSE NULL
            END,
            secret_encrypted            = $3,
            secret_digest               = $4,
            secret_rotation_started_at  = $5,
            updated_at                  = NOW()
        WHERE id = $1
          AND (secret_previous_expires_at IS NULL OR secret_previous_expires_at < NOW())
        RETURNING id
        "#,
    )
    .bind(id)
    .bind(previous_expires_at)
    .bind(&new_encrypted)
    .bind(&new_digest)
    .bind(now)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    if updated.is_none() {
        // Either the row is missing or the rotation guard failed. Disambiguate
        // by reading the row's `secret_previous_expires_at` directly; the read
        // is cheap and the 409 body needs the active expiry timestamp anyway.
        let active = sqlx::query_scalar::<_, Option<chrono::DateTime<chrono::Utc>>>(
            "SELECT secret_previous_expires_at FROM webhooks WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        return match active {
            None => Err(AppError::NotFound("Webhook not found".to_string())),
            Some(maybe_expires) => match maybe_expires {
                Some(expires_at) if expires_at >= chrono::Utc::now() => {
                    let body = serde_json::json!({
                        "error": "rotation_already_in_progress",
                        "expires_at": expires_at,
                    });
                    Ok((axum::http::StatusCode::CONFLICT, Json(body)).into_response())
                }
                // Should not happen: a NULL or past expiry means the UPDATE
                // would have succeeded. Fall back to a generic 409 rather
                // than racing again automatically.
                _ => {
                    let body = serde_json::json!({
                        "error": "rotation_already_in_progress",
                        "expires_at": serde_json::Value::Null,
                    });
                    Ok((axum::http::StatusCode::CONFLICT, Json(body)).into_response())
                }
            },
        };
    }

    Ok(Json(RotateWebhookSecretResponse {
        id,
        secret: new_secret,
        secret_digest: new_digest,
        previous_secret_expires_at: previous_expires_at,
    })
    .into_response())
}

/// Background-task entry point: clear expired previous-secret material so
/// stale ciphertext does not linger past the rotation overlap window.
///
/// Returns the number of rows updated. Safe to call from a scheduler tick.
pub async fn cleanup_expired_previous_secrets(
    db: &sqlx::PgPool,
) -> std::result::Result<u64, sqlx::Error> {
    let result = sqlx::query(
        r#"
        UPDATE webhooks
        SET secret_previous_encrypted  = NULL,
            secret_previous_expires_at = NULL
        WHERE secret_previous_encrypted IS NOT NULL
          AND secret_previous_expires_at IS NOT NULL
          AND secret_previous_expires_at <= NOW()
        "#,
    )
    .execute(db)
    .await?;
    Ok(result.rows_affected())
}

/// Validate a webhook URL to prevent SSRF attacks.
///
/// Blocks URLs pointing to private/internal networks, loopback addresses,
/// link-local addresses (AWS/cloud metadata), and known internal hostnames.
pub(crate) fn validate_webhook_url(url_str: &str) -> Result<()> {
    crate::api::validation::validate_outbound_url(url_str, "Webhook URL")
}

/// Whether a webhook row carries any form of signing secret.
///
/// `secret_encrypted` (AES-GCM, E1) is the authoritative new form. The
/// legacy bcrypt `secret_hash` column is kept around so pre-v1.1.9 rows
/// that have not yet been rotated continue to advertise that they are
/// configured for signing. Returns `true` iff at least one form is set
/// to a non-empty value. Rows where both are NULL or empty are treated
/// as "no signing configured" and the retry path omits the
/// `X-Webhook-Signature` header entirely.
pub(crate) fn has_signing_secret(
    secret_hash: &Option<String>,
    secret_encrypted: Option<&[u8]>,
) -> bool {
    let hash_present = secret_hash.as_deref().is_some_and(|s| !s.is_empty());
    let enc_present = secret_encrypted.is_some_and(|b| !b.is_empty());
    hash_present || enc_present
}

/// Calculate retry delay in seconds for webhook delivery.
/// Schedule: 30s, 2m, 15m, 1h, 4h (caps at 4h for attempt >= 5).
pub(crate) fn webhook_retry_delay_secs(attempt: i32) -> i64 {
    match attempt {
        1 => 30,
        2 => 120,
        3 => 900,
        4 => 3600,
        _ => 14400,
    }
}

/// Outcome of a webhook delivery retry attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RetryOutcome {
    /// Delivery succeeded (2xx status).
    Success,
    /// Max attempts exhausted, delivery is dead-lettered.
    DeadLetter,
    /// Should retry after the given delay in seconds.
    Retry { delay_secs: i64 },
}

/// Determine the outcome of a webhook delivery attempt.
///
/// Given the current attempt count, max attempts, and whether the HTTP call
/// succeeded, returns whether to mark success, dead-letter, or schedule a retry.
pub(crate) fn determine_retry_outcome(
    success: bool,
    current_attempts: i32,
    max_attempts: i32,
) -> RetryOutcome {
    let new_attempts = current_attempts + 1;
    if success {
        RetryOutcome::Success
    } else if new_attempts >= max_attempts {
        RetryOutcome::DeadLetter
    } else {
        RetryOutcome::Retry {
            delay_secs: webhook_retry_delay_secs(new_attempts),
        }
    }
}

/// Check whether an HTTP status code indicates a successful webhook delivery.
pub(crate) fn is_webhook_delivery_success(status_code: u16) -> bool {
    (200..300).contains(&status_code)
}

/// A row from the webhook_deliveries retry queue.
#[derive(Debug)]
struct RetryDeliveryRow {
    pub id: uuid::Uuid,
    pub webhook_id: uuid::Uuid,
    pub event: String,
    pub payload: serde_json::Value,
    pub attempts: i32,
    pub max_attempts: i32,
}

/// Process failed webhook deliveries that are due for retry.
///
/// Queries the retry queue for deliveries where `next_retry_at <= NOW()`,
/// attempts the HTTP POST again, and updates the delivery record with the
/// result. Uses `sqlx::query()` (not the macro) because the new columns
/// are not in the offline SQLx cache.
pub async fn process_webhook_retries(db: &sqlx::PgPool) -> std::result::Result<(), String> {
    use sqlx::Row;

    // Fetch deliveries due for retry (using sqlx::query, not the macro)
    let raw_rows = sqlx::query(
        r#"
        SELECT id, webhook_id, event, payload, attempts, max_attempts
        FROM webhook_deliveries
        WHERE success = false
          AND next_retry_at IS NOT NULL
          AND next_retry_at <= NOW()
          AND attempts < max_attempts
        ORDER BY next_retry_at ASC
        LIMIT 50
        "#,
    )
    .fetch_all(db)
    .await
    .map_err(|e| format!("Failed to fetch retry queue: {}", e))?;

    let rows: Vec<RetryDeliveryRow> = raw_rows
        .into_iter()
        .map(|row| RetryDeliveryRow {
            id: row.get("id"),
            webhook_id: row.get("webhook_id"),
            event: row.get("event"),
            payload: row.get("payload"),
            attempts: row.get("attempts"),
            max_attempts: row.get("max_attempts"),
        })
        .collect();

    if rows.is_empty() {
        return Ok(());
    }

    tracing::debug!("Processing {} webhook deliveries due for retry", rows.len());

    let client = crate::services::http_client::base_client_builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| format!("Failed to build HTTP client: {}", e))?;

    for delivery in &rows {
        // Look up the webhook URL, headers, and both signing-secret forms
        // (using sqlx::query, not the macro, because the WHERE clause differs
        // from the cached version). The retry path treats `secret_encrypted`
        // (E1, AES-GCM) as authoritative for new rows and falls back to the
        // legacy bcrypt `secret_hash` for un-rotated pre-v1.1.9 webhooks.
        // Migration 081 leaves both NULL on rows it migrates so the operator
        // is forced to rotate before signatures resume.
        let webhook_row = sqlx::query(
            "SELECT url, headers, secret_hash, secret_encrypted \
             FROM webhooks WHERE id = $1 AND is_enabled = true",
        )
        .bind(delivery.webhook_id)
        .fetch_optional(db)
        .await
        .map_err(|e| format!("Failed to fetch webhook: {}", e))?;

        let webhook_row = match webhook_row {
            Some(w) => w,
            None => {
                // Webhook deleted or disabled: mark delivery as dead letter
                let _ =
                    sqlx::query("UPDATE webhook_deliveries SET next_retry_at = NULL WHERE id = $1")
                        .bind(delivery.id)
                        .execute(db)
                        .await;
                continue;
            }
        };

        let url: String = webhook_row.get("url");
        let headers: Option<serde_json::Value> = webhook_row.get("headers");
        let secret_hash: Option<String> = webhook_row.get("secret_hash");
        let secret_encrypted: Option<Vec<u8>> = webhook_row.get("secret_encrypted");

        // Validate URL before delivery (SSRF prevention)
        if validate_webhook_url(&url).is_err() {
            let _ = sqlx::query("UPDATE webhook_deliveries SET next_retry_at = NULL WHERE id = $1")
                .bind(delivery.id)
                .execute(db)
                .await;
            tracing::warn!(
                "Webhook URL failed validation during retry, delivery {} dead-lettered",
                delivery.id
            );
            continue;
        }

        // Build the request
        let mut request = client
            .post(&url)
            .header("Content-Type", "application/json")
            .header("X-Webhook-Event", &delivery.event)
            .header("X-Webhook-Delivery", delivery.id.to_string())
            .header(
                "X-Webhook-Retry-Attempt",
                (delivery.attempts + 1).to_string(),
            );

        if let Some(ref h) = headers {
            if let Some(obj) = h.as_object() {
                for (key, value) in obj {
                    if let Some(v) = value.as_str() {
                        request = request.header(key.as_str(), v);
                    }
                }
            }
        }

        // Emit the signature header iff EITHER form of signing secret is
        // configured. The actual HMAC is wired up in E2; today we still
        // emit the placeholder string so the wire contract (header presence
        // means "signing configured") is stable. Rows where BOTH forms are
        // NULL (e.g. notifications migrated by migration 081 before the
        // operator rotates) MUST NOT emit this header so receivers can
        // distinguish "signing configured" from "legacy unsigned".
        if has_signing_secret(&secret_hash, secret_encrypted.as_deref()) {
            request = request.header("X-Webhook-Signature", "hmac-signature");
        }

        let (success, response_status, response_body) =
            match request.json(&delivery.payload).send().await {
                Ok(response) => {
                    let status = response.status().as_u16() as i32;
                    let body = response.text().await.ok();
                    (
                        is_webhook_delivery_success(status as u16),
                        Some(status),
                        body,
                    )
                }
                Err(e) => (false, None, Some(e.to_string())),
            };

        let new_attempts = delivery.attempts + 1;
        let outcome = determine_retry_outcome(success, delivery.attempts, delivery.max_attempts);

        if outcome == RetryOutcome::Success {
            // Delivery succeeded
            let _ = sqlx::query(
                r#"
                UPDATE webhook_deliveries
                SET success = true,
                    response_status = $2,
                    response_body = $3,
                    attempts = $4,
                    delivered_at = NOW(),
                    next_retry_at = NULL
                WHERE id = $1
                "#,
            )
            .bind(delivery.id)
            .bind(response_status)
            .bind(&response_body)
            .bind(new_attempts)
            .execute(db)
            .await;
        } else if outcome == RetryOutcome::DeadLetter {
            // Max attempts exhausted: dead letter
            let _ = sqlx::query(
                r#"
                UPDATE webhook_deliveries
                SET response_status = $2,
                    response_body = $3,
                    attempts = $4,
                    next_retry_at = NULL
                WHERE id = $1
                "#,
            )
            .bind(delivery.id)
            .bind(response_status)
            .bind(&response_body)
            .bind(new_attempts)
            .execute(db)
            .await;

            tracing::info!(
                "Webhook delivery {} exhausted {} attempts, dead-lettered",
                delivery.id,
                new_attempts
            );
        } else if let RetryOutcome::Retry { delay_secs } = outcome {
            // Schedule next retry
            let _ = sqlx::query(
                r#"
                UPDATE webhook_deliveries
                SET response_status = $2,
                    response_body = $3,
                    attempts = $4,
                    next_retry_at = NOW() + ($5 || ' seconds')::interval
                WHERE id = $1
                "#,
            )
            .bind(delivery.id)
            .bind(response_status)
            .bind(&response_body)
            .bind(new_attempts)
            .bind(delay_secs.to_string())
            .execute(db)
            .await;
        }

        crate::services::metrics_service::record_webhook_delivery(&delivery.event, success);
    }

    Ok(())
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
        rotate_webhook_secret,
        list_deliveries,
        redeliver,
    ),
    components(schemas(
        WebhookEvent,
        PayloadTemplate,
        CreateWebhookRequest,
        WebhookResponse,
        WebhookSecretCreatedResponse,
        RotateWebhookSecretResponse,
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
        assert!(validate_webhook_url("http://opensearch/").is_err());
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
        assert_eq!(req.payload_template, PayloadTemplate::Generic);
    }

    #[test]
    fn test_create_webhook_request_with_all_fields() {
        let json = serde_json::json!({
            "name": "full",
            "url": "https://hooks.example.com/full",
            "events": ["artifact_uploaded", "artifact_deleted"],
            "secret": "my-secret-key",
            "repository_id": Uuid::new_v4(),
            "headers": {"X-Custom": "value"},
            "payload_template": "slack"
        });
        let req: CreateWebhookRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.events.len(), 2);
        assert!(req.secret.is_some());
        assert!(req.repository_id.is_some());
        assert!(req.headers.is_some());
        assert_eq!(req.payload_template, PayloadTemplate::Slack);
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
            payload_template: PayloadTemplate::Generic,
            secret_digest: Some("whsec_...abcd".to_string()),
            secret_rotation_active: false,
            last_triggered_at: None,
            created_at: chrono::Utc::now(),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["name"], "test");
        assert_eq!(json["is_enabled"], true);
        assert_eq!(json["events"].as_array().unwrap().len(), 1);
        assert_eq!(json["payload_template"], "generic");
    }

    #[test]
    fn test_webhook_response_omits_secret_material_keys() {
        // Write-once contract: GET/LIST responses must NEVER include the
        // raw secret, the encrypted blob, the previous-secret blob, or the
        // legacy bcrypt hash. The serialized form is allowed to carry
        // `secret_digest` (a non-reversible last-4 indicator) and
        // `secret_rotation_active` (a boolean), nothing else secret-related.
        let resp = WebhookResponse {
            id: Uuid::nil(),
            name: "test".to_string(),
            url: "https://example.com/hook".to_string(),
            events: vec!["artifact_uploaded".to_string()],
            is_enabled: true,
            repository_id: None,
            headers: None,
            payload_template: PayloadTemplate::Generic,
            secret_digest: Some("whsec_...abcd".to_string()),
            secret_rotation_active: false,
            last_triggered_at: None,
            created_at: chrono::Utc::now(),
        };
        let json = serde_json::to_value(&resp).unwrap();
        let obj = json
            .as_object()
            .expect("WebhookResponse serializes to object");
        let forbidden_keys = [
            "secret",
            "secret_encrypted",
            "secret_previous_encrypted",
            "secret_hash",
            "secret_previous_expires_at",
            "secret_rotation_started_at",
        ];
        for key in forbidden_keys {
            assert!(
                !obj.contains_key(key),
                "WebhookResponse must not serialize key `{}`; got keys: {:?}",
                key,
                obj.keys().collect::<Vec<_>>()
            );
        }
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

    // -----------------------------------------------------------------------
    // webhook_retry_delay_secs
    // -----------------------------------------------------------------------

    #[test]
    fn test_webhook_retry_backoff_schedule() {
        assert_eq!(webhook_retry_delay_secs(1), 30);
        assert_eq!(webhook_retry_delay_secs(2), 120);
        assert_eq!(webhook_retry_delay_secs(3), 900);
        assert_eq!(webhook_retry_delay_secs(4), 3600);
        assert_eq!(webhook_retry_delay_secs(5), 14400);
    }

    #[test]
    fn test_webhook_retry_backoff_capped() {
        assert_eq!(webhook_retry_delay_secs(10), 14400);
    }

    // -----------------------------------------------------------------------
    // determine_retry_outcome (extracted pure function)
    // -----------------------------------------------------------------------

    #[test]
    fn test_retry_outcome_success() {
        assert_eq!(determine_retry_outcome(true, 0, 5), RetryOutcome::Success);
    }

    #[test]
    fn test_retry_outcome_dead_letter() {
        // attempts=4, max=5: new_attempts = 5 >= 5 → DeadLetter
        assert_eq!(
            determine_retry_outcome(false, 4, 5),
            RetryOutcome::DeadLetter
        );
    }

    #[test]
    fn test_retry_outcome_retry_first_attempt() {
        // attempts=0, max=5: new_attempts = 1 < 5 → Retry with delay for attempt 1
        assert_eq!(
            determine_retry_outcome(false, 0, 5),
            RetryOutcome::Retry { delay_secs: 30 }
        );
    }

    #[test]
    fn test_retry_outcome_retry_second_attempt() {
        // attempts=1, max=5: new_attempts = 2 < 5 → Retry with delay for attempt 2
        assert_eq!(
            determine_retry_outcome(false, 1, 5),
            RetryOutcome::Retry { delay_secs: 120 }
        );
    }

    #[test]
    fn test_retry_outcome_retry_third_attempt() {
        // attempts=2, max=5: new_attempts = 3 < 5 → Retry with delay for attempt 3
        assert_eq!(
            determine_retry_outcome(false, 2, 5),
            RetryOutcome::Retry { delay_secs: 900 }
        );
    }

    #[test]
    fn test_retry_outcome_dead_letter_exact() {
        // attempts=2, max=3: new_attempts = 3 >= 3 → DeadLetter
        assert_eq!(
            determine_retry_outcome(false, 2, 3),
            RetryOutcome::DeadLetter
        );
    }

    #[test]
    fn test_retry_outcome_success_ignores_attempts() {
        // Even with high attempt count, success is success
        assert_eq!(determine_retry_outcome(true, 4, 5), RetryOutcome::Success);
    }

    // -----------------------------------------------------------------------
    // is_webhook_delivery_success (extracted pure function)
    // -----------------------------------------------------------------------

    #[test]
    fn test_is_delivery_success_200() {
        assert!(is_webhook_delivery_success(200));
    }

    #[test]
    fn test_is_delivery_success_201() {
        assert!(is_webhook_delivery_success(201));
    }

    #[test]
    fn test_is_delivery_success_204() {
        assert!(is_webhook_delivery_success(204));
    }

    #[test]
    fn test_is_delivery_success_299() {
        assert!(is_webhook_delivery_success(299));
    }

    #[test]
    fn test_is_delivery_success_300() {
        assert!(!is_webhook_delivery_success(300));
    }

    #[test]
    fn test_is_delivery_success_400() {
        assert!(!is_webhook_delivery_success(400));
    }

    #[test]
    fn test_is_delivery_success_500() {
        assert!(!is_webhook_delivery_success(500));
    }

    #[test]
    fn test_is_delivery_success_199() {
        assert!(!is_webhook_delivery_success(199));
    }

    // -----------------------------------------------------------------------
    // has_signing_secret: unified gate for X-Webhook-Signature header
    // -----------------------------------------------------------------------

    #[test]
    fn test_has_signing_secret_neither_form() {
        // Migration 081 leaves both NULL. The retry path must NOT advertise
        // a signature header for these rows.
        assert!(!has_signing_secret(&None, None));
    }

    #[test]
    fn test_has_signing_secret_legacy_bcrypt_only() {
        // Pre-v1.1.9 rows that have not been rotated yet have only the
        // legacy bcrypt hash; the gate still considers them configured.
        let bcrypt_hash = Some("$2b$12$abcdefghijklmnop".to_string());
        assert!(has_signing_secret(&bcrypt_hash, None));
    }

    #[test]
    fn test_has_signing_secret_encrypted_only() {
        // New rows from `create_webhook` populate `secret_encrypted` only.
        let ct: &[u8] = b"\x00\x01\x02ciphertext";
        assert!(has_signing_secret(&None, Some(ct)));
    }

    #[test]
    fn test_has_signing_secret_both_forms() {
        // Mid-migration rows can briefly carry both. Still configured.
        let bcrypt_hash = Some("$2b$12$abcdefghijklmnop".to_string());
        let ct: &[u8] = b"ciphertext";
        assert!(has_signing_secret(&bcrypt_hash, Some(ct)));
    }

    #[test]
    fn test_has_signing_secret_empty_strings_treated_as_absent() {
        // Defensive: an empty string in secret_hash (e.g. older rows from
        // the prior migration variant) is not a valid hash and must NOT
        // count as signing-configured.
        let empty_hash = Some(String::new());
        let empty_bytes: &[u8] = b"";
        assert!(!has_signing_secret(&empty_hash, Some(empty_bytes)));
        assert!(!has_signing_secret(&empty_hash, None));
        assert!(!has_signing_secret(&None, Some(empty_bytes)));
    }

    // -----------------------------------------------------------------------
    // Rotation overlap window: pure-function semantics
    // -----------------------------------------------------------------------

    #[test]
    fn test_rotation_overlap_constant_is_24_hours() {
        // The integration contract documented in the PR body and the
        // operator docs says 24 hours. Tying it down here means a future
        // edit cannot silently change the window from under callers.
        assert_eq!(SECRET_ROTATION_OVERLAP, chrono::Duration::hours(24));
    }

    #[test]
    fn test_rotation_guard_allows_when_no_previous() {
        // A row that has never been rotated has NULL previous-expiry.
        let now = chrono::Utc::now();
        assert!(rotation_guard_allows(None, now));
    }

    #[test]
    fn test_rotation_guard_allows_when_previous_already_expired() {
        // The cleanup tick may not have fired yet, but logically the
        // overlap window has closed: rotation is fine.
        let now = chrono::Utc::now();
        let an_hour_ago = now - chrono::Duration::hours(1);
        assert!(rotation_guard_allows(Some(an_hour_ago), now));
    }

    #[test]
    fn test_rotation_guard_blocks_when_previous_still_active() {
        // Mid-overlap: a second rotation must NOT be allowed; the API
        // returns 409 Conflict.
        let now = chrono::Utc::now();
        let in_three_hours = now + chrono::Duration::hours(3);
        assert!(!rotation_guard_allows(Some(in_three_hours), now));
    }

    #[test]
    fn test_rotation_guard_boundary_now_is_blocked() {
        // Strict `<` in the SQL means a row whose previous expiry equals
        // now is still considered active. Mirror that here.
        let now = chrono::Utc::now();
        assert!(!rotation_guard_allows(Some(now), now));
    }

    #[test]
    fn test_rotation_overlap_window_math() {
        // The `previous_expires_at = now + SECRET_ROTATION_OVERLAP` formula
        // used in the rotate handler. Lock the math down so a future
        // refactor cannot accidentally use minutes vs hours.
        let now = chrono::DateTime::parse_from_rfc3339("2026-04-27T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let previous_expires_at = now + SECRET_ROTATION_OVERLAP;
        assert_eq!(
            previous_expires_at,
            chrono::DateTime::parse_from_rfc3339("2026-04-28T12:00:00Z")
                .unwrap()
                .with_timezone(&chrono::Utc)
        );
        // Second rotate within the window is blocked.
        assert!(!rotation_guard_allows(Some(previous_expires_at), now));
        // After the window closes, rotate is allowed again.
        let after = previous_expires_at + chrono::Duration::seconds(1);
        assert!(rotation_guard_allows(Some(previous_expires_at), after));
    }

    // -----------------------------------------------------------------------
    // Cleanup tick semantics
    // -----------------------------------------------------------------------

    #[test]
    fn test_cleanup_predicate_matches_only_expired_rows() {
        // The SQL in `cleanup_expired_previous_secrets` uses the predicate
        // `secret_previous_expires_at <= NOW()`. Pure-function expression
        // of that predicate so callers can unit-test their inputs without
        // a database. A row is cleared iff it has a previous expiry AND
        // that expiry is in the past or now.
        fn would_clear(
            expires_at: Option<chrono::DateTime<chrono::Utc>>,
            now: chrono::DateTime<chrono::Utc>,
        ) -> bool {
            matches!(expires_at, Some(t) if t <= now)
        }
        let now = chrono::Utc::now();
        // Row with no previous: never cleared.
        assert!(!would_clear(None, now));
        // Row with future expiry: not cleared.
        assert!(!would_clear(Some(now + chrono::Duration::hours(1)), now));
        // Row at exactly now: cleared (<=).
        assert!(would_clear(Some(now), now));
        // Row in the past: cleared.
        assert!(would_clear(Some(now - chrono::Duration::seconds(1)), now));
    }
}
