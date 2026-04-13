//! Notification dispatcher service.
//!
//! Subscribes to the EventBus and dispatches matching notifications to the
//! configured delivery channels (email via SmtpService, webhook via HTTP POST).
//! Each incoming domain event is compared against the notification_subscriptions
//! table. Subscriptions whose event_types array contains the event type (and
//! whose repository_id matches, if set) trigger a delivery attempt.

use std::sync::Arc;

use sqlx::{PgPool, Row};
use tokio::sync::broadcast;

use crate::services::event_bus::{DomainEvent, EventBus};
use crate::services::smtp_service::SmtpService;

/// Maps a domain event type (e.g. "artifact.created") to the notification
/// event type used in subscription filters (e.g. "artifact.uploaded").
///
/// The EventBus uses short-form event types while the notification system
/// uses a slightly different naming convention. This function bridges
/// between the two. Unrecognized event types are passed through unchanged.
pub fn map_event_type(event_type: &str) -> &str {
    match event_type {
        "artifact.created" => "artifact.uploaded",
        "artifact.uploaded" => "artifact.uploaded",
        "artifact.deleted" => "artifact.deleted",
        "scan.completed" => "scan.completed",
        "scan.vulnerability_found" => "scan.vulnerability_found",
        "repository.updated" => "repository.updated",
        "repository.deleted" => "repository.deleted",
        "build.completed" => "build.completed",
        "build.failed" => "build.failed",
        other => other,
    }
}

/// Row type for notification subscription lookups.
#[derive(Debug)]
struct SubscriptionRow {
    id: uuid::Uuid,
    channel: String,
    config: serde_json::Value,
}

/// Start the notification dispatcher background task.
///
/// This function spawns a tokio task that listens on the EventBus and, for
/// each received event, queries matching subscriptions and delivers
/// notifications. The task runs until the broadcast channel is closed (i.e.
/// the EventBus is dropped).
pub fn start_dispatcher(
    event_bus: Arc<EventBus>,
    db: PgPool,
    smtp_service: Option<Arc<SmtpService>>,
) {
    let mut rx = event_bus.subscribe();

    tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(event) => {
                    if let Err(e) = dispatch_event(&db, &smtp_service, &event).await {
                        tracing::warn!(
                            event_type = %event.event_type,
                            error = %e,
                            "Failed to dispatch notification"
                        );
                    }
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    tracing::warn!(
                        skipped = n,
                        "Notification dispatcher lagged, some events were dropped"
                    );
                }
                Err(broadcast::error::RecvError::Closed) => {
                    tracing::info!("EventBus closed, notification dispatcher shutting down");
                    break;
                }
            }
        }
    });
}

/// Dispatch notifications for a single domain event.
///
/// Queries matching subscriptions (where event_types contains the mapped event
/// type and the repository_id matches) and delivers via the appropriate channel.
async fn dispatch_event(
    db: &PgPool,
    smtp_service: &Option<Arc<SmtpService>>,
    event: &DomainEvent,
) -> std::result::Result<(), String> {
    let notification_event = map_event_type(&event.event_type);

    // Try to parse entity_id as a UUID (repository ID). If it is not a valid
    // UUID, the event does not carry a repository context and we only match
    // global subscriptions (repository_id IS NULL).
    let repo_id: Option<uuid::Uuid> = uuid::Uuid::parse_str(&event.entity_id).ok();

    let rows = sqlx::query(
        r#"
        SELECT id, channel, config
        FROM notification_subscriptions
        WHERE enabled = true
          AND $1 = ANY(event_types)
          AND (repository_id IS NULL OR repository_id = $2)
        "#,
    )
    .bind(notification_event)
    .bind(repo_id)
    .fetch_all(db)
    .await
    .map_err(|e| format!("Failed to query notification subscriptions: {}", e))?;

    let subscriptions: Vec<SubscriptionRow> = rows
        .into_iter()
        .map(|row| SubscriptionRow {
            id: row.get("id"),
            channel: row.get("channel"),
            config: row.get("config"),
        })
        .collect();

    for sub in &subscriptions {
        match sub.channel.as_str() {
            "email" => {
                deliver_email(smtp_service, event, &sub.config, sub.id).await;
            }
            "webhook" => {
                deliver_webhook(event, &sub.config, sub.id).await;
            }
            other => {
                tracing::warn!(
                    subscription_id = %sub.id,
                    channel = other,
                    "Unknown notification channel, skipping"
                );
            }
        }
    }

    Ok(())
}

/// Deliver a notification via email.
async fn deliver_email(
    smtp_service: &Option<Arc<SmtpService>>,
    event: &DomainEvent,
    config: &serde_json::Value,
    subscription_id: uuid::Uuid,
) {
    let smtp = match smtp_service {
        Some(s) if s.is_configured() => s,
        _ => {
            tracing::debug!(
                subscription_id = %subscription_id,
                "SMTP not configured, skipping email notification"
            );
            return;
        }
    };

    let recipients = match config.get("recipients").and_then(|v| v.as_array()) {
        Some(r) => r,
        None => {
            tracing::warn!(
                subscription_id = %subscription_id,
                "Email subscription has no recipients configured"
            );
            return;
        }
    };

    let subject = format!(
        "Artifact Keeper: {} ({})",
        event.event_type, event.entity_id
    );
    let body_text = format!(
        "Event: {}\nEntity: {}\nActor: {}\nTime: {}",
        event.event_type,
        event.entity_id,
        event.actor.as_deref().unwrap_or("system"),
        event.timestamp,
    );
    let body_html = format!(
        "<h2>Artifact Keeper Notification</h2>\
         <p><strong>Event:</strong> {}</p>\
         <p><strong>Entity:</strong> {}</p>\
         <p><strong>Actor:</strong> {}</p>\
         <p><strong>Time:</strong> {}</p>",
        event.event_type,
        event.entity_id,
        event.actor.as_deref().unwrap_or("system"),
        event.timestamp,
    );

    for recipient_value in recipients {
        if let Some(to) = recipient_value.as_str() {
            if let Err(e) = smtp.send_email(to, &subject, &body_html, &body_text).await {
                tracing::warn!(
                    subscription_id = %subscription_id,
                    recipient = to,
                    error = %e,
                    "Failed to send email notification"
                );
            }
        }
    }
}

/// Deliver a notification via webhook HTTP POST.
async fn deliver_webhook(
    event: &DomainEvent,
    config: &serde_json::Value,
    subscription_id: uuid::Uuid,
) {
    let url = match config.get("url").and_then(|v| v.as_str()) {
        Some(u) => u,
        None => {
            tracing::warn!(
                subscription_id = %subscription_id,
                "Webhook subscription has no URL configured"
            );
            return;
        }
    };

    let payload = serde_json::json!({
        "event": event.event_type,
        "entity_id": event.entity_id,
        "actor": event.actor,
        "timestamp": event.timestamp,
    });

    let client = match crate::services::http_client::base_client_builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(
                subscription_id = %subscription_id,
                error = %e,
                "Failed to build HTTP client for webhook delivery"
            );
            return;
        }
    };

    let mut request = client.post(url).json(&payload);

    // Add HMAC signature header if a secret is configured
    if let Some(secret) = config.get("secret").and_then(|v| v.as_str()) {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        if let Ok(payload_bytes) = serde_json::to_vec(&payload) {
            if let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(secret.as_bytes()) {
                mac.update(&payload_bytes);
                let signature = hex::encode(mac.finalize().into_bytes());
                request = request.header("X-Signature-256", format!("sha256={}", signature));
            }
        }
    }

    match request.send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            if !(200..300).contains(&status) {
                tracing::warn!(
                    subscription_id = %subscription_id,
                    url = url,
                    status = status,
                    "Webhook notification delivery returned non-2xx status"
                );
            }
        }
        Err(e) => {
            tracing::warn!(
                subscription_id = %subscription_id,
                url = url,
                error = %e,
                "Webhook notification delivery failed"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_map_event_type_artifact_created() {
        assert_eq!(map_event_type("artifact.created"), "artifact.uploaded");
    }

    #[test]
    fn test_map_event_type_artifact_uploaded() {
        assert_eq!(map_event_type("artifact.uploaded"), "artifact.uploaded");
    }

    #[test]
    fn test_map_event_type_artifact_deleted() {
        assert_eq!(map_event_type("artifact.deleted"), "artifact.deleted");
    }

    #[test]
    fn test_map_event_type_scan_completed() {
        assert_eq!(map_event_type("scan.completed"), "scan.completed");
    }

    #[test]
    fn test_map_event_type_scan_vulnerability() {
        assert_eq!(
            map_event_type("scan.vulnerability_found"),
            "scan.vulnerability_found"
        );
    }

    #[test]
    fn test_map_event_type_repository_updated() {
        assert_eq!(map_event_type("repository.updated"), "repository.updated");
    }

    #[test]
    fn test_map_event_type_repository_deleted() {
        assert_eq!(map_event_type("repository.deleted"), "repository.deleted");
    }

    #[test]
    fn test_map_event_type_build_completed() {
        assert_eq!(map_event_type("build.completed"), "build.completed");
    }

    #[test]
    fn test_map_event_type_build_failed() {
        assert_eq!(map_event_type("build.failed"), "build.failed");
    }

    #[test]
    fn test_map_event_type_unknown_passthrough() {
        assert_eq!(map_event_type("custom.event"), "custom.event");
    }

    #[test]
    fn test_map_event_type_empty_string() {
        assert_eq!(map_event_type(""), "");
    }
}
