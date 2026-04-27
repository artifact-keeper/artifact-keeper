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

/// Lookup table used by the v1.1.9 data migration that copies
/// `notification_subscriptions` rows (System B) into the `webhooks` table
/// (System A).
///
/// Notification event types use dot-separated names
/// (e.g. `artifact.uploaded`) while webhook event types use underscore
/// names (e.g. `artifact_uploaded`). Each tuple is
/// `(notification_event_type, webhook_event_type)`. This constant is the
/// authoritative source for the equivalent SQL `CASE` expression in
/// `migrations/081_migrate_notification_subscriptions_to_webhooks.sql`;
/// keeping both in sync prevents migrated rows from drifting out of the
/// webhook event vocabulary.
pub const NOTIFICATION_TO_WEBHOOK_EVENT_MAP: &[(&str, &str)] = &[
    ("artifact.uploaded", "artifact_uploaded"),
    ("artifact.deleted", "artifact_deleted"),
    ("scan.completed", "scan_completed"),
    ("scan.vulnerability_found", "scan_vulnerability_found"),
    ("repository.updated", "repository_updated"),
    ("repository.deleted", "repository_deleted"),
    ("build.completed", "build_completed"),
    ("build.failed", "build_failed"),
];

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

/// Extract email recipient strings from subscription config.
///
/// Returns `None` if the config is missing a `recipients` array or if the
/// array is empty. Non-string entries are silently skipped.
pub fn parse_email_recipients(config: &serde_json::Value) -> Option<Vec<String>> {
    let arr = config.get("recipients")?.as_array()?;
    let recipients: Vec<String> = arr
        .iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect();
    if recipients.is_empty() {
        None
    } else {
        Some(recipients)
    }
}

/// Build the email subject line for a notification event.
pub fn build_email_subject(event: &DomainEvent) -> String {
    format!(
        "Artifact Keeper: {} ({})",
        event.event_type, event.entity_id
    )
}

/// Build the plain-text email body for a notification event.
pub fn build_email_body_text(event: &DomainEvent) -> String {
    format!(
        "Event: {}\nEntity: {}\nActor: {}\nTime: {}",
        event.event_type,
        event.entity_id,
        event.actor.as_deref().unwrap_or("system"),
        event.timestamp,
    )
}

/// Build the HTML email body for a notification event.
pub fn build_email_body_html(event: &DomainEvent) -> String {
    format!(
        "<h2>Artifact Keeper Notification</h2>\
         <p><strong>Event:</strong> {}</p>\
         <p><strong>Entity:</strong> {}</p>\
         <p><strong>Actor:</strong> {}</p>\
         <p><strong>Time:</strong> {}</p>",
        event.event_type,
        event.entity_id,
        event.actor.as_deref().unwrap_or("system"),
        event.timestamp,
    )
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

    let recipients = match parse_email_recipients(config) {
        Some(r) => r,
        None => {
            tracing::warn!(
                subscription_id = %subscription_id,
                "Email subscription has no recipients configured"
            );
            return;
        }
    };

    let subject = build_email_subject(event);
    let body_text = build_email_body_text(event);
    let body_html = build_email_body_html(event);

    for to in &recipients {
        if let Err(e) = smtp.send_email(to, &subject, &body_html, &body_text).await {
            tracing::warn!(
                subscription_id = %subscription_id,
                recipient = %to,
                error = %e,
                "Failed to send email notification"
            );
        }
    }
}

/// Extract the webhook URL from subscription config.
///
/// Returns `None` if the config has no `url` string field.
pub fn parse_webhook_url(config: &serde_json::Value) -> Option<String> {
    config.get("url").and_then(|v| v.as_str()).map(String::from)
}

/// Build the JSON payload sent to a webhook endpoint.
pub fn build_webhook_payload(event: &DomainEvent) -> serde_json::Value {
    serde_json::json!({
        "event": event.event_type,
        "entity_id": event.entity_id,
        "actor": event.actor,
        "timestamp": event.timestamp,
    })
}

/// Compute an HMAC-SHA256 signature for a webhook payload.
///
/// Returns the hex-encoded signature prefixed with `sha256=`, matching the
/// format expected by the `X-Signature-256` header. Returns `None` if the
/// payload cannot be serialized.
pub fn compute_webhook_signature(payload: &serde_json::Value, secret: &str) -> Option<String> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let payload_bytes = serde_json::to_vec(payload).ok()?;
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).ok()?;
    mac.update(&payload_bytes);
    let signature = hex::encode(mac.finalize().into_bytes());
    Some(format!("sha256={}", signature))
}

/// Determine whether a subscription channel name is one we know how to
/// deliver to.
pub fn is_known_channel(channel: &str) -> bool {
    matches!(channel, "email" | "webhook")
}

/// Deliver a notification via webhook HTTP POST.
async fn deliver_webhook(
    event: &DomainEvent,
    config: &serde_json::Value,
    subscription_id: uuid::Uuid,
) {
    let url = match parse_webhook_url(config) {
        Some(u) => u,
        None => {
            tracing::warn!(
                subscription_id = %subscription_id,
                "Webhook subscription has no URL configured"
            );
            return;
        }
    };

    let payload = build_webhook_payload(event);

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

    let mut request = client.post(&url).json(&payload);

    // Add HMAC signature header if a secret is configured
    if let Some(secret) = config.get("secret").and_then(|v| v.as_str()) {
        if let Some(sig) = compute_webhook_signature(&payload, secret) {
            request = request.header("X-Signature-256", sig);
        }
    }

    match request.send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            if !(200..300).contains(&status) {
                tracing::warn!(
                    subscription_id = %subscription_id,
                    url = %url,
                    status = status,
                    "Webhook notification delivery returned non-2xx status"
                );
            }
        }
        Err(e) => {
            tracing::warn!(
                subscription_id = %subscription_id,
                url = %url,
                error = %e,
                "Webhook notification delivery failed"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to build a test DomainEvent with all fields populated.
    fn sample_event() -> DomainEvent {
        DomainEvent {
            event_type: "artifact.created".into(),
            entity_id: "550e8400-e29b-41d4-a716-446655440000".into(),
            actor: Some("alice".into()),
            timestamp: "2026-04-08T12:00:00Z".into(),
        }
    }

    /// Helper to build a DomainEvent with no actor.
    fn sample_event_no_actor() -> DomainEvent {
        DomainEvent {
            event_type: "scan.completed".into(),
            entity_id: "repo-key-abc".into(),
            actor: None,
            timestamp: "2026-04-08T13:00:00Z".into(),
        }
    }

    // -----------------------------------------------------------------------
    // map_event_type
    // -----------------------------------------------------------------------

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

    // -----------------------------------------------------------------------
    // NOTIFICATION_TO_WEBHOOK_EVENT_MAP
    // -----------------------------------------------------------------------

    #[test]
    fn test_notification_to_webhook_event_map_covers_all_valid_event_types() {
        // Every event type the notifications API accepts must have a
        // webhook equivalent so the data migration cannot drop events.
        use crate::api::handlers::notifications::VALID_EVENT_TYPES;
        for et in VALID_EVENT_TYPES {
            assert!(
                NOTIFICATION_TO_WEBHOOK_EVENT_MAP
                    .iter()
                    .any(|(n, _)| n == et),
                "missing webhook mapping for notification event '{}'",
                et
            );
        }
    }

    #[test]
    fn test_notification_to_webhook_event_map_uses_underscore_names() {
        // Webhook events use underscore-separated names; verify the map
        // does not accidentally store a dot-form value on the webhook side.
        for (_, webhook_name) in NOTIFICATION_TO_WEBHOOK_EVENT_MAP {
            assert!(
                !webhook_name.contains('.'),
                "webhook event name '{}' must not contain a dot",
                webhook_name
            );
        }
    }

    #[test]
    fn test_notification_to_webhook_event_map_artifact_uploaded() {
        let webhook_name = NOTIFICATION_TO_WEBHOOK_EVENT_MAP
            .iter()
            .find(|(n, _)| *n == "artifact.uploaded")
            .map(|(_, w)| *w);
        assert_eq!(webhook_name, Some("artifact_uploaded"));
    }

    #[test]
    fn test_notification_to_webhook_event_map_no_duplicate_keys() {
        let mut seen: Vec<&str> = Vec::new();
        for (n, _) in NOTIFICATION_TO_WEBHOOK_EVENT_MAP {
            assert!(!seen.contains(n), "duplicate key in mapping: {}", n);
            seen.push(n);
        }
    }

    // -----------------------------------------------------------------------
    // parse_email_recipients
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_email_recipients_valid() {
        let config = serde_json::json!({"recipients": ["a@b.com", "c@d.com"]});
        let result = parse_email_recipients(&config).unwrap();
        assert_eq!(result, vec!["a@b.com", "c@d.com"]);
    }

    #[test]
    fn test_parse_email_recipients_single() {
        let config = serde_json::json!({"recipients": ["admin@example.com"]});
        let result = parse_email_recipients(&config).unwrap();
        assert_eq!(result, vec!["admin@example.com"]);
    }

    #[test]
    fn test_parse_email_recipients_missing_key() {
        let config = serde_json::json!({});
        assert!(parse_email_recipients(&config).is_none());
    }

    #[test]
    fn test_parse_email_recipients_not_array() {
        let config = serde_json::json!({"recipients": "admin@example.com"});
        assert!(parse_email_recipients(&config).is_none());
    }

    #[test]
    fn test_parse_email_recipients_empty_array() {
        let config = serde_json::json!({"recipients": []});
        assert!(parse_email_recipients(&config).is_none());
    }

    #[test]
    fn test_parse_email_recipients_skips_non_strings() {
        let config = serde_json::json!({"recipients": [42, "valid@email.com", null]});
        let result = parse_email_recipients(&config).unwrap();
        assert_eq!(result, vec!["valid@email.com"]);
    }

    #[test]
    fn test_parse_email_recipients_all_non_strings() {
        let config = serde_json::json!({"recipients": [42, true, null]});
        assert!(parse_email_recipients(&config).is_none());
    }

    // -----------------------------------------------------------------------
    // build_email_subject
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_email_subject_with_actor() {
        let event = sample_event();
        let subject = build_email_subject(&event);
        assert_eq!(
            subject,
            "Artifact Keeper: artifact.created (550e8400-e29b-41d4-a716-446655440000)"
        );
    }

    #[test]
    fn test_build_email_subject_no_actor() {
        let event = sample_event_no_actor();
        let subject = build_email_subject(&event);
        assert!(subject.contains("scan.completed"));
        assert!(subject.contains("repo-key-abc"));
    }

    #[test]
    fn test_build_email_subject_format() {
        let event = DomainEvent {
            event_type: "build.failed".into(),
            entity_id: "build-42".into(),
            actor: None,
            timestamp: "2026-01-01T00:00:00Z".into(),
        };
        let subject = build_email_subject(&event);
        assert_eq!(subject, "Artifact Keeper: build.failed (build-42)");
    }

    // -----------------------------------------------------------------------
    // build_email_body_text
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_email_body_text_with_actor() {
        let event = sample_event();
        let body = build_email_body_text(&event);
        assert!(body.contains("Event: artifact.created"));
        assert!(body.contains("Entity: 550e8400-e29b-41d4-a716-446655440000"));
        assert!(body.contains("Actor: alice"));
        assert!(body.contains("Time: 2026-04-08T12:00:00Z"));
    }

    #[test]
    fn test_build_email_body_text_no_actor_shows_system() {
        let event = sample_event_no_actor();
        let body = build_email_body_text(&event);
        assert!(body.contains("Actor: system"));
    }

    #[test]
    fn test_build_email_body_text_contains_newlines() {
        let event = sample_event();
        let body = build_email_body_text(&event);
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(lines.len(), 4);
        assert!(lines[0].starts_with("Event:"));
        assert!(lines[1].starts_with("Entity:"));
        assert!(lines[2].starts_with("Actor:"));
        assert!(lines[3].starts_with("Time:"));
    }

    // -----------------------------------------------------------------------
    // build_email_body_html
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_email_body_html_with_actor() {
        let event = sample_event();
        let html = build_email_body_html(&event);
        assert!(html.contains("<h2>Artifact Keeper Notification</h2>"));
        assert!(html.contains("<strong>Event:</strong> artifact.created"));
        assert!(html.contains("<strong>Actor:</strong> alice"));
    }

    #[test]
    fn test_build_email_body_html_no_actor_shows_system() {
        let event = sample_event_no_actor();
        let html = build_email_body_html(&event);
        assert!(html.contains("<strong>Actor:</strong> system"));
    }

    #[test]
    fn test_build_email_body_html_contains_entity() {
        let event = sample_event();
        let html = build_email_body_html(&event);
        assert!(html.contains("550e8400-e29b-41d4-a716-446655440000"));
    }

    #[test]
    fn test_build_email_body_html_contains_timestamp() {
        let event = sample_event();
        let html = build_email_body_html(&event);
        assert!(html.contains("2026-04-08T12:00:00Z"));
    }

    // -----------------------------------------------------------------------
    // parse_webhook_url
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_webhook_url_valid_https() {
        let config = serde_json::json!({"url": "https://hooks.example.com/notify"});
        assert_eq!(
            parse_webhook_url(&config).unwrap(),
            "https://hooks.example.com/notify"
        );
    }

    #[test]
    fn test_parse_webhook_url_valid_http() {
        let config = serde_json::json!({"url": "http://internal.example.com/hook"});
        assert_eq!(
            parse_webhook_url(&config).unwrap(),
            "http://internal.example.com/hook"
        );
    }

    #[test]
    fn test_parse_webhook_url_missing() {
        let config = serde_json::json!({});
        assert!(parse_webhook_url(&config).is_none());
    }

    #[test]
    fn test_parse_webhook_url_not_string() {
        let config = serde_json::json!({"url": 42});
        assert!(parse_webhook_url(&config).is_none());
    }

    #[test]
    fn test_parse_webhook_url_null() {
        let config = serde_json::json!({"url": null});
        assert!(parse_webhook_url(&config).is_none());
    }

    #[test]
    fn test_parse_webhook_url_with_extra_fields() {
        let config = serde_json::json!({
            "url": "https://hooks.example.com/x",
            "secret": "my-secret"
        });
        assert_eq!(
            parse_webhook_url(&config).unwrap(),
            "https://hooks.example.com/x"
        );
    }

    // -----------------------------------------------------------------------
    // build_webhook_payload
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_webhook_payload_structure() {
        let event = sample_event();
        let payload = build_webhook_payload(&event);
        assert_eq!(payload["event"], "artifact.created");
        assert_eq!(payload["entity_id"], "550e8400-e29b-41d4-a716-446655440000");
        assert_eq!(payload["actor"], "alice");
        assert_eq!(payload["timestamp"], "2026-04-08T12:00:00Z");
    }

    #[test]
    fn test_build_webhook_payload_no_actor() {
        let event = sample_event_no_actor();
        let payload = build_webhook_payload(&event);
        assert_eq!(payload["event"], "scan.completed");
        assert!(payload["actor"].is_null());
    }

    #[test]
    fn test_build_webhook_payload_is_valid_json() {
        let event = sample_event();
        let payload = build_webhook_payload(&event);
        let serialized = serde_json::to_string(&payload).unwrap();
        let reparsed: serde_json::Value = serde_json::from_str(&serialized).unwrap();
        assert_eq!(reparsed, payload);
    }

    #[test]
    fn test_build_webhook_payload_has_four_fields() {
        let event = sample_event();
        let payload = build_webhook_payload(&event);
        let obj = payload.as_object().unwrap();
        assert_eq!(obj.len(), 4);
        assert!(obj.contains_key("event"));
        assert!(obj.contains_key("entity_id"));
        assert!(obj.contains_key("actor"));
        assert!(obj.contains_key("timestamp"));
    }

    // -----------------------------------------------------------------------
    // compute_webhook_signature
    // -----------------------------------------------------------------------

    #[test]
    fn test_compute_webhook_signature_deterministic() {
        let payload = serde_json::json!({"event": "test"});
        let sig1 = compute_webhook_signature(&payload, "secret123").unwrap();
        let sig2 = compute_webhook_signature(&payload, "secret123").unwrap();
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn test_compute_webhook_signature_prefix() {
        let payload = serde_json::json!({"event": "test"});
        let sig = compute_webhook_signature(&payload, "key").unwrap();
        assert!(sig.starts_with("sha256="));
    }

    #[test]
    fn test_compute_webhook_signature_hex_length() {
        let payload = serde_json::json!({"event": "test"});
        let sig = compute_webhook_signature(&payload, "key").unwrap();
        // "sha256=" (7 chars) + 64 hex chars (SHA-256 = 32 bytes = 64 hex)
        assert_eq!(sig.len(), 7 + 64);
    }

    #[test]
    fn test_compute_webhook_signature_different_secrets() {
        let payload = serde_json::json!({"event": "test"});
        let sig1 = compute_webhook_signature(&payload, "secret-a").unwrap();
        let sig2 = compute_webhook_signature(&payload, "secret-b").unwrap();
        assert_ne!(sig1, sig2);
    }

    #[test]
    fn test_compute_webhook_signature_different_payloads() {
        let p1 = serde_json::json!({"event": "a"});
        let p2 = serde_json::json!({"event": "b"});
        let sig1 = compute_webhook_signature(&p1, "same-key").unwrap();
        let sig2 = compute_webhook_signature(&p2, "same-key").unwrap();
        assert_ne!(sig1, sig2);
    }

    #[test]
    fn test_compute_webhook_signature_empty_secret() {
        let payload = serde_json::json!({"event": "test"});
        // Empty secret should still work (HMAC accepts zero-length keys)
        let sig = compute_webhook_signature(&payload, "");
        assert!(sig.is_some());
        assert!(sig.unwrap().starts_with("sha256="));
    }

    #[test]
    fn test_compute_webhook_signature_complex_payload() {
        let event = sample_event();
        let payload = build_webhook_payload(&event);
        let sig = compute_webhook_signature(&payload, "webhook-secret");
        assert!(sig.is_some());
    }

    // -----------------------------------------------------------------------
    // is_known_channel
    // -----------------------------------------------------------------------

    #[test]
    fn test_is_known_channel_email() {
        assert!(is_known_channel("email"));
    }

    #[test]
    fn test_is_known_channel_webhook() {
        assert!(is_known_channel("webhook"));
    }

    #[test]
    fn test_is_known_channel_unknown() {
        assert!(!is_known_channel("sms"));
    }

    #[test]
    fn test_is_known_channel_empty() {
        assert!(!is_known_channel(""));
    }

    #[test]
    fn test_is_known_channel_case_sensitive() {
        assert!(!is_known_channel("Email"));
        assert!(!is_known_channel("WEBHOOK"));
    }

    // -----------------------------------------------------------------------
    // Integration: email body consistency
    // -----------------------------------------------------------------------

    #[test]
    fn test_email_text_and_html_contain_same_data() {
        let event = sample_event();
        let text = build_email_body_text(&event);
        let html = build_email_body_html(&event);

        // Both should contain the same key fields
        assert!(text.contains("artifact.created"));
        assert!(html.contains("artifact.created"));

        assert!(text.contains("550e8400-e29b-41d4-a716-446655440000"));
        assert!(html.contains("550e8400-e29b-41d4-a716-446655440000"));

        assert!(text.contains("alice"));
        assert!(html.contains("alice"));

        assert!(text.contains("2026-04-08T12:00:00Z"));
        assert!(html.contains("2026-04-08T12:00:00Z"));
    }

    #[test]
    fn test_email_subject_and_body_reference_same_event() {
        let event = sample_event();
        let subject = build_email_subject(&event);
        let body = build_email_body_text(&event);

        // Subject and body should both reference the event type
        assert!(subject.contains("artifact.created"));
        assert!(body.contains("artifact.created"));
    }

    // -----------------------------------------------------------------------
    // Integration: webhook payload + signature round-trip
    // -----------------------------------------------------------------------

    #[test]
    fn test_webhook_payload_and_signature_round_trip() {
        let event = sample_event();
        let payload = build_webhook_payload(&event);
        let sig = compute_webhook_signature(&payload, "test-secret").unwrap();

        // Verify the signature by recomputing it
        let sig_again = compute_webhook_signature(&payload, "test-secret").unwrap();
        assert_eq!(sig, sig_again);
    }

    #[test]
    fn test_webhook_url_and_payload_for_sample_event() {
        let config = serde_json::json!({
            "url": "https://hooks.example.com/notify",
            "secret": "my-secret"
        });
        let url = parse_webhook_url(&config).unwrap();
        assert_eq!(url, "https://hooks.example.com/notify");

        let event = sample_event();
        let payload = build_webhook_payload(&event);
        assert_eq!(payload["event"], "artifact.created");

        let sig = compute_webhook_signature(&payload, "my-secret").unwrap();
        assert!(sig.starts_with("sha256="));
    }

    // -----------------------------------------------------------------------
    // map_event_type + payload integration
    // -----------------------------------------------------------------------

    #[test]
    fn test_mapped_event_type_in_payload() {
        let event = DomainEvent {
            event_type: "artifact.created".into(),
            entity_id: "abc".into(),
            actor: None,
            timestamp: "2026-01-01T00:00:00Z".into(),
        };
        let mapped = map_event_type(&event.event_type);
        assert_eq!(mapped, "artifact.uploaded");

        // The payload uses the raw event type, not the mapped one
        let payload = build_webhook_payload(&event);
        assert_eq!(payload["event"], "artifact.created");
    }
}
