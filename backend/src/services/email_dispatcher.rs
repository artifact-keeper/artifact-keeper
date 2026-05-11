//! Email subscription dispatcher service.
//!
//! Subscribes to the EventBus and dispatches matching email notifications
//! using the configured SmtpService. Each incoming domain event is compared
//! against the `email_subscriptions` table; rows whose `event_types` array
//! contains the mapped event type (and whose `repository_id` matches or is
//! NULL for global subscriptions) trigger one email per recipient.
//!
//! This module replaces the email path of the v1.1.x `notification_dispatcher`
//! removed in artifact-keeper#920. Webhook delivery now goes exclusively
//! through the v2 webhook pipeline (`webhook_producer` + `webhook_notifier`).

use std::sync::Arc;

use sqlx::{PgPool, Row};
use tokio::sync::broadcast;

use crate::services::event_bus::{DomainEvent, EventBus};
use crate::services::smtp_service::SmtpService;

/// Map a domain event type (e.g. `artifact.created`) to the email
/// subscription event type used in subscription filters
/// (e.g. `artifact.uploaded`).
///
/// The EventBus emits `artifact.created` for legacy reasons; the email
/// subscriptions API exposes `artifact.uploaded` as the user-facing name.
/// Unrecognized event types pass through unchanged.
pub fn map_event_type(event_type: &str) -> &str {
    match event_type {
        "artifact.created" => "artifact.uploaded",
        other => other,
    }
}

/// Row type for email subscription lookups.
#[derive(Debug)]
struct EmailSubscriptionRow {
    id: uuid::Uuid,
    recipients: Vec<String>,
}

/// Start the email dispatcher background task.
///
/// Spawns a tokio task that listens on the EventBus and, for each received
/// event, queries matching email subscriptions and sends one email per
/// recipient. The task exits when the broadcast channel closes (i.e. the
/// EventBus is dropped).
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
                            "Failed to dispatch email notification"
                        );
                    }
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    tracing::warn!(
                        skipped = n,
                        "Email dispatcher lagged, some events were dropped"
                    );
                }
                Err(broadcast::error::RecvError::Closed) => {
                    tracing::info!("EventBus closed, email dispatcher shutting down");
                    break;
                }
            }
        }
    });
}

/// Dispatch email notifications for a single domain event.
///
/// Queries `email_subscriptions` for enabled rows where `event_types`
/// contains the mapped event type and the repository_id matches (or is NULL
/// for global subscriptions), then sends one email per recipient.
async fn dispatch_event(
    db: &PgPool,
    smtp_service: &Option<Arc<SmtpService>>,
    event: &DomainEvent,
) -> std::result::Result<(), String> {
    let mapped = map_event_type(&event.event_type);
    let repo_id: Option<uuid::Uuid> = event.repository_id;

    let rows = sqlx::query(
        r#"
        SELECT id, recipients
        FROM email_subscriptions
        WHERE enabled = true
          AND $1 = ANY(event_types)
          AND (repository_id IS NULL OR repository_id = $2)
        "#,
    )
    .bind(mapped)
    .bind(repo_id)
    .fetch_all(db)
    .await
    .map_err(|e| format!("Failed to query email_subscriptions: {}", e))?;

    let subscriptions: Vec<EmailSubscriptionRow> = rows
        .into_iter()
        .map(|row| EmailSubscriptionRow {
            id: row.get("id"),
            recipients: row.get("recipients"),
        })
        .collect();

    for sub in &subscriptions {
        deliver_email(smtp_service, event, &sub.recipients, sub.id).await;
    }

    Ok(())
}

/// Build the subject line for an event notification email.
pub fn build_email_subject(event: &DomainEvent) -> String {
    format!(
        "Artifact Keeper: {} ({})",
        event.event_type, event.entity_id
    )
}

/// Build the plain-text body for an event notification email.
pub fn build_email_body_text(event: &DomainEvent) -> String {
    format!(
        "Event: {}\nEntity: {}\nActor: {}\nTime: {}",
        event.event_type,
        event.entity_id,
        event.actor.as_deref().unwrap_or("system"),
        event.timestamp,
    )
}

/// Build the HTML body for an event notification email.
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

/// Send the notification email to every recipient on the subscription.
///
/// Skips delivery silently when the SmtpService is not configured (matches
/// the prior notification_dispatcher behaviour so a deployment without SMTP
/// keeps producing events without log spam). Per-recipient send failures are
/// logged at warn level and do not abort the remaining recipients.
async fn deliver_email(
    smtp_service: &Option<Arc<SmtpService>>,
    event: &DomainEvent,
    recipients: &[String],
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

    if recipients.is_empty() {
        tracing::warn!(
            subscription_id = %subscription_id,
            "Email subscription has no recipients configured"
        );
        return;
    }

    let subject = build_email_subject(event);
    let body_text = build_email_body_text(event);
    let body_html = build_email_body_html(event);

    for to in recipients {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a sample event with a full set of fields populated.
    fn sample_event() -> DomainEvent {
        DomainEvent {
            event_type: "artifact.created".into(),
            entity_id: "550e8400-e29b-41d4-a716-446655440000".into(),
            repository_id: None,
            actor: Some("alice".into()),
            timestamp: "2026-05-09T12:00:00Z".into(),
        }
    }

    /// Build a sample event with no actor (typical for system-driven events).
    fn sample_event_no_actor() -> DomainEvent {
        DomainEvent {
            event_type: "scan.completed".into(),
            entity_id: "repo-key-abc".into(),
            repository_id: None,
            actor: None,
            timestamp: "2026-05-09T13:00:00Z".into(),
        }
    }

    // -----------------------------------------------------------------------
    // map_event_type
    // -----------------------------------------------------------------------

    #[test]
    fn test_map_event_type_artifact_created_aliases_uploaded() {
        assert_eq!(map_event_type("artifact.created"), "artifact.uploaded");
    }

    #[test]
    fn test_map_event_type_passthrough_uploaded() {
        assert_eq!(map_event_type("artifact.uploaded"), "artifact.uploaded");
    }

    #[test]
    fn test_map_event_type_passthrough_unknown() {
        assert_eq!(map_event_type("custom.event"), "custom.event");
    }

    #[test]
    fn test_map_event_type_empty_string() {
        assert_eq!(map_event_type(""), "");
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
            repository_id: None,
            actor: None,
            timestamp: "2026-01-01T00:00:00Z".into(),
        };
        assert_eq!(
            build_email_subject(&event),
            "Artifact Keeper: build.failed (build-42)"
        );
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
        assert!(body.contains("Time: 2026-05-09T12:00:00Z"));
    }

    #[test]
    fn test_build_email_body_text_no_actor_shows_system() {
        let event = sample_event_no_actor();
        let body = build_email_body_text(&event);
        assert!(body.contains("Actor: system"));
    }

    #[test]
    fn test_build_email_body_text_line_count() {
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

    // -----------------------------------------------------------------------
    // Integration: text and html bodies share the same data
    // -----------------------------------------------------------------------

    #[test]
    fn test_text_and_html_reference_same_event() {
        let event = sample_event();
        let text = build_email_body_text(&event);
        let html = build_email_body_html(&event);

        for needle in [
            "artifact.created",
            "550e8400-e29b-41d4-a716-446655440000",
            "alice",
            "2026-05-09T12:00:00Z",
        ] {
            assert!(text.contains(needle), "text missing {}", needle);
            assert!(html.contains(needle), "html missing {}", needle);
        }
    }
}
