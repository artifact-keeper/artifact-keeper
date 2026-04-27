//! Webhook producer service.
//!
//! Subscribes to the EventBus and writes a row into `webhook_deliveries` for
//! every webhook whose `events` array contains the mapped event type and whose
//! `repository_id` matches (or is NULL, meaning "global"). The row is enqueued
//! with `next_retry_at = NOW()`, `attempts = 0`, `success = false`. The retry
//! scheduler in `crate::api::handlers::webhooks::process_webhook_retries`
//! (driven from `scheduler_service`) picks rows up on its 30-second tick and
//! performs the actual HTTP POST.
//!
//! This module is the missing producer in v1.1.9. Before it existed, the
//! retry scheduler had nothing to retry: no code path inserted into
//! `webhook_deliveries`. The result was that webhook delivery was dead code.
//!
//! Companion ticket E2 (HMAC signing) and E4 (richer payload schema) are
//! independent and can land before or after this PR. This module emits a
//! minimal v1 payload. HMAC signing happens at delivery time, not enqueue
//! time, so it is the retry scheduler's responsibility, not this producer's.

use std::sync::Arc;

use sqlx::{PgPool, Row};
use tokio::sync::broadcast;

use crate::services::event_bus::{DomainEvent, EventBus};

/// Map an EventBus event type (e.g. "artifact.created", "repository.deleted")
/// to the underscore-form string used in the `webhooks.events` text array
/// (e.g. "artifact_uploaded", "repository_deleted").
///
/// The webhook system uses snake_case underscore identifiers to match
/// `WebhookEvent::Display` in `crate::api::handlers::webhooks`. The EventBus
/// uses dotted, lower-case identifiers. This function bridges the two.
///
/// Returns `None` for events that do not have a corresponding `WebhookEvent`
/// variant. Such events are silently skipped (no rows are enqueued).
pub fn map_event_type(event_type: &str) -> Option<&'static str> {
    match event_type {
        // Artifact uploads: both ".created" (legacy) and ".uploaded" (new) emit
        // the artifact_uploaded webhook. Mirrors the alias in
        // notification_dispatcher::map_event_type.
        "artifact.created" | "artifact.uploaded" => Some("artifact_uploaded"),
        "artifact.deleted" => Some("artifact_deleted"),
        "repository.created" => Some("repository_created"),
        "repository.deleted" => Some("repository_deleted"),
        "user.created" => Some("user_created"),
        "user.deleted" => Some("user_deleted"),
        "build.started" => Some("build_started"),
        "build.completed" => Some("build_completed"),
        "build.failed" => Some("build_failed"),
        _ => None,
    }
}

/// Build the v1 JSON payload that gets stored in `webhook_deliveries.payload`.
///
/// The shape is intentionally minimal in v1.1.9. E4 will add
/// `event_schema_version` and richer event-specific fields. Consumers that
/// rely on these fields today should pin to a specific producer version.
pub fn build_event_payload(event: &DomainEvent, mapped_event: &str) -> serde_json::Value {
    serde_json::json!({
        "event": mapped_event,
        "entity_id": event.entity_id,
        "actor": event.actor,
        "timestamp": event.timestamp,
        "payload": serde_json::Value::Null,
    })
}

/// Row type for the webhook lookup query.
#[derive(Debug)]
struct MatchingWebhookRow {
    id: uuid::Uuid,
}

/// Start the webhook producer background task.
///
/// Spawns a tokio task that subscribes to the EventBus and, for each received
/// event, looks up all enabled matching webhooks and enqueues a row into
/// `webhook_deliveries`. The task runs until the broadcast channel is closed
/// (i.e. the EventBus is dropped at shutdown).
///
/// # Idempotency
///
/// Tokio broadcast channels can deliver duplicates if a slow subscriber lags
/// the buffer. This module accepts rare duplicates rather than adding a
/// migration to dedupe at insert time. The downstream retry scheduler is
/// idempotent at the row level: a duplicate row just produces one extra
/// delivery. Correctness is preserved; the cost is at-most-once becomes
/// at-least-once. This is the standard tradeoff for Postgres-backed work
/// queues and it matches what other Artifact Keeper consumers expect.
pub fn start_webhook_producer(event_bus: Arc<EventBus>, db: PgPool) {
    let mut rx = event_bus.subscribe();

    tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(event) => {
                    if let Err(e) = enqueue_for_event(&db, &event).await {
                        tracing::warn!(
                            event_type = %event.event_type,
                            entity_id = %event.entity_id,
                            error = %e,
                            "Failed to enqueue webhook deliveries for event"
                        );
                    }
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    tracing::warn!(
                        skipped = n,
                        "Webhook producer lagged, some events were dropped"
                    );
                }
                Err(broadcast::error::RecvError::Closed) => {
                    tracing::info!("EventBus closed, webhook producer shutting down");
                    break;
                }
            }
        }
    });
}

/// Enqueue webhook_deliveries rows for a single domain event.
///
/// Looks up enabled webhooks whose `events` array contains the mapped event
/// type and whose `repository_id` is either NULL (global) or matches the
/// event's entity_id when interpretable as a UUID. For each match, INSERTs a
/// row into `webhook_deliveries` with `attempts = 0`, `next_retry_at = NOW()`,
/// `success = false`. The retry scheduler picks these up on its tick.
///
/// Uses `sqlx::query()` (not the macro) to avoid contention on the offline
/// SQLx query cache while parallel webhook PRs are in flight (E1, E2, E4).
async fn enqueue_for_event(db: &PgPool, event: &DomainEvent) -> std::result::Result<(), String> {
    let mapped_event = match map_event_type(&event.event_type) {
        Some(m) => m,
        None => {
            // No webhook subscribers for this event type. Silently skip.
            return Ok(());
        }
    };

    // Try to parse entity_id as a UUID for repository scoping. If it is not
    // a UUID, only global webhooks (repository_id IS NULL) match.
    let repo_id: Option<uuid::Uuid> = uuid::Uuid::parse_str(&event.entity_id).ok();

    let raw_rows = sqlx::query(
        r#"
        SELECT id
        FROM webhooks
        WHERE is_enabled = true
          AND $1 = ANY(events)
          AND (repository_id IS NULL OR repository_id = $2)
        "#,
    )
    .bind(mapped_event)
    .bind(repo_id)
    .fetch_all(db)
    .await
    .map_err(|e| format!("Failed to query webhooks: {}", e))?;

    let webhooks: Vec<MatchingWebhookRow> = raw_rows
        .into_iter()
        .map(|row| MatchingWebhookRow { id: row.get("id") })
        .collect();

    if webhooks.is_empty() {
        return Ok(());
    }

    let payload = build_event_payload(event, mapped_event);

    for webhook in &webhooks {
        let result = sqlx::query(
            r#"
            INSERT INTO webhook_deliveries
                (webhook_id, event, payload, attempts, next_retry_at, success)
            VALUES ($1, $2, $3, 0, NOW(), false)
            "#,
        )
        .bind(webhook.id)
        .bind(mapped_event)
        .bind(&payload)
        .execute(db)
        .await;

        match result {
            Ok(_) => {
                crate::services::metrics_service::record_webhook_delivery_enqueued(mapped_event);
            }
            Err(e) => {
                tracing::warn!(
                    webhook_id = %webhook.id,
                    event = mapped_event,
                    error = %e,
                    "Failed to insert webhook_deliveries row"
                );
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_event(event_type: &str) -> DomainEvent {
        DomainEvent {
            event_type: event_type.to_string(),
            entity_id: "550e8400-e29b-41d4-a716-446655440000".into(),
            actor: Some("alice".into()),
            timestamp: "2026-04-08T12:00:00Z".into(),
        }
    }

    // -----------------------------------------------------------------------
    // map_event_type: every WebhookEvent variant must map
    // -----------------------------------------------------------------------

    #[test]
    fn test_map_artifact_uploaded() {
        assert_eq!(
            map_event_type("artifact.uploaded"),
            Some("artifact_uploaded")
        );
    }

    #[test]
    fn test_map_artifact_created_aliases_uploaded() {
        // The EventBus uses ".created"; the webhook system uses "uploaded".
        // This alias mirrors notification_dispatcher::map_event_type.
        assert_eq!(
            map_event_type("artifact.created"),
            Some("artifact_uploaded")
        );
    }

    #[test]
    fn test_map_artifact_deleted() {
        assert_eq!(map_event_type("artifact.deleted"), Some("artifact_deleted"));
    }

    #[test]
    fn test_map_repository_created() {
        assert_eq!(
            map_event_type("repository.created"),
            Some("repository_created")
        );
    }

    #[test]
    fn test_map_repository_deleted() {
        assert_eq!(
            map_event_type("repository.deleted"),
            Some("repository_deleted")
        );
    }

    #[test]
    fn test_map_user_created() {
        assert_eq!(map_event_type("user.created"), Some("user_created"));
    }

    #[test]
    fn test_map_user_deleted() {
        assert_eq!(map_event_type("user.deleted"), Some("user_deleted"));
    }

    #[test]
    fn test_map_build_started() {
        assert_eq!(map_event_type("build.started"), Some("build_started"));
    }

    #[test]
    fn test_map_build_completed() {
        assert_eq!(map_event_type("build.completed"), Some("build_completed"));
    }

    #[test]
    fn test_map_build_failed() {
        assert_eq!(map_event_type("build.failed"), Some("build_failed"));
    }

    #[test]
    fn test_map_unknown_returns_none() {
        // Unmapped events are silently skipped, not panicked over.
        assert_eq!(map_event_type("permission.created"), None);
        assert_eq!(map_event_type("group.member_added"), None);
        assert_eq!(map_event_type(""), None);
        assert_eq!(map_event_type("totally.bogus"), None);
    }

    #[test]
    fn test_map_covers_all_webhook_event_variants() {
        // This is a fence test: the WebhookEvent enum has 9 variants.
        // We must produce a mapping for each one. If a new variant is added,
        // update this list and the match arm above.
        let expected_outputs = [
            "artifact_uploaded",
            "artifact_deleted",
            "repository_created",
            "repository_deleted",
            "user_created",
            "user_deleted",
            "build_started",
            "build_completed",
            "build_failed",
        ];
        let event_bus_inputs = [
            "artifact.uploaded",
            "artifact.deleted",
            "repository.created",
            "repository.deleted",
            "user.created",
            "user.deleted",
            "build.started",
            "build.completed",
            "build.failed",
        ];
        for (input, expected) in event_bus_inputs.iter().zip(expected_outputs.iter()) {
            assert_eq!(map_event_type(input), Some(*expected), "input: {}", input);
        }
    }

    // -----------------------------------------------------------------------
    // build_event_payload
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_event_payload_shape() {
        let event = sample_event("artifact.created");
        let payload = build_event_payload(&event, "artifact_uploaded");
        let obj = payload.as_object().unwrap();

        assert_eq!(obj.len(), 5);
        assert_eq!(payload["event"], "artifact_uploaded");
        assert_eq!(payload["entity_id"], "550e8400-e29b-41d4-a716-446655440000");
        assert_eq!(payload["actor"], "alice");
        assert_eq!(payload["timestamp"], "2026-04-08T12:00:00Z");
        assert!(payload["payload"].is_null());
    }

    #[test]
    fn test_build_event_payload_uses_mapped_event_name() {
        // The payload's "event" field is the underscore (mapped) form, not
        // the dotted EventBus form. Consumers see snake_case identifiers.
        let event = sample_event("artifact.created");
        let payload = build_event_payload(&event, "artifact_uploaded");
        assert_eq!(payload["event"], "artifact_uploaded");
        assert_ne!(payload["event"], "artifact.created");
    }

    #[test]
    fn test_build_event_payload_no_actor() {
        let event = DomainEvent {
            event_type: "user.deleted".into(),
            entity_id: "u-7".into(),
            actor: None,
            timestamp: "2026-01-01T00:00:00Z".into(),
        };
        let payload = build_event_payload(&event, "user_deleted");
        assert!(payload["actor"].is_null());
    }

    #[test]
    fn test_build_event_payload_is_valid_json() {
        let event = sample_event("artifact.deleted");
        let payload = build_event_payload(&event, "artifact_deleted");
        let serialized = serde_json::to_string(&payload).unwrap();
        let reparsed: serde_json::Value = serde_json::from_str(&serialized).unwrap();
        assert_eq!(reparsed, payload);
    }

    #[test]
    fn test_build_event_payload_preserves_timestamp_format() {
        // The timestamp is passed through verbatim. Consumers parse RFC 3339.
        let event = DomainEvent {
            event_type: "build.failed".into(),
            entity_id: "build-99".into(),
            actor: Some("ci".into()),
            timestamp: "2026-04-27T16:30:00.123456789Z".into(),
        };
        let payload = build_event_payload(&event, "build_failed");
        assert_eq!(payload["timestamp"], "2026-04-27T16:30:00.123456789Z");
    }

    // -----------------------------------------------------------------------
    // Skipped event types: producer must not panic
    // -----------------------------------------------------------------------

    #[test]
    fn test_unmapped_event_returns_none_safely() {
        // A handful of permission/group events fire but have no webhook
        // counterpart. Make sure the mapper is total over a representative
        // sample we observe in production grep.
        let unmapped = [
            "permission.created",
            "permission.updated",
            "permission.deleted",
            "group.created",
            "group.updated",
            "group.deleted",
            "group.member_added",
            "group.member_removed",
            "service_account.created",
            "service_account.deleted",
            "quality_gate.created",
            "quality_gate.updated",
            "quality_gate.deleted",
            "quarantine.added",
            "scan.completed",
            "scan.vulnerability_found",
        ];
        for ev in unmapped {
            assert_eq!(map_event_type(ev), None, "{} should be unmapped", ev);
        }
    }
}
