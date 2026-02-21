use serde::Serialize;
use tokio::sync::broadcast;

/// A domain event published when entities change.
#[derive(Debug, Clone, Serialize)]
pub struct DomainEvent {
    /// Event type, e.g. "user.created", "repository.deleted"
    #[serde(rename = "type")]
    pub event_type: String,
    /// UUID or key of the affected entity
    pub entity_id: String,
    /// Username of the actor who triggered the change
    pub actor: Option<String>,
    /// ISO 8601 timestamp
    pub timestamp: String,
}

impl DomainEvent {
    /// Create a domain event timestamped to now.
    pub fn now(
        event_type: impl Into<String>,
        entity_id: impl Into<String>,
        actor: Option<String>,
    ) -> Self {
        Self {
            event_type: event_type.into(),
            entity_id: entity_id.into(),
            actor,
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }
}

/// Broadcast-based event bus for domain events.
///
/// Subscribers receive events via `tokio::sync::broadcast`. If a subscriber
/// falls behind, it receives `RecvError::Lagged` and can request a full refresh.
pub struct EventBus {
    tx: broadcast::Sender<DomainEvent>,
}

impl EventBus {
    pub fn new(capacity: usize) -> Self {
        let (tx, _) = broadcast::channel(capacity);
        Self { tx }
    }

    /// Publish a domain event. If there are no subscribers the event is dropped silently.
    pub fn publish(&self, event: DomainEvent) {
        let _ = self.tx.send(event);
    }

    /// Subscribe to domain events.
    pub fn subscribe(&self) -> broadcast::Receiver<DomainEvent> {
        self.tx.subscribe()
    }

    /// Convenience: create a timestamped domain event and publish it in one call.
    pub fn emit(&self, event_type: &str, entity_id: impl ToString, actor: Option<String>) {
        self.publish(DomainEvent::now(event_type, entity_id.to_string(), actor));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn publish_and_receive() {
        let bus = EventBus::new(16);
        let mut rx = bus.subscribe();

        bus.publish(DomainEvent {
            event_type: "user.created".into(),
            entity_id: "abc-123".into(),
            actor: Some("admin".into()),
            timestamp: "2026-01-01T00:00:00Z".into(),
        });

        let event = rx.recv().await.unwrap();
        assert_eq!(event.event_type, "user.created");
        assert_eq!(event.entity_id, "abc-123");
    }

    #[tokio::test]
    async fn no_subscribers_does_not_panic() {
        let bus = EventBus::new(16);
        // Publishing with no subscribers should not panic
        bus.publish(DomainEvent {
            event_type: "test".into(),
            entity_id: "x".into(),
            actor: None,
            timestamp: "2026-01-01T00:00:00Z".into(),
        });
    }

    #[tokio::test]
    async fn lagged_subscriber() {
        let bus = EventBus::new(2); // tiny buffer
        let mut rx = bus.subscribe();

        // Overflow the buffer
        for i in 0..5 {
            bus.publish(DomainEvent {
                event_type: format!("event.{i}"),
                entity_id: i.to_string(),
                actor: None,
                timestamp: "2026-01-01T00:00:00Z".into(),
            });
        }

        // First recv should be Lagged
        match rx.recv().await {
            Err(broadcast::error::RecvError::Lagged(_)) => {} // expected
            other => panic!("Expected Lagged, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn multiple_subscribers_receive_same_event() {
        let bus = EventBus::new(16);
        let mut rx1 = bus.subscribe();
        let mut rx2 = bus.subscribe();

        bus.publish(DomainEvent {
            event_type: "repo.created".into(),
            entity_id: "repo-1".into(),
            actor: Some("alice".into()),
            timestamp: "2026-01-01T00:00:00Z".into(),
        });

        let e1 = rx1.recv().await.unwrap();
        let e2 = rx2.recv().await.unwrap();
        assert_eq!(e1.event_type, e2.event_type);
        assert_eq!(e1.entity_id, e2.entity_id);
    }

    #[test]
    fn domain_event_now_sets_fields_and_timestamp() {
        let event = DomainEvent::now("repo.deleted", "repo-42", Some("alice".into()));
        assert_eq!(event.event_type, "repo.deleted");
        assert_eq!(event.entity_id, "repo-42");
        assert_eq!(event.actor, Some("alice".into()));
        // Timestamp should be a valid RFC 3339 string
        chrono::DateTime::parse_from_rfc3339(&event.timestamp)
            .expect("timestamp should be valid RFC 3339");
    }

    #[test]
    fn domain_event_now_with_no_actor() {
        let event = DomainEvent::now("user.updated", "u-7", None);
        assert_eq!(event.event_type, "user.updated");
        assert_eq!(event.entity_id, "u-7");
        assert_eq!(event.actor, None);
    }

    #[tokio::test]
    async fn emit_creates_and_publishes_event() {
        let bus = EventBus::new(16);
        let mut rx = bus.subscribe();

        bus.emit("permission.created", "p-99", Some("bob".into()));

        let event = rx.recv().await.unwrap();
        assert_eq!(event.event_type, "permission.created");
        assert_eq!(event.entity_id, "p-99");
        assert_eq!(event.actor, Some("bob".into()));
        chrono::DateTime::parse_from_rfc3339(&event.timestamp)
            .expect("timestamp should be valid RFC 3339");
    }

    #[tokio::test]
    async fn emit_with_uuid_entity_id() {
        let bus = EventBus::new(16);
        let mut rx = bus.subscribe();
        let id = uuid::Uuid::new_v4();

        bus.emit("group.deleted", id, None);

        let event = rx.recv().await.unwrap();
        assert_eq!(event.entity_id, id.to_string());
        assert_eq!(event.actor, None);
    }

    #[tokio::test]
    async fn emit_no_subscribers_does_not_panic() {
        let bus = EventBus::new(16);
        bus.emit("test.event", "x", None);
    }

    #[tokio::test]
    async fn domain_event_serializes_type_field() {
        let event = DomainEvent {
            event_type: "user.deleted".into(),
            entity_id: "u-42".into(),
            actor: None,
            timestamp: "2026-01-01T00:00:00Z".into(),
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains(r#""type":"user.deleted""#));
        assert!(!json.contains("event_type"));
    }
}
