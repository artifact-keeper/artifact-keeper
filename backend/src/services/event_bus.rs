use serde::Serialize;
use tokio::sync::broadcast;
use uuid::Uuid;

/// A domain event published when entities change.
#[derive(Debug, Clone, Serialize)]
pub struct DomainEvent {
    /// Event type, e.g. "user.created", "repository.deleted"
    #[serde(rename = "type")]
    pub event_type: String,
    /// UUID or key of the affected entity
    pub entity_id: String,
    /// The owning repository, if this event is repo-scoped. Set explicitly
    /// by the publisher (NOT parsed from `entity_id`) so repo-scoped
    /// webhook and notification subscriptions can match non-repo events
    /// (`user.*`, `group.*`, `quality_gate.*`, etc.) whose `entity_id` is
    /// the affected entity's UUID rather than the owning repo's UUID.
    /// See #948.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repository_id: Option<Uuid>,
    /// Username of the actor who triggered the change
    pub actor: Option<String>,
    /// ISO 8601 timestamp
    pub timestamp: String,
}

impl DomainEvent {
    /// Create a non-repo-scoped domain event timestamped to now.
    /// Use [`DomainEvent::now_for_repo`] for events owned by a specific
    /// repository.
    pub fn now(
        event_type: impl Into<String>,
        entity_id: impl Into<String>,
        actor: Option<String>,
    ) -> Self {
        Self::now_with_repo(event_type, entity_id, None, actor)
    }

    /// Create a repo-scoped domain event timestamped to now.
    pub fn now_for_repo(
        event_type: impl Into<String>,
        entity_id: impl Into<String>,
        repository_id: Uuid,
        actor: Option<String>,
    ) -> Self {
        Self::now_with_repo(event_type, entity_id, Some(repository_id), actor)
    }

    fn now_with_repo(
        event_type: impl Into<String>,
        entity_id: impl Into<String>,
        repository_id: Option<Uuid>,
        actor: Option<String>,
    ) -> Self {
        Self {
            event_type: event_type.into(),
            entity_id: entity_id.into(),
            repository_id,
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
    capacity: usize,
}

/// How [`EventBus::publish_paced`] waits for subscribers (#6469).
#[derive(Debug, Clone, Copy)]
pub struct Pacing {
    /// Publish only while fewer than this many events are still queued for
    /// the slowest subscriber.
    pub high_water: usize,
    /// The most a call waits in total. A subscriber that has stopped reading
    /// (an idle SSE client) keeps the queue full; past this budget the rest
    /// is published unpaced, as [`EventBus::publish`] would.
    pub max_wait: std::time::Duration,
    /// Pause between checks while the queue is at `high_water`.
    pub poll: std::time::Duration,
}

impl Pacing {
    /// A quarter of the buffer, at most 2 s of waiting per call.
    pub fn for_capacity(capacity: usize) -> Self {
        Self {
            high_water: (capacity / 4).max(1),
            max_wait: std::time::Duration::from_secs(2),
            poll: std::time::Duration::from_millis(5),
        }
    }
}

impl EventBus {
    pub fn new(capacity: usize) -> Self {
        let (tx, _) = broadcast::channel(capacity);
        Self { tx, capacity }
    }

    /// The broadcast buffer size the bus was built with.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Wait (at most `pacing.max_wait`) until the slowest subscriber has
    /// fewer than `pacing.high_water` events queued, so a burst published
    /// right after fits in the buffer (#6469: a sweep page waits here before
    /// it takes its locks, then publishes without waiting). Returns the time
    /// spent waiting.
    pub async fn wait_for_room(&self, pacing: Pacing) -> std::time::Duration {
        let started = std::time::Instant::now();
        while started.elapsed() < pacing.max_wait && self.tx.len() >= pacing.high_water {
            tokio::time::sleep(pacing.poll).await;
        }
        started.elapsed()
    }

    /// Publish a burst without outrunning the subscribers (#6469).
    ///
    /// [`EventBus::publish`] never waits, so a burst larger than the buffer
    /// makes every subscriber that has not caught up (webhook producer, email
    /// dispatcher, search indexer) drop the oldest events with `Lagged`,
    /// including unrelated events published at the same time. This publishes
    /// one event at a time and, while the slowest subscriber still has
    /// `pacing.high_water` events queued, waits for it to drain, so the
    /// buffer keeps room for everyone else. Returns the time spent waiting.
    pub async fn publish_paced(
        &self,
        events: impl IntoIterator<Item = DomainEvent>,
        pacing: Pacing,
    ) -> std::time::Duration {
        let started = std::time::Instant::now();
        let mut waited = std::time::Duration::ZERO;
        for (i, event) in events.into_iter().enumerate() {
            while waited < pacing.max_wait && self.tx.len() >= pacing.high_water {
                tokio::time::sleep(pacing.poll).await;
                waited = started.elapsed();
            }
            self.publish(event);
            if i % 32 == 31 {
                // Give the subscriber tasks a turn even when the queue is
                // short, so a burst does not monopolise this worker thread.
                tokio::task::yield_now().await;
            }
        }
        waited
    }

    /// Publish a domain event. If there are no subscribers the event is dropped silently.
    pub fn publish(&self, event: DomainEvent) {
        let _ = self.tx.send(event);
    }

    /// Subscribe to domain events.
    pub fn subscribe(&self) -> broadcast::Receiver<DomainEvent> {
        self.tx.subscribe()
    }

    /// Convenience: create a timestamped non-repo-scoped domain event and
    /// publish it in one call. Use [`EventBus::emit_for_repo`] for events
    /// owned by a specific repository so repo-scoped subscriptions match.
    pub fn emit(&self, event_type: &str, entity_id: impl ToString, actor: Option<String>) {
        self.publish(DomainEvent::now(event_type, entity_id.to_string(), actor));
    }

    /// Like [`EventBus::emit`] but threads an explicit `repository_id` into
    /// the published event. Use this when the affected entity is NOT the
    /// repository itself (e.g., a `user.created` triggered from a
    /// repo-scoped admin action). For `repository.*` events where the
    /// entity_id and repository_id coincide, prefer
    /// [`EventBus::emit_repository_event`] which takes the UUID once.
    /// See #948.
    pub fn emit_for_repo(
        &self,
        event_type: &str,
        entity_id: impl ToString,
        repository_id: Uuid,
        actor: Option<String>,
    ) {
        self.publish(DomainEvent::now_for_repo(
            event_type,
            entity_id.to_string(),
            repository_id,
            actor,
        ));
    }

    /// Publish `artifact.uploaded` for an `artifacts` row the caller has just
    /// written and whose id it already holds (#3939).
    ///
    /// For the write paths that copy or create an artifact row WITHOUT a
    /// catalog registration to hang the event off: promotion, approval
    /// execution, Git LFS and the chunked-upload completion. Hosted format
    /// publishes go through `package_service::register_published_package`
    /// instead, which emits the same event; calling both would double-deliver.
    /// The payload matches what `ArtifactService::finalize_upload` emits: the
    /// artifact id as the entity and the uploader as the actor.
    pub fn emit_artifact_uploaded(
        &self,
        artifact_id: Uuid,
        repository_id: Uuid,
        uploaded_by: Option<Uuid>,
    ) {
        self.emit_for_repo(
            "artifact.uploaded",
            artifact_id,
            repository_id,
            uploaded_by.map(|id| id.to_string()),
        );
    }

    /// Convenience for `repository.*` events where the affected entity IS
    /// the repository. Sets both `entity_id` and `repository_id` to
    /// `repo_id`, avoiding the visually-duplicated argument at the call
    /// site that `emit_for_repo(.., repo.id, repo.id, ..)` produces.
    /// See #948.
    pub fn emit_repository_event(&self, event_type: &str, repo_id: Uuid, actor: Option<String>) {
        self.emit_for_repo(event_type, repo_id, repo_id, actor);
    }
}

#[cfg(ak_test_shard = "services-1")]
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
            repository_id: None,
            actor: Some("admin".into()),
            timestamp: "2026-01-01T00:00:00Z".into(),
        });

        let event = rx.recv().await.unwrap();
        assert_eq!(event.event_type, "user.created");
        assert_eq!(event.entity_id, "abc-123");
    }

    /// #3939: the row-holding producer carries the artifact id, the owning
    /// repository and the uploader, exactly as `finalize_upload`'s event does.
    #[tokio::test]
    async fn emit_artifact_uploaded_carries_row_repo_and_uploader() {
        let bus = EventBus::new(16);
        let mut rx = bus.subscribe();
        let (artifact, repo, user) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());

        bus.emit_artifact_uploaded(artifact, repo, Some(user));
        bus.emit_artifact_uploaded(artifact, repo, None);

        let first = rx.recv().await.unwrap();
        assert_eq!(first.event_type, "artifact.uploaded");
        assert_eq!(first.entity_id, artifact.to_string());
        assert_eq!(first.repository_id, Some(repo));
        assert_eq!(first.actor, Some(user.to_string()));
        let second = rx.recv().await.unwrap();
        assert_eq!(second.actor, None);
    }

    #[tokio::test]
    async fn no_subscribers_does_not_panic() {
        let bus = EventBus::new(16);
        // Publishing with no subscribers should not panic
        bus.publish(DomainEvent {
            event_type: "test".into(),
            entity_id: "x".into(),
            repository_id: None,
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
                repository_id: None,
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
            repository_id: None,
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
            repository_id: None,
            actor: None,
            timestamp: "2026-01-01T00:00:00Z".into(),
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains(r#""type":"user.deleted""#));
        assert!(!json.contains("event_type"));
    }

    #[test]
    fn domain_event_now_for_repo_sets_repository_id() {
        let repo_id = Uuid::new_v4();
        let event = DomainEvent::now_for_repo("user.created", "u-7", repo_id, None);
        assert_eq!(event.repository_id, Some(repo_id));
        assert_eq!(event.event_type, "user.created");
    }

    #[test]
    fn domain_event_now_leaves_repository_id_none() {
        let event = DomainEvent::now("group.deleted", "g-7", None);
        assert!(event.repository_id.is_none());
    }

    #[test]
    fn domain_event_repository_id_omitted_when_none() {
        // The serde `skip_serializing_if = "Option::is_none"` keeps the
        // payload backward-compatible for non-repo events.
        let event = DomainEvent::now("group.deleted", "g-7", None);
        let json = serde_json::to_string(&event).unwrap();
        assert!(!json.contains("repository_id"));
    }

    #[test]
    fn domain_event_repository_id_present_when_set() {
        let repo_id = Uuid::new_v4();
        let event = DomainEvent::now_for_repo("repository.created", "r-1", repo_id, None);
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("repository_id"));
        assert!(json.contains(&repo_id.to_string()));
    }

    #[tokio::test]
    async fn emit_for_repo_threads_repository_id() {
        let bus = EventBus::new(16);
        let mut rx = bus.subscribe();
        let repo_id = Uuid::new_v4();

        bus.emit_for_repo(
            "user.created",
            "u-1".to_string(),
            repo_id,
            Some("alice".into()),
        );

        let event = rx.recv().await.unwrap();
        assert_eq!(event.repository_id, Some(repo_id));
        assert_eq!(event.entity_id, "u-1");
    }

    #[tokio::test]
    async fn emit_repository_event_uses_repo_id_for_both_fields() {
        // For `repository.*` events the affected entity IS the repository,
        // so entity_id and repository_id coincide. The shortcut takes the
        // UUID once.
        let bus = EventBus::new(16);
        let mut rx = bus.subscribe();
        let repo_id = Uuid::new_v4();

        bus.emit_repository_event("repository.created", repo_id, Some("alice".into()));

        let event = rx.recv().await.unwrap();
        assert_eq!(event.event_type, "repository.created");
        assert_eq!(event.entity_id, repo_id.to_string());
        assert_eq!(event.repository_id, Some(repo_id));
    }

    /// #6469: a paced burst larger than the buffer reaches a subscriber that
    /// keeps reading without a single `Lagged`, while an unpaced one drops.
    #[tokio::test]
    async fn paced_burst_does_not_lag_a_reading_subscriber_6469() {
        let bus = std::sync::Arc::new(EventBus::new(16));
        let mut rx = bus.subscribe();
        let reader = tokio::spawn(async move {
            let (mut got, mut lagged) = (0usize, 0u64);
            loop {
                match rx.recv().await {
                    Ok(_) => got += 1,
                    Err(broadcast::error::RecvError::Lagged(n)) => lagged += n,
                    Err(broadcast::error::RecvError::Closed) => break,
                }
                if got + lagged as usize >= 200 {
                    break;
                }
            }
            (got, lagged)
        });
        let events = (0..200).map(|i| DomainEvent::now("artifact.deleted", i.to_string(), None));
        bus.publish_paced(events, Pacing::for_capacity(bus.capacity()))
            .await;
        let (got, lagged) = tokio::time::timeout(std::time::Duration::from_secs(10), reader)
            .await
            .expect("reader finishes")
            .unwrap();
        assert_eq!(lagged, 0, "no event dropped");
        assert_eq!(got, 200);
    }

    /// #6469: a subscriber that never reads cannot wedge a paced publisher;
    /// it waits at most `max_wait` and then publishes the rest.
    #[tokio::test]
    async fn paced_burst_gives_up_waiting_on_a_stalled_subscriber_6469() {
        let bus = EventBus::new(8);
        let _stalled = bus.subscribe();
        let pacing = Pacing {
            high_water: 2,
            max_wait: std::time::Duration::from_millis(50),
            poll: std::time::Duration::from_millis(1),
        };
        let started = std::time::Instant::now();
        let events = (0..100).map(|i| DomainEvent::now("artifact.deleted", i.to_string(), None));
        let waited = bus.publish_paced(events, pacing).await;
        assert!(waited >= std::time::Duration::from_millis(50));
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
    }

    /// #6469: `wait_for_room` returns once a reading subscriber has drained
    /// below the high-water mark, and gives up after `max_wait` on a stalled
    /// one.
    #[tokio::test]
    async fn wait_for_room_waits_for_a_drain_and_is_capped_6469() {
        let bus = std::sync::Arc::new(EventBus::new(16));
        let mut rx = bus.subscribe();
        for i in 0..12 {
            bus.publish(DomainEvent::now("artifact.deleted", i.to_string(), None));
        }
        let pacing = Pacing {
            high_water: 4,
            max_wait: std::time::Duration::from_secs(5),
            poll: std::time::Duration::from_millis(1),
        };
        let drain = tokio::spawn(async move {
            for _ in 0..12 {
                rx.recv().await.unwrap();
            }
            rx
        });
        let waited = bus.wait_for_room(pacing).await;
        assert!(bus.tx.len() < 4);
        assert!(waited < std::time::Duration::from_secs(5));
        let _rx = drain.await.unwrap();

        let stalled = EventBus::new(8);
        let _never = stalled.subscribe();
        for i in 0..8 {
            stalled.publish(DomainEvent::now("artifact.deleted", i.to_string(), None));
        }
        let capped = Pacing {
            high_water: 2,
            max_wait: std::time::Duration::from_millis(50),
            poll: std::time::Duration::from_millis(1),
        };
        let waited = stalled.wait_for_room(capped).await;
        assert!(waited >= std::time::Duration::from_millis(50));
        assert!(waited < std::time::Duration::from_secs(5));
    }
}
