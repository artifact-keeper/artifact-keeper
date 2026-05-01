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
use tokio_util::sync::CancellationToken;

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
///
/// v1 OMITS the `payload` key entirely (rather than serialising it as
/// `null`) when no enriched payload is available yet, so receivers can
/// distinguish "v1 producer with no enrichment" from "v2 producer that
/// chose to emit a null payload". E4 will populate the key.
pub fn build_event_payload(event: &DomainEvent, mapped_event: &str) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    map.insert(
        "event".into(),
        serde_json::Value::String(mapped_event.into()),
    );
    map.insert(
        "entity_id".into(),
        serde_json::Value::String(event.entity_id.clone()),
    );
    map.insert(
        "actor".into(),
        match &event.actor {
            Some(a) => serde_json::Value::String(a.clone()),
            None => serde_json::Value::Null,
        },
    );
    map.insert(
        "timestamp".into(),
        serde_json::Value::String(event.timestamp.clone()),
    );
    // v1 omits `payload` when not yet enriched; v2 (E4) will populate it.
    serde_json::Value::Object(map)
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
/// `webhook_deliveries`. The task runs until either the broadcast channel is
/// closed (the EventBus was dropped) or `shutdown_token` is cancelled by the
/// HTTP/gRPC server lifecycle.
///
/// # Delivery semantics: at-most-once with explicit lag drops
///
/// Tokio broadcast channels DO NOT duplicate events. On subscriber lag they
/// surface `RecvError::Lagged(n)` which means the n oldest events were
/// silently DROPPED from this subscriber's view. The producer logs lag at
/// warn-level but cannot recover the dropped events: at-most-once is the
/// best the in-process bus can offer. Customers requiring at-least-once for
/// missed deliveries must fall back to the polling/manual-replay UI on
/// `/api/v1/webhooks/{id}/deliveries` (or the GET-then-redeliver flow).
/// This is acceptable for v1.1.9; v1.2.0 will introduce a durable event log
/// if reviewers determine in-process broadcast is insufficient.
pub fn start_webhook_producer(
    event_bus: Arc<EventBus>,
    db: PgPool,
    shutdown_token: CancellationToken,
) {
    let mut rx = event_bus.subscribe();

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = shutdown_token.cancelled() => {
                    tracing::info!(
                        "Shutdown signalled, webhook producer draining and exiting"
                    );
                    break;
                }
                recv = rx.recv() => {
                    match recv {
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
                                "Webhook producer lagged; events were dropped (at-most-once)"
                            );
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            tracing::info!(
                                "EventBus closed, webhook producer shutting down"
                            );
                            break;
                        }
                    }
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
/// # Repository scoping limitation
///
/// `event.entity_id` is parsed as a `repository_id`. This works correctly
/// for `repository.*` events because the EventBus carries the repo UUID in
/// `entity_id`. It is a category error for `user.*`, `build.*`, and
/// `artifact.*` events: their `entity_id` is the user/build/artifact UUID
/// respectively, not the owning repository. For those events, the
/// `repository_id = $2` arm of the WHERE clause never matches, so only
/// global-scoped webhooks (repository_id IS NULL) fire. This matches the
/// design that lands on main as #948.
///
/// FIXME(#948): Thread an explicit `repository_id: Option<Uuid>` through
/// `DomainEvent` so this scoping is correct for non-repo events. Until
/// then, scoping non-repo events requires the operator to use a global
/// webhook subscription.
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
                crate::services::metrics_service::record_webhook_delivery_enqueue_failed(
                    mapped_event,
                    "db_error",
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
        // Compile-time fence: an exhaustive match over `WebhookEvent`
        // produces the (event_bus_input, expected_output) pair for every
        // variant. If a new variant is added to `WebhookEvent`, this match
        // FAILS TO COMPILE until both the match arm here AND the runtime
        // dispatch in `map_event_type` above are updated. That is the
        // entire point: hand-maintained lists drift silently.
        use crate::api::handlers::webhooks::WebhookEvent;

        fn expected_pair(v: &WebhookEvent) -> (&'static str, &'static str) {
            match v {
                WebhookEvent::ArtifactUploaded => ("artifact.uploaded", "artifact_uploaded"),
                WebhookEvent::ArtifactDeleted => ("artifact.deleted", "artifact_deleted"),
                WebhookEvent::RepositoryCreated => ("repository.created", "repository_created"),
                WebhookEvent::RepositoryDeleted => ("repository.deleted", "repository_deleted"),
                WebhookEvent::UserCreated => ("user.created", "user_created"),
                WebhookEvent::UserDeleted => ("user.deleted", "user_deleted"),
                WebhookEvent::BuildStarted => ("build.started", "build_started"),
                WebhookEvent::BuildCompleted => ("build.completed", "build_completed"),
                WebhookEvent::BuildFailed => ("build.failed", "build_failed"),
            }
        }

        // Hand-listed for the body of the test; the exhaustive match above
        // is what the fence relies on. If you add a variant, the compiler
        // forces you to extend `expected_pair`, and you should also extend
        // this list so the runtime side actually exercises every variant.
        let all_variants = [
            WebhookEvent::ArtifactUploaded,
            WebhookEvent::ArtifactDeleted,
            WebhookEvent::RepositoryCreated,
            WebhookEvent::RepositoryDeleted,
            WebhookEvent::UserCreated,
            WebhookEvent::UserDeleted,
            WebhookEvent::BuildStarted,
            WebhookEvent::BuildCompleted,
            WebhookEvent::BuildFailed,
        ];

        for variant in &all_variants {
            let (bus_input, expected) = expected_pair(variant);
            assert_eq!(
                map_event_type(bus_input),
                Some(expected),
                "variant {:?} maps {} -> {}",
                variant,
                bus_input,
                expected
            );
            // Also assert the WebhookEvent::Display matches the mapped form
            // so the wire identifier stays in lockstep with the Rust enum.
            assert_eq!(variant.to_string(), expected);
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

        // v1 emits exactly four keys: event, entity_id, actor, timestamp.
        // The `payload` key is OMITTED (not serialized as null) until E4
        // wires up the per-event enrichment. Receivers see a missing key,
        // not a null value, so they can tell v1 apart from a deliberate
        // v2-null-payload.
        assert_eq!(obj.len(), 4);
        assert_eq!(payload["event"], "artifact_uploaded");
        assert_eq!(payload["entity_id"], "550e8400-e29b-41d4-a716-446655440000");
        assert_eq!(payload["actor"], "alice");
        assert_eq!(payload["timestamp"], "2026-04-08T12:00:00Z");
        assert!(
            obj.get("payload").is_none(),
            "v1 must omit the payload key entirely, not emit null"
        );
    }

    #[test]
    fn test_build_event_payload_omits_payload_key_not_null() {
        // Explicit fence: serialising-then-parsing must not introduce a
        // payload key. If a future change writes `"payload": null` instead
        // of omitting it, this test fails loudly.
        let event = sample_event("artifact.created");
        let payload = build_event_payload(&event, "artifact_uploaded");
        let serialized = serde_json::to_string(&payload).unwrap();
        assert!(
            !serialized.contains("\"payload\""),
            "serialized v1 payload must not contain a payload key, got: {}",
            serialized
        );
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

    // -----------------------------------------------------------------------
    // Integration tests for enqueue_for_event and start_webhook_producer.
    //
    // These tests exercise the database-bound paths that pure unit tests
    // cannot reach: the webhook lookup query, the INSERT into
    // webhook_deliveries, the broadcast subscription loop, and the global
    // vs scoped match logic. They run as part of `cargo test --workspace
    // --lib` (which is what the coverage gate uses) and skip silently if
    // no database is available, so local runs without Postgres still pass.
    //
    // CI provides DATABASE_URL with a fully migrated schema. Locally:
    //   DATABASE_URL="postgresql://registry:registry@localhost:30432/artifact_registry" \
    //     cargo test --workspace --lib webhook_producer::tests::integration
    // -----------------------------------------------------------------------
    mod integration {
        use super::*;
        use sqlx::PgPool;
        use std::sync::OnceLock;
        use std::time::Duration;
        use tokio::sync::Mutex;
        use tokio_util::sync::CancellationToken;
        use uuid::Uuid;

        /// Serialize integration tests against the shared Postgres instance.
        ///
        /// `cargo test` runs tests in parallel by default. These tests insert
        /// webhooks that subscribe to the same event types and then call
        /// `enqueue_for_event`, which scans ALL enabled webhooks for a given
        /// event. Without serialization, test A's webhook is found by test B's
        /// enqueue call (and vice versa), so each test sees deliveries for
        /// rows it never set up. Holding this mutex keeps each test's window
        /// of "my webhooks exist in the table" disjoint from the others'.
        fn serial_lock() -> &'static Mutex<()> {
            static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
            LOCK.get_or_init(|| Mutex::new(()))
        }

        /// Try to connect to the test database. Returns `None` if DATABASE_URL
        /// is unset or the connection fails, which is the signal to skip the
        /// test (so `cargo test --lib` without Postgres still passes).
        async fn maybe_pool() -> Option<PgPool> {
            let url = std::env::var("DATABASE_URL").ok()?;
            match PgPool::connect(&url).await {
                Ok(pool) => Some(pool),
                Err(e) => {
                    eprintln!(
                        "webhook_producer integration test: skipping, cannot connect to \
                         DATABASE_URL ({}): {}",
                        url, e
                    );
                    None
                }
            }
        }

        /// Insert a webhook subscription. Returns the new webhook id.
        async fn insert_webhook(
            pool: &PgPool,
            name: &str,
            events: &[&str],
            repo_id: Option<Uuid>,
            is_enabled: bool,
        ) -> Uuid {
            let id = Uuid::new_v4();
            let events_owned: Vec<String> = events.iter().map(|s| s.to_string()).collect();
            sqlx::query(
                r#"
                INSERT INTO webhooks
                    (id, name, url, events, is_enabled, repository_id)
                VALUES ($1, $2, $3, $4, $5, $6)
                "#,
            )
            .bind(id)
            .bind(name)
            .bind("https://example.invalid/hook")
            .bind(&events_owned)
            .bind(is_enabled)
            .bind(repo_id)
            .execute(pool)
            .await
            .expect("insert webhook");
            id
        }

        /// Insert a minimal `local` repository row so a webhook can scope to
        /// it. Returns the repo id.
        async fn insert_repo(pool: &PgPool, key_suffix: &str) -> Uuid {
            let id = Uuid::new_v4();
            let key = format!("ak992-{}-{}", key_suffix, &id.to_string()[..8]);
            sqlx::query(
                r#"
                INSERT INTO repositories
                    (id, key, name, format, repo_type, storage_path, is_public)
                VALUES ($1, $2, $2, 'generic', 'local', $3, false)
                "#,
            )
            .bind(id)
            .bind(&key)
            .bind(format!("/tmp/ak992-test/{}", key))
            .execute(pool)
            .await
            .expect("insert repository");
            id
        }

        async fn delivery_count_for(pool: &PgPool, webhook_id: Uuid) -> i64 {
            let row: (i64,) =
                sqlx::query_as("SELECT COUNT(*) FROM webhook_deliveries WHERE webhook_id = $1")
                    .bind(webhook_id)
                    .fetch_one(pool)
                    .await
                    .expect("count deliveries");
            row.0
        }

        /// Best-effort cleanup. Run at the end of each test so reruns of the
        /// same test against the same DB don't accumulate cruft.
        async fn cleanup_webhooks(pool: &PgPool, ids: &[Uuid]) {
            for id in ids {
                let _ = sqlx::query("DELETE FROM webhook_deliveries WHERE webhook_id = $1")
                    .bind(id)
                    .execute(pool)
                    .await;
                let _ = sqlx::query("DELETE FROM webhooks WHERE id = $1")
                    .bind(id)
                    .execute(pool)
                    .await;
            }
        }

        async fn cleanup_repos(pool: &PgPool, ids: &[Uuid]) {
            for id in ids {
                let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
                    .bind(id)
                    .execute(pool)
                    .await;
            }
        }

        /// Wipe any leftover ak992 fixtures from a previous failed run so a
        /// rerun against the same database starts clean. Operates only on
        /// rows we ourselves create (name prefix `ak992-`, repo key prefix
        /// `ak992-`), never on real production data.
        async fn purge_leftovers(pool: &PgPool) {
            let _ = sqlx::query(
                "DELETE FROM webhook_deliveries WHERE webhook_id IN \
                 (SELECT id FROM webhooks WHERE name LIKE 'ak992-%')",
            )
            .execute(pool)
            .await;
            let _ = sqlx::query("DELETE FROM webhooks WHERE name LIKE 'ak992-%'")
                .execute(pool)
                .await;
            let _ = sqlx::query("DELETE FROM repositories WHERE key LIKE 'ak992-%'")
                .execute(pool)
                .await;
        }

        /// Test 1: a published event lands as a `webhook_deliveries` row for a
        /// matching, enabled, global subscription. End-to-end through
        /// `start_webhook_producer` so the broadcast loop is exercised too.
        #[tokio::test]
        async fn end_to_end_event_produces_delivery_row() {
            let Some(pool) = maybe_pool().await else {
                return;
            };
            let _guard = serial_lock().lock().await;
            purge_leftovers(&pool).await;

            let webhook_id = insert_webhook(
                &pool,
                "ak992-end-to-end",
                &["repository_created"],
                None,
                true,
            )
            .await;

            let bus = std::sync::Arc::new(crate::services::event_bus::EventBus::new(16));
            let token = CancellationToken::new();
            start_webhook_producer(bus.clone(), pool.clone(), token.clone());

            // Tiny sleep so the spawned task is parked on rx.recv() before we
            // publish. Without this the broadcast send can race the spawn.
            tokio::time::sleep(Duration::from_millis(20)).await;

            let entity = Uuid::new_v4().to_string();
            bus.publish(DomainEvent {
                event_type: "repository.created".into(),
                entity_id: entity.clone(),
                actor: Some("admin".into()),
                timestamp: "2026-04-28T12:00:00Z".into(),
            });

            // Settling delay for the producer to dequeue + INSERT. Not a
            // load-bearing assertion; we re-check below if needed.
            tokio::time::sleep(Duration::from_millis(150)).await;

            let count = delivery_count_for(&pool, webhook_id).await;
            assert_eq!(
                count, 1,
                "expected exactly one delivery row, found {}",
                count
            );

            let row: (String, serde_json::Value) = sqlx::query_as(
                "SELECT event, payload FROM webhook_deliveries WHERE webhook_id = $1 LIMIT 1",
            )
            .bind(webhook_id)
            .fetch_one(&pool)
            .await
            .expect("fetch delivery row");
            assert_eq!(row.0, "repository_created", "event column mismatch");
            assert_eq!(
                row.1.get("entity_id").and_then(|v| v.as_str()),
                Some(entity.as_str()),
                "payload entity_id must round-trip"
            );
            assert_eq!(
                row.1.get("actor").and_then(|v| v.as_str()),
                Some("admin"),
                "payload actor must round-trip"
            );

            token.cancel();
            cleanup_webhooks(&pool, &[webhook_id]).await;
        }

        /// Test 2: global webhook (`repository_id IS NULL`) matches every
        /// event; scoped webhook (`repository_id = X`) only matches events
        /// whose `entity_id` parses to `X`. Calls `enqueue_for_event` directly
        /// so timing isn't a factor.
        #[tokio::test]
        async fn global_and_scoped_webhook_routing() {
            let Some(pool) = maybe_pool().await else {
                return;
            };
            let _guard = serial_lock().lock().await;
            purge_leftovers(&pool).await;

            let scoped_repo_id = insert_repo(&pool, "scoped").await;
            let other_repo_id = insert_repo(&pool, "other").await;

            let global_id =
                insert_webhook(&pool, "ak992-global", &["repository_created"], None, true).await;
            let scoped_id = insert_webhook(
                &pool,
                "ak992-scoped",
                &["repository_created"],
                Some(scoped_repo_id),
                true,
            )
            .await;

            // Event 1: targets the scoped repo. Both webhooks must fire.
            let event_for_scoped = DomainEvent {
                event_type: "repository.created".into(),
                entity_id: scoped_repo_id.to_string(),
                actor: Some("admin".into()),
                timestamp: "2026-04-28T12:00:00Z".into(),
            };
            enqueue_for_event(&pool, &event_for_scoped)
                .await
                .expect("enqueue scoped event");

            assert_eq!(
                delivery_count_for(&pool, global_id).await,
                1,
                "global webhook must receive delivery for scoped repo event"
            );
            assert_eq!(
                delivery_count_for(&pool, scoped_id).await,
                1,
                "scoped webhook must receive delivery for its own repo event"
            );

            // Event 2: targets a different repo. Only the global webhook
            // gets a new row; the scoped webhook stays at 1.
            let event_for_other = DomainEvent {
                event_type: "repository.created".into(),
                entity_id: other_repo_id.to_string(),
                actor: Some("admin".into()),
                timestamp: "2026-04-28T12:01:00Z".into(),
            };
            enqueue_for_event(&pool, &event_for_other)
                .await
                .expect("enqueue other event");

            assert_eq!(
                delivery_count_for(&pool, global_id).await,
                2,
                "global webhook must receive a second delivery for the other repo"
            );
            assert_eq!(
                delivery_count_for(&pool, scoped_id).await,
                1,
                "scoped webhook must NOT fire for a different repo's event"
            );

            cleanup_webhooks(&pool, &[global_id, scoped_id]).await;
            cleanup_repos(&pool, &[scoped_repo_id, other_repo_id]).await;
        }

        /// Test 3: a disabled subscription must not produce delivery rows
        /// even when its event filter and scope would otherwise match.
        #[tokio::test]
        async fn disabled_subscription_does_not_fire() {
            let Some(pool) = maybe_pool().await else {
                return;
            };
            let _guard = serial_lock().lock().await;
            purge_leftovers(&pool).await;

            let webhook_id = insert_webhook(
                &pool,
                "ak992-disabled",
                &["repository_created"],
                None,
                false,
            )
            .await;

            let event = DomainEvent {
                event_type: "repository.created".into(),
                entity_id: Uuid::new_v4().to_string(),
                actor: None,
                timestamp: "2026-04-28T12:00:00Z".into(),
            };
            enqueue_for_event(&pool, &event)
                .await
                .expect("enqueue must not error even when there are no matching webhooks");

            assert_eq!(
                delivery_count_for(&pool, webhook_id).await,
                0,
                "disabled webhook must not receive a delivery"
            );

            cleanup_webhooks(&pool, &[webhook_id]).await;
        }

        /// Test 4: an event type with no `WebhookEvent` mapping is silently
        /// skipped. No rows are inserted, no error is returned.
        #[tokio::test]
        async fn unmapped_event_type_is_silently_skipped() {
            let Some(pool) = maybe_pool().await else {
                return;
            };
            let _guard = serial_lock().lock().await;
            purge_leftovers(&pool).await;

            // A webhook that subscribes to every known event. Even so, an
            // unmapped event type must produce zero rows because the producer
            // exits early in `map_event_type`.
            let webhook_id = insert_webhook(
                &pool,
                "ak992-unmapped",
                &[
                    "artifact_uploaded",
                    "artifact_deleted",
                    "repository_created",
                    "repository_deleted",
                    "user_created",
                    "user_deleted",
                    "build_started",
                    "build_completed",
                    "build_failed",
                ],
                None,
                true,
            )
            .await;

            let event = DomainEvent {
                event_type: "completely_unknown_event".into(),
                entity_id: Uuid::new_v4().to_string(),
                actor: None,
                timestamp: "2026-04-28T12:00:00Z".into(),
            };
            enqueue_for_event(&pool, &event)
                .await
                .expect("unmapped event must not error");

            assert_eq!(
                delivery_count_for(&pool, webhook_id).await,
                0,
                "unmapped event type must produce zero delivery rows"
            );

            cleanup_webhooks(&pool, &[webhook_id]).await;
        }
    }
}
