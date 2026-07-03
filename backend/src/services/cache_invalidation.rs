//! Cross-replica cache-invalidation fanout over Postgres `LISTEN`/`NOTIFY`.
//!
//! Several authorization-sensitive caches are process-local:
//!
//! - the API-token validation cache (`auth_service`, 5-minute TTL),
//! - the repository-metadata cache (`api::RepoCache`, 60-second TTL),
//! - the fine-grained permission cache (`permission_service`, 30-second TTL).
//!
//! In multi-replica deployments a security-relevant write handled by replica A
//! (token revocation, user deactivation, repo public→private flip, permission
//! or group-membership change) is invisible to replicas B..N until their local
//! TTL expires, leaving a 30–300 s stale-authorization window.
//!
//! This module closes that window: database triggers (migration 141) call
//! `pg_notify` on the [`CACHE_INVALIDATION_CHANNEL`] whenever one of those
//! writes commits, and every backend process runs a listener task that maps
//! each received [`InvalidationEvent`] onto the existing process-local
//! invalidation helpers.
//!
//! Postgres notifications are delivered only to sessions that are currently
//! listening, so this is a best-effort latency optimisation layered on top of
//! the existing TTLs, not a consistency proof: on listener startup and on
//! every reconnect the affected caches are conservatively flushed because
//! notifications may have been missed while not listening. If a replica stays
//! disconnected, the TTL remains the final safety bound.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::api::RepoCache;
use crate::services::permission_service::PermissionService;

/// Postgres notification channel the triggers publish on and the listener
/// subscribes to. Versioned so a future incompatible payload schema can move
/// to a `_v2` channel without confusing old replicas during a rolling deploy.
pub const CACHE_INVALIDATION_CHANNEL: &str = "ak_cache_invalidation_v1";

/// Payload schema version expected inside each notification envelope.
pub const CACHE_INVALIDATION_VERSION: u8 = 1;

/// A single cache-invalidation event, JSON-encoded by the migration-141
/// trigger functions as `{"v":1,"kind":"<snake_case_kind>",...fields}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum InvalidationEvent {
    /// `api_tokens.revoked_at` transitioned NULL → non-NULL.
    ApiTokenRevoked { token_id: Uuid },
    /// The user was deactivated (`users.is_active` → false) or hard-deleted;
    /// every cached API-token validation for them must be rejected.
    UserApiTokensInvalidated { user_id: Uuid },
    /// An auth-relevant column of `repositories` changed (`key`, `format`,
    /// `repo_type`, `upstream_url`, `storage_backend`, `storage_path`,
    /// `is_public`). `old_key == new_key` unless the repo was renamed.
    RepositoryChanged { old_key: String, new_key: String },
    /// The repository row was deleted.
    RepositoryDeleted { key: String },
    /// Permission CRUD, group-membership change, or group delete. Coarse by
    /// design: the whole permission cache is flushed (30 s TTL, so the
    /// refill burst is bounded); fine-grained keys can come later if needed.
    PermissionsChanged,
}

/// Versioned wrapper matching the exact JSON the triggers emit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvalidationEnvelope {
    pub v: u8,
    #[serde(flatten)]
    pub event: InvalidationEvent,
}

/// Handles to the per-process caches the listener evicts from. The API-token
/// caches are process-global statics in `auth_service` and need no handle.
#[derive(Clone)]
pub struct CacheInvalidationHandles {
    pub repo_cache: RepoCache,
    pub permission_service: Arc<PermissionService>,
}

/// Parse one notification payload into an [`InvalidationEvent`].
///
/// Returns `Err` for malformed JSON, an unknown `kind`, or a version other
/// than [`CACHE_INVALIDATION_VERSION`]; the caller must treat any `Err` as a
/// signal to conservatively flush all affected caches rather than silently
/// ignoring a payload it cannot understand.
pub fn parse_invalidation_payload(_payload: &str) -> Result<InvalidationEvent, String> {
    // TDD skeleton: implemented together with the listener.
    Err("cache-invalidation payload parsing not implemented yet".to_string())
}

/// Apply one event to this process's caches, idempotently.
pub async fn apply_invalidation_event(
    _handles: &CacheInvalidationHandles,
    _event: &InvalidationEvent,
) {
    // TDD skeleton: implemented together with the listener.
}

/// Conservatively flush every cache family this module manages. Used on
/// listener startup, on reconnect, and on any payload that fails to parse.
pub async fn conservative_flush_all(_handles: &CacheInvalidationHandles) {
    // TDD skeleton: implemented together with the listener.
}

/// Handle one raw notification payload: apply it if it parses, otherwise
/// log and conservatively flush.
pub async fn handle_notification_payload(_handles: &CacheInvalidationHandles, _payload: &str) {
    // TDD skeleton: implemented together with the listener.
}

/// Connect a dedicated [`sqlx::postgres::PgListener`], `LISTEN` on
/// [`CACHE_INVALIDATION_CHANNEL`], conservatively flush the local caches
/// (notifications may have been missed before this point), then spawn the
/// receive loop and return its handle.
///
/// The receive loop reconnects with bounded exponential backoff and flushes
/// the local caches after every reconnect; the process keeps serving requests
/// (degraded to TTL-bound staleness) while the listener is down. The task
/// exits when `shutdown` is cancelled.
///
/// When the initial connection cannot be established the function still
/// returns `Ok`: the spawned task keeps retrying in the background so a
/// temporarily unreachable database at boot does not abort startup.
pub async fn start_cache_invalidation_listener(
    _pool: PgPool,
    _handles: CacheInvalidationHandles,
    _shutdown: CancellationToken,
) -> JoinHandle<()> {
    // TDD skeleton: implemented together with the migration-141 triggers.
    tokio::spawn(async {})
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::time::Instant;

    use tokio::sync::RwLock;

    use super::*;
    use crate::api::CachedRepo;
    use crate::services::auth_service;

    /// The permission service needs a pool at construction time but these
    /// tests never touch the database: `connect_lazy` defers any real
    /// connection until first use, which never happens here.
    fn lazy_permission_service() -> Arc<PermissionService> {
        let pool = PgPool::connect_lazy("postgresql://unused:unused@127.0.0.1:1/unused")
            .expect("lazy pool construction must not fail");
        Arc::new(PermissionService::new(pool))
    }

    fn test_handles() -> CacheInvalidationHandles {
        CacheInvalidationHandles {
            repo_cache: Arc::new(RwLock::new(HashMap::new())),
            permission_service: lazy_permission_service(),
        }
    }

    fn cached_repo(key: &str, is_public: bool) -> CachedRepo {
        CachedRepo {
            id: Uuid::new_v4(),
            format: "generic".to_string(),
            repo_type: "local".to_string(),
            upstream_url: None,
            storage_path: format!("/data/{key}"),
            storage_backend: "filesystem".to_string(),
            is_public,
            index_upstream_url: None,
        }
    }

    async fn warm_repo_cache(handles: &CacheInvalidationHandles, key: &str) {
        handles
            .repo_cache
            .write()
            .await
            .insert(key.to_string(), (cached_repo(key, true), Instant::now()));
    }

    async fn repo_cache_contains(handles: &CacheInvalidationHandles, key: &str) -> bool {
        handles.repo_cache.read().await.contains_key(key)
    }

    // -- payload contract ---------------------------------------------------

    /// Round-trip every known variant through the envelope JSON the triggers
    /// emit. The serialized form is also asserted structurally so the SQL
    /// trigger payloads (written by hand in migration 141) and this parser
    /// cannot silently drift apart.
    #[test]
    fn parse_round_trips_every_known_variant() {
        let token_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let events = vec![
            InvalidationEvent::ApiTokenRevoked { token_id },
            InvalidationEvent::UserApiTokensInvalidated { user_id },
            InvalidationEvent::RepositoryChanged {
                old_key: "repo-a".to_string(),
                new_key: "repo-b".to_string(),
            },
            InvalidationEvent::RepositoryDeleted {
                key: "repo-a".to_string(),
            },
            InvalidationEvent::PermissionsChanged,
        ];
        for event in events {
            let payload = serde_json::to_string(&InvalidationEnvelope {
                v: CACHE_INVALIDATION_VERSION,
                event: event.clone(),
            })
            .expect("envelope must serialize");
            let parsed = parse_invalidation_payload(&payload)
                .unwrap_or_else(|e| panic!("payload {payload} must parse, got: {e}"));
            assert_eq!(parsed, event, "round-trip mismatch for {payload}");
        }
    }

    #[test]
    fn parse_matches_the_exact_trigger_payload_shape() {
        let token_id = Uuid::new_v4();
        let payload = format!(r#"{{"v":1,"kind":"api_token_revoked","token_id":"{token_id}"}}"#);
        assert_eq!(
            parse_invalidation_payload(&payload),
            Ok(InvalidationEvent::ApiTokenRevoked { token_id })
        );
        assert_eq!(
            parse_invalidation_payload(r#"{"v":1,"kind":"permissions_changed"}"#),
            Ok(InvalidationEvent::PermissionsChanged)
        );
    }

    #[test]
    fn parse_rejects_malformed_unknown_and_wrong_version_payloads() {
        for bad in [
            "not json at all",
            "{}",
            r#"{"v":1}"#,
            r#"{"v":1,"kind":"totally_unknown_kind"}"#,
            r#"{"kind":"permissions_changed"}"#,
            r#"{"v":2,"kind":"permissions_changed"}"#,
            r#"{"v":1,"kind":"api_token_revoked"}"#,
        ] {
            assert!(
                parse_invalidation_payload(bad).is_err(),
                "payload must be rejected: {bad}"
            );
        }
    }

    // -- apply behavior -----------------------------------------------------

    #[tokio::test]
    async fn applying_repository_changed_evicts_old_and_new_keys_only() {
        let handles = test_handles();
        warm_repo_cache(&handles, "repo-old").await;
        warm_repo_cache(&handles, "repo-new").await;
        warm_repo_cache(&handles, "repo-unrelated").await;

        apply_invalidation_event(
            &handles,
            &InvalidationEvent::RepositoryChanged {
                old_key: "repo-old".to_string(),
                new_key: "repo-new".to_string(),
            },
        )
        .await;

        assert!(!repo_cache_contains(&handles, "repo-old").await);
        assert!(!repo_cache_contains(&handles, "repo-new").await);
        assert!(
            repo_cache_contains(&handles, "repo-unrelated").await,
            "unrelated cache entries must survive a targeted eviction"
        );
    }

    #[tokio::test]
    async fn applying_repository_deleted_evicts_the_key() {
        let handles = test_handles();
        warm_repo_cache(&handles, "repo-doomed").await;

        apply_invalidation_event(
            &handles,
            &InvalidationEvent::RepositoryDeleted {
                key: "repo-doomed".to_string(),
            },
        )
        .await;

        assert!(!repo_cache_contains(&handles, "repo-doomed").await);
    }

    #[tokio::test]
    async fn applying_api_token_revoked_marks_the_token_in_the_global_set() {
        let handles = test_handles();
        let token_id = Uuid::new_v4();
        assert!(!auth_service::is_api_token_revoked_in_cache(token_id));

        apply_invalidation_event(&handles, &InvalidationEvent::ApiTokenRevoked { token_id }).await;

        assert!(
            auth_service::is_api_token_revoked_in_cache(token_id),
            "the local revoked-token set must reject cache hits for this token"
        );
    }

    #[tokio::test]
    async fn applying_user_api_tokens_invalidated_stamps_the_global_watermark() {
        let handles = test_handles();
        let user_id = Uuid::new_v4();
        let cached_before_event = Instant::now();
        assert!(!auth_service::is_user_api_tokens_invalidated_after(
            user_id,
            cached_before_event
        ));

        apply_invalidation_event(
            &handles,
            &InvalidationEvent::UserApiTokensInvalidated { user_id },
        )
        .await;

        assert!(
            auth_service::is_user_api_tokens_invalidated_after(user_id, cached_before_event),
            "cache entries older than the event must be rejected on hit"
        );
    }

    // -- unparseable payloads must fail closed -------------------------------

    #[tokio::test]
    async fn malformed_payload_triggers_a_conservative_flush() {
        let handles = test_handles();
        warm_repo_cache(&handles, "repo-flush-on-garbage").await;

        handle_notification_payload(&handles, "certainly { not json").await;

        assert!(
            !repo_cache_contains(&handles, "repo-flush-on-garbage").await,
            "an unparseable payload must flush caches, not be ignored"
        );
    }

    #[tokio::test]
    async fn valid_payload_is_applied_not_flushed() {
        let handles = test_handles();
        warm_repo_cache(&handles, "repo-hit").await;
        warm_repo_cache(&handles, "repo-bystander").await;

        handle_notification_payload(
            &handles,
            r#"{"v":1,"kind":"repository_deleted","key":"repo-hit"}"#,
        )
        .await;

        assert!(!repo_cache_contains(&handles, "repo-hit").await);
        assert!(
            repo_cache_contains(&handles, "repo-bystander").await,
            "a valid targeted event must not degrade into a full flush"
        );
    }

    #[tokio::test]
    async fn conservative_flush_empties_the_repo_cache() {
        let handles = test_handles();
        warm_repo_cache(&handles, "repo-a").await;
        warm_repo_cache(&handles, "repo-b").await;

        conservative_flush_all(&handles).await;

        assert!(handles.repo_cache.read().await.is_empty());
    }
}
