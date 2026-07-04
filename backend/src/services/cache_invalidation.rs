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
//! This module closes that window: database triggers (migration 142) call
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
use std::time::Duration;

use metrics::counter;
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgListener;
use sqlx::PgPool;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::api::RepoCache;
use crate::services::auth_service;
use crate::services::permission_service::PermissionService;

/// Upper bound for the reconnect backoff. Long enough to avoid hammering a
/// database that is down, short enough that a recovered database is picked
/// up quickly (until then the TTLs bound staleness).
const MAX_RECONNECT_BACKOFF: Duration = Duration::from_secs(30);

/// Postgres notification channel the triggers publish on and the listener
/// subscribes to. Versioned so a future incompatible payload schema can move
/// to a `_v2` channel without confusing old replicas during a rolling deploy.
pub const CACHE_INVALIDATION_CHANNEL: &str = "ak_cache_invalidation_v1";

/// Payload schema version expected inside each notification envelope.
pub const CACHE_INVALIDATION_VERSION: u8 = 1;

/// A single cache-invalidation event, JSON-encoded by the migration-142
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
pub fn parse_invalidation_payload(payload: &str) -> Result<InvalidationEvent, String> {
    let envelope: InvalidationEnvelope =
        serde_json::from_str(payload).map_err(|e| format!("malformed payload: {e}"))?;
    if envelope.v != CACHE_INVALIDATION_VERSION {
        return Err(format!(
            "unsupported payload version {} (expected {})",
            envelope.v, CACHE_INVALIDATION_VERSION
        ));
    }
    Ok(envelope.event)
}

/// Apply one event to this process's caches, idempotently. Each arm reuses
/// the same invalidation helper the originating replica calls locally, so
/// same-replica and cross-replica behavior cannot drift apart.
pub async fn apply_invalidation_event(
    handles: &CacheInvalidationHandles,
    event: &InvalidationEvent,
) {
    match event {
        InvalidationEvent::ApiTokenRevoked { token_id } => {
            auth_service::mark_api_token_revoked(*token_id);
        }
        InvalidationEvent::UserApiTokensInvalidated { user_id } => {
            auth_service::invalidate_user_token_cache_entries(*user_id);
        }
        InvalidationEvent::RepositoryChanged { old_key, new_key } => {
            let mut cache = handles.repo_cache.write().await;
            cache.remove(old_key);
            cache.remove(new_key);
        }
        InvalidationEvent::RepositoryDeleted { key } => {
            handles.repo_cache.write().await.remove(key);
        }
        InvalidationEvent::PermissionsChanged => {
            handles.permission_service.invalidate_cache();
        }
    }
}

/// Conservatively flush every cache family this module manages. Used on
/// listener startup, on reconnect, and on any payload that fails to parse.
pub async fn conservative_flush_all(handles: &CacheInvalidationHandles) {
    let flushed_token_entries = auth_service::flush_all_api_token_cache_entries();
    handles.repo_cache.write().await.clear();
    handles.permission_service.invalidate_cache();
    counter!("ak_cache_invalidation_conservative_flushes_total").increment(1);
    tracing::info!(
        flushed_token_entries,
        "conservatively flushed authorization caches (listener start/reconnect or bad payload)"
    );
}

/// Handle one raw notification payload: apply it if it parses, otherwise
/// log and conservatively flush. Failing closed on unparseable payloads
/// means a newer schema (or a corrupted payload) degrades to an extra cache
/// refill instead of a silently retained stale authorization.
pub async fn handle_notification_payload(handles: &CacheInvalidationHandles, payload: &str) {
    match parse_invalidation_payload(payload) {
        Ok(event) => {
            counter!("ak_cache_invalidation_events_total").increment(1);
            tracing::debug!(?event, "applying cache-invalidation event");
            apply_invalidation_event(handles, &event).await;
        }
        Err(reason) => {
            counter!("ak_cache_invalidation_parse_errors_total").increment(1);
            tracing::warn!(
                %reason,
                "unparseable cache-invalidation payload; conservatively flushing caches"
            );
            conservative_flush_all(handles).await;
        }
    }
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
/// When the initial connection cannot be established the handle is still
/// returned: the spawned task keeps retrying in the background so a
/// temporarily unreachable database at boot does not abort startup.
pub async fn start_cache_invalidation_listener(
    pool: PgPool,
    handles: CacheInvalidationHandles,
    shutdown: CancellationToken,
) -> JoinHandle<()> {
    // Establish the first LISTEN before returning so callers know that any
    // event committed after this function resolves will be observed (or, if
    // the database is unreachable at boot, the task below keeps retrying
    // while the process serves requests under TTL-bound staleness).
    let initial = connect_and_flush(&pool, &handles).await;

    tokio::spawn(async move {
        let mut listener = initial;
        let mut backoff = Duration::from_secs(1);
        loop {
            let mut current = match listener.take() {
                Some(l) => l,
                None => {
                    tokio::select! {
                        _ = shutdown.cancelled() => return,
                        _ = tokio::time::sleep(backoff) => {}
                    }
                    backoff = (backoff * 2).min(MAX_RECONNECT_BACKOFF);
                    match connect_and_flush(&pool, &handles).await {
                        Some(l) => l,
                        None => continue,
                    }
                }
            };
            backoff = Duration::from_secs(1);

            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => return,
                    received = current.try_recv() => match received {
                        Ok(Some(notification)) => {
                            handle_notification_payload(&handles, notification.payload()).await;
                        }
                        // sqlx re-established the connection under the hood;
                        // LISTEN is active again but anything committed in
                        // the gap was missed.
                        Ok(None) => {
                            counter!("ak_cache_invalidation_reconnects_total").increment(1);
                            tracing::warn!(
                                "cache-invalidation listener reconnected; flushing caches"
                            );
                            conservative_flush_all(&handles).await;
                        }
                        // Reconnect failed inside sqlx: drop this listener and
                        // go back to explicit connect-with-backoff so the
                        // conservative flush runs only once LISTEN is truly
                        // re-established (flushing earlier would let a cache
                        // refill go stale again before we are listening).
                        Err(e) => {
                            tracing::warn!(
                                error = %e,
                                "cache-invalidation listener lost; reconnecting with backoff"
                            );
                            break;
                        }
                    }
                }
            }
        }
    })
}

/// Open a dedicated listener connection, `LISTEN`, then conservatively flush
/// the local caches: anything committed while this process was not listening
/// was missed, so every cached authorization is suspect. Returns `None` (after
/// logging) when the connection or `LISTEN` fails.
async fn connect_and_flush(
    pool: &PgPool,
    handles: &CacheInvalidationHandles,
) -> Option<PgListener> {
    let mut listener = match PgListener::connect_with(pool).await {
        Ok(l) => l,
        Err(e) => {
            tracing::warn!(error = %e, "cache-invalidation listener connect failed");
            return None;
        }
    };
    if let Err(e) = listener.listen(CACHE_INVALIDATION_CHANNEL).await {
        tracing::warn!(error = %e, "cache-invalidation LISTEN failed");
        return None;
    }
    counter!("ak_cache_invalidation_reconnects_total").increment(1);
    conservative_flush_all(handles).await;
    tracing::info!(
        channel = CACHE_INVALIDATION_CHANNEL,
        "cache-invalidation listener established"
    );
    Some(listener)
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
    /// trigger payloads (written by hand in migration 142) and this parser
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
