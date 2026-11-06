use axum::{
    extract::{Extension, State},
    response::sse::{Event, KeepAlive, Sse},
    routing::get,
    Router,
};
use futures::stream::Stream;
use std::collections::HashMap;
use std::convert::Infallible;
use std::time::{Duration, Instant};
use tokio::sync::broadcast;
use uuid::Uuid;

use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::error::Result;
use crate::services::event_bus::DomainEvent;

pub fn router() -> Router<SharedState> {
    Router::new().route("/stream", get(event_stream))
}

/// Stream domain events via Server-Sent Events.
///
/// Clients receive `entity.changed` events whenever a CRUD operation happens.
/// If a client falls behind, it receives a `lagged` event and should do a full refresh.
///
/// An administrator receives every event. Any other caller receives only the
/// events of repositories it may read (the `require_visible` predicate, token
/// scope included), with the actor left out, and, for an artifact of an MCP
/// registry it does not hold, only while that server version is served to
/// readers (the MCP serve decision). Events about no repository (users,
/// groups, permissions, service accounts, quality gates) are administrator
/// data, except a `user.*` event about the caller itself.
#[utoipa::path(
    get,
    path = "/stream",
    context_path = "/api/v1/events",
    tag = "events",
    responses(
        (status = 200, description = "SSE stream of domain events the caller may see")
    ),
    security(("bearer_auth" = []))
)]
async fn event_stream(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
) -> Result<Sse<impl Stream<Item = std::result::Result<Event, Infallible>>>> {
    let mut rx = state.event_bus.subscribe();
    let mut audience = Audience::new(state.clone(), auth);

    let stream = async_stream::stream! {
        yield Ok(Event::default().event("connected").data(r#"{"status":"ok"}"#));

        loop {
            match rx.recv().await {
                Ok(domain_event) => {
                    if let Some(domain_event) = audience.admit(domain_event).await {
                        let data = serde_json::to_string(&domain_event).unwrap_or_default();
                        yield Ok(Event::default().event("entity.changed").data(data));
                    }
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    yield Ok(Event::default()
                        .event("lagged")
                        .data(format!(r#"{{"missed":{n}}}"#)));
                }
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    };

    Ok(Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(std::time::Duration::from_secs(15))
            .text("ping"),
    ))
}

/// How long one subscriber's repository read decision is reused before it
/// is evaluated again, so a revoked grant stops the events within this time.
const REPO_DECISION_TTL: Duration = Duration::from_secs(30);

/// Which events one subscriber may receive.
pub(crate) struct Audience {
    state: SharedState,
    auth: AuthExtension,
    /// Per repository: when it was decided, and `None` when the caller may
    /// not read it, otherwise whether it is an MCP registry.
    repos: HashMap<Uuid, (Instant, Option<bool>)>,
}

impl Audience {
    pub(crate) fn new(state: SharedState, auth: AuthExtension) -> Self {
        Self {
            state,
            auth,
            repos: HashMap::new(),
        }
    }

    /// The event as this subscriber may see it, or `None`. Fails closed: an
    /// event whose repository or artifact cannot be resolved is dropped.
    pub(crate) async fn admit(&mut self, mut event: DomainEvent) -> Option<DomainEvent> {
        if self.auth.is_admin {
            return Some(event);
        }
        let artifact = if event.event_type.starts_with("artifact.") {
            match Uuid::parse_str(&event.entity_id) {
                Ok(id) => Some((id, self.artifact_row(id).await?)),
                Err(_) => None,
            }
        } else {
            None
        };
        let repo_id = event
            .repository_id
            .or_else(|| artifact.as_ref().map(|(_, (repo, _))| *repo));
        let Some(repo_id) = repo_id else {
            let own = event.event_type.starts_with("user.")
                && event.entity_id == self.auth.user_id.to_string();
            if !own {
                return None;
            }
            event.actor = None;
            return Some(event);
        };
        let is_mcp = self.readable(repo_id).await?;
        if is_mcp {
            if let Some((_, (artifact_repo, path))) = &artifact {
                let mut gate = crate::api::handlers::mcp::GenericArtifactGate::new(
                    &self.state,
                    Some(&self.auth),
                );
                if !gate.visible(*artifact_repo, path).await {
                    return None;
                }
            }
        }
        event.actor = None;
        Some(event)
    }

    async fn artifact_row(&self, id: Uuid) -> Option<(Uuid, String)> {
        sqlx::query_as("SELECT repository_id, path FROM artifacts WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.state.db)
            .await
            .ok()
            .flatten()
    }

    /// `Some(is_mcp)` when the caller may read the repository.
    async fn readable(&mut self, repo_id: Uuid) -> Option<bool> {
        if let Some((at, decided)) = self.repos.get(&repo_id) {
            if at.elapsed() < REPO_DECISION_TTL {
                return *decided;
            }
        }
        let service =
            crate::services::repository_service::RepositoryService::new(self.state.db.clone());
        let decided = match service.get_by_id(repo_id).await {
            Ok(repo) => crate::api::handlers::repositories::require_visible(
                &repo,
                &Some(self.auth.clone()),
                &service,
            )
            .await
            .ok()
            .map(|_| repo.format == crate::models::repository::RepositoryFormat::Mcp),
            Err(_) => None,
        };
        self.repos.insert(repo_id, (Instant::now(), decided));
        decided
    }
}

#[cfg(ak_test_shard = "handlers-1")]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::AppState;
    use crate::config::Config;
    use crate::services::event_bus::{DomainEvent, EventBus};
    use crate::storage::filesystem::FilesystemStorage;
    use axum::body::Body;
    use axum::http::Request;
    use sqlx::PgPool;
    use std::sync::Arc;
    use tower::ServiceExt;

    fn test_config() -> Config {
        Config::test_config()
    }

    fn test_state() -> Arc<AppState> {
        let pool = PgPool::connect_lazy("postgres://fake:fake@localhost/fake")
            .expect("connect_lazy should not fail");
        let storage: Arc<dyn crate::storage::StorageBackend> =
            Arc::new(FilesystemStorage::new("/tmp/test-events"));
        let registry = Arc::new(crate::storage::StorageRegistry::new(
            std::collections::HashMap::new(),
            "filesystem".to_string(),
        ));
        Arc::new(AppState::new(test_config(), pool, storage, registry))
    }

    fn admin() -> AuthExtension {
        AuthExtension {
            is_admin: true,
            ..crate::api::handlers::test_db_helpers::make_auth(uuid::Uuid::new_v4(), "admin")
        }
    }

    async fn send_stream_request(state: Arc<AppState>) -> axum::response::Response<Body> {
        send_stream_request_as(state, admin()).await
    }

    async fn send_stream_request_as(
        state: Arc<AppState>,
        auth: AuthExtension,
    ) -> axum::response::Response<Body> {
        let app = router().with_state(state).layer(axum::Extension(auth));
        let req = Request::builder()
            .uri("/stream")
            .body(Body::empty())
            .unwrap();
        ServiceExt::<axum::http::Request<Body>>::oneshot(app, req)
            .await
            .unwrap()
    }

    /// Collect SSE body bytes for up to `ms` milliseconds.
    async fn collect_sse_bytes(state: Arc<AppState>, ms: u64) -> Vec<u8> {
        collect_sse_bytes_as(state, admin(), ms).await
    }

    async fn collect_sse_bytes_as(state: Arc<AppState>, auth: AuthExtension, ms: u64) -> Vec<u8> {
        use futures::StreamExt;

        let resp = send_stream_request_as(state, auth).await;
        let mut body = resp.into_body().into_data_stream();
        let mut bytes = Vec::new();

        let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(ms);
        while let Ok(Some(Ok(chunk))) = tokio::time::timeout_at(deadline, body.next()).await {
            bytes.extend_from_slice(&chunk);
        }
        bytes
    }

    #[tokio::test]
    async fn stream_returns_200_with_sse_content_type() {
        let state = test_state();
        let resp = send_stream_request(state).await;
        assert_eq!(resp.status(), 200);
        let ct = resp
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(
            ct.contains("text/event-stream"),
            "expected text/event-stream, got: {ct}"
        );
    }

    #[tokio::test]
    async fn stream_sends_connected_event_first() {
        let state = test_state();
        let bytes = collect_sse_bytes(state, 200).await;
        let body = String::from_utf8_lossy(&bytes);
        assert!(
            body.contains("event: connected"),
            "first event should be connected, got: {body}"
        );
        assert!(
            body.contains(r#"{"status":"ok"}"#),
            "connected data missing, got: {body}"
        );
    }

    #[tokio::test]
    async fn stream_receives_published_domain_event() {
        let state = test_state();
        let bus = state.event_bus.clone();

        let handle = tokio::spawn({
            let state = state.clone();
            async move { collect_sse_bytes(state, 500).await }
        });

        // Give the handler time to subscribe
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        bus.publish(DomainEvent::now(
            "user.created",
            "u-1",
            Some("admin".into()),
        ));

        let bytes = handle.await.unwrap();
        let body = String::from_utf8_lossy(&bytes);
        assert!(
            body.contains("event: entity.changed"),
            "expected entity.changed, got: {body}"
        );
        assert!(
            body.contains("user.created"),
            "expected user.created in data, got: {body}"
        );
    }

    #[tokio::test]
    async fn stream_sends_lagged_on_overflow() {
        let state = test_state();
        let tiny_bus = Arc::new(EventBus::new(2));
        let state = Arc::new(AppState {
            event_bus: tiny_bus.clone(),
            ..(*state).clone()
        });

        let handle = tokio::spawn({
            let state = state.clone();
            async move { collect_sse_bytes(state, 500).await }
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        for i in 0..5 {
            tiny_bus.publish(DomainEvent::now(format!("event.{i}"), i.to_string(), None));
        }

        let bytes = handle.await.unwrap();
        let body = String::from_utf8_lossy(&bytes);
        assert!(
            body.contains("event: lagged"),
            "expected lagged event, got: {body}"
        );
        assert!(
            body.contains("missed"),
            "expected missed count, got: {body}"
        );
    }

    #[tokio::test]
    async fn router_mounts_at_stream_path() {
        let state = test_state();
        let resp = send_stream_request(state).await;
        assert_eq!(resp.status(), 200);
    }

    /// The `type`s and actors of the `entity.changed` events `auth` receives
    /// while `events` are published.
    async fn received_as(
        state: Arc<AppState>,
        auth: AuthExtension,
        events: Vec<DomainEvent>,
    ) -> Vec<(String, serde_json::Value)> {
        let bus = state.event_bus.clone();
        let handle = tokio::spawn({
            let state = state.clone();
            async move { collect_sse_bytes_as(state, auth, 1500).await }
        });
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        for e in events {
            bus.publish(e);
        }
        let bytes = handle.await.unwrap();
        String::from_utf8_lossy(&bytes)
            .lines()
            .filter_map(|l| l.strip_prefix("data:"))
            .filter_map(|d| serde_json::from_str::<serde_json::Value>(d.trim()).ok())
            .filter_map(|v| {
                let t = v["type"].as_str()?.to_string();
                Some((t, v["actor"].clone()))
            })
            .collect()
    }

    /// A signed-in non-admin receives only the events of repositories it may
    /// read, without the actor, and no event about another principal or a
    /// non-repository entity; an administrator receives all of them.
    #[tokio::test]
    async fn stream_forwards_only_events_the_subscriber_may_see() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        // The fixture user holds a grant on its own repository, none here.
        let (hidden_id, _hidden_key, hidden_dir) =
            tdh::create_repo(&fx.pool, "local", "generic").await;
        let user = tdh::make_auth(fx.user_id, &fx.username);
        let actor = Some("someone".to_string());
        let events = || {
            vec![
                DomainEvent::now_for_repo(
                    "repository.updated",
                    fx.repo_id,
                    fx.repo_id,
                    actor.clone(),
                ),
                DomainEvent::now_for_repo(
                    "artifact.uploaded",
                    uuid::Uuid::new_v4(),
                    hidden_id,
                    actor.clone(),
                ),
                DomainEvent::now_for_repo(
                    "repository.updated",
                    hidden_id,
                    hidden_id,
                    actor.clone(),
                ),
                DomainEvent::now("user.created", uuid::Uuid::new_v4(), actor.clone()),
                DomainEvent::now("group.updated", uuid::Uuid::new_v4(), actor.clone()),
                DomainEvent::now("permission.created", uuid::Uuid::new_v4(), actor.clone()),
                DomainEvent::now("user.updated", fx.user_id, actor.clone()),
                DomainEvent::now(
                    "artifact.quarantine.released",
                    uuid::Uuid::new_v4(),
                    actor.clone(),
                ),
            ]
        };
        let seen_user = received_as(fx.state.clone(), user, events()).await;
        let seen_admin = received_as(fx.state.clone(), admin(), events()).await;

        tdh::cleanup_member_repo(&fx.pool, hidden_id, &hidden_dir).await;
        fx.teardown().await;

        assert_eq!(
            seen_user,
            vec![
                ("repository.updated".to_string(), serde_json::Value::Null),
                ("user.updated".to_string(), serde_json::Value::Null),
            ],
            "a non-admin sees its readable repository and itself, without actors"
        );
        assert_eq!(seen_admin.len(), 8, "an administrator sees every event");
        assert!(seen_admin.iter().all(|(_, a)| a == "someone"));
    }
}
