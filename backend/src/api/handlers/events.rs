use axum::{
    extract::State,
    response::sse::{Event, KeepAlive, Sse},
    routing::get,
    Router,
};
use futures::stream::Stream;
use std::convert::Infallible;
use tokio::sync::broadcast;

use crate::api::SharedState;
use crate::error::Result;

pub fn router() -> Router<SharedState> {
    Router::new().route("/stream", get(event_stream))
}

/// Stream domain events via Server-Sent Events.
///
/// Clients receive `entity.changed` events whenever a CRUD operation happens.
/// If a client falls behind, it receives a `lagged` event and should do a full refresh.
#[utoipa::path(
    get,
    path = "/stream",
    context_path = "/api/v1/events",
    tag = "events",
    responses(
        (status = 200, description = "SSE stream of domain events")
    ),
    security(("bearer_auth" = []))
)]
async fn event_stream(
    State(state): State<SharedState>,
) -> Result<Sse<impl Stream<Item = std::result::Result<Event, Infallible>>>> {
    let mut rx = state.event_bus.subscribe();

    let stream = async_stream::stream! {
        yield Ok(Event::default().event("connected").data(r#"{"status":"ok"}"#));

        loop {
            match rx.recv().await {
                Ok(domain_event) => {
                    let data = serde_json::to_string(&domain_event).unwrap_or_default();
                    yield Ok(Event::default().event("entity.changed").data(data));
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
        Config {
            database_url: String::new(),
            bind_address: "0.0.0.0:8080".into(),
            log_level: "info".into(),
            storage_backend: "filesystem".into(),
            storage_path: "/tmp".into(),
            s3_bucket: None,
            s3_region: None,
            s3_endpoint: None,
            jwt_secret: "test-secret".into(),
            jwt_expiration_secs: 3600,
            jwt_access_token_expiry_minutes: 30,
            jwt_refresh_token_expiry_days: 7,
            oidc_issuer: None,
            oidc_client_id: None,
            oidc_client_secret: None,
            ldap_url: None,
            ldap_base_dn: None,
            trivy_url: None,
            openscap_url: None,
            openscap_profile: "standard".into(),
            meilisearch_url: None,
            meilisearch_api_key: None,
            scan_workspace_path: "/tmp".into(),
            demo_mode: false,
            peer_instance_name: "test".into(),
            peer_public_endpoint: "http://localhost:8080".into(),
            peer_api_key: "test".into(),
            dependency_track_url: None,
            otel_exporter_otlp_endpoint: None,
            otel_service_name: "test".into(),
            gc_schedule: "0 0 * * * *".into(),
            lifecycle_check_interval_secs: 60,
        }
    }

    fn test_state() -> Arc<AppState> {
        let pool = PgPool::connect_lazy("postgres://fake:fake@localhost/fake")
            .expect("connect_lazy should not fail");
        let storage = Arc::new(FilesystemStorage::new("/tmp/test-events"));
        Arc::new(AppState::new(test_config(), pool, storage))
    }

    async fn send_stream_request(state: Arc<AppState>) -> axum::response::Response<Body> {
        let app = router().with_state(state);
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
        use futures::StreamExt;

        let resp = send_stream_request(state).await;
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
}
