//! General (Generic) repository download handler.
//!
//! Provides a native-protocol style download endpoint for Generic format
//! repositories, matching the URL pattern used by other format handlers.
//!
//! Routes are mounted at `/general/{repo_key}/...`:
//!   GET  /general/{repo_key}/*path — Download artifact

use axum::Router;

use crate::api::handlers::repositories::download_artifact;
use crate::api::SharedState;

pub fn router() -> Router<SharedState> {
    Router::new().route("/:repo_key/*path", axum::routing::get(download_artifact))
}

#[cfg(test)]
mod tests {
    use crate::api::handlers::test_db_helpers as tdh;

    /// #2705: a proxy download through the generic `/general/{key}/*path`
    /// route must be recorded in `proxy_download_statistics`, with the same
    /// semantics as the format-specific proxy paths (first serve counts,
    /// counting continues on cache hits, HEAD never counts).
    ///
    /// Pre-fix, `repositories::download_artifact`'s Remote fallback streamed
    /// the proxy body but never called `record_proxy_download`, so generic
    /// remote downloads were invisible to proxy download counting (count
    /// stayed 0 here). Skips cleanly when DATABASE_URL is unset.
    #[tokio::test]
    async fn test_general_remote_proxy_download_is_counted_2705() {
        use crate::services::proxy_catalog::download_count_by_repo;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(fx) = tdh::Fixture::setup("remote", "generic").await else {
            return;
        };
        let server = MockServer::start().await;
        let blob: &[u8] = b"#2705 generic proxy serve marker bytes";
        Mock::given(method("GET"))
            .and(path("/files/obj.bin"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(blob))
            .mount(&server)
            .await;

        let (state, _cache) = tdh::rewire_remote_proxy(&fx, &server.uri()).await;
        let auth = tdh::make_auth(fx.user_id, &fx.username);
        let uri = format!("/{}/files/obj.bin", fx.repo_key);

        // First (cold) serve: 200 + upstream bytes, and the serve is counted.
        let app = tdh::router_with_auth(super::router(), state.clone(), auth.clone());
        let (status, body) = tdh::send(app, tdh::get(uri.clone())).await;

        let teardown = || async { fx.teardown().await };
        if status != axum::http::StatusCode::OK {
            teardown().await;
            panic!("expected 200 from generic remote proxy download, got {status}");
        }
        if &body[..] != blob {
            teardown().await;
            panic!("streamed body must equal upstream bytes");
        }
        let first = download_count_by_repo(&fx.pool, fx.repo_id)
            .await
            .expect("count query");
        if first != 1 {
            teardown().await;
            panic!(
                "#2705: first generic proxy serve must record exactly one \
                 proxy_download_statistics row, got {first} (0 = the pre-fix \
                 /general/ path never called record_proxy_download)"
            );
        }

        // Second serve (cache hit or refetch — either way a real serve):
        // counting continues, matching the format handlers' semantics.
        let app = tdh::router_with_auth(super::router(), state.clone(), auth.clone());
        let (status2, _) = tdh::send(app, tdh::get(uri.clone())).await;
        let second = download_count_by_repo(&fx.pool, fx.repo_id)
            .await
            .expect("count query");
        if status2 != axum::http::StatusCode::OK || second != 2 {
            teardown().await;
            panic!(
                "second generic proxy serve must count (status {status2}, count {second}, want 200/2)"
            );
        }

        // HEAD guard: a HEAD probe serves no bytes and must not count.
        let app = tdh::router_with_auth(super::router(), state.clone(), auth);
        let head_req = axum::http::Request::builder()
            .method(axum::http::Method::HEAD)
            .uri(uri)
            .body(axum::body::Body::empty())
            .expect("build HEAD request");
        let _ = tdh::send(app, head_req).await;
        let after_head = download_count_by_repo(&fx.pool, fx.repo_id)
            .await
            .expect("count query");
        teardown().await;
        assert_eq!(
            after_head, 2,
            "HEAD must not increment the proxy download count (is_head guard)"
        );
    }
}
