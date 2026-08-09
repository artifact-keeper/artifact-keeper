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

    /// #3143: the Generic download path must apply the repository's scan
    /// policy, not just the quarantine predicate.
    ///
    /// `repositories::download_artifact` — re-exported here as the Generic
    /// format route, and also mounted as the generic REST download at
    /// `/api/v1/repositories/{key}/download/*path` — resolved the artifact row
    /// itself and called the raw `check_download_allowed` predicate. That is
    /// quarantine only, so `block_unscanned` / `block_on_fail` / `max_severity`
    /// were skipped entirely, unlike the ~25 per-format handlers that route
    /// through `enforce_download_gate`.
    ///
    /// The gate is placed at the handler, before the branch into the presigned
    /// redirect / `?version=` revision / streamed-local sub-paths, because only
    /// the last of those reaches `ArtifactService::prepare_download`.
    ///
    /// Positive and negative controls live in this same fixture: the identical
    /// request serves 200 before the policy is created and 200 again after it
    /// is removed, so the 403 is attributable to the policy alone.
    #[tokio::test]
    async fn test_generic_download_applies_scan_policy_3143() {
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let blob = bytes::Bytes::from_static(b"#3143 generic gate marker bytes");
        let path = "files/gate.bin";
        tdh::seed_artifact(
            &fx.state,
            &fx.pool,
            &fx.repo_info("local", None),
            path,
            path,
            "gate",
            "1.0.0",
            "application/octet-stream",
            blob.clone(),
            fx.user_id,
        )
        .await;

        let uri = format!("/{}/{}", fx.repo_key, path);

        // POSITIVE CONTROL: no scan policy -> must serve the real bytes.
        let (before_status, before_body) =
            tdh::send(fx.router_with_auth(super::router()), tdh::get(uri.clone())).await;

        // A policy that blocks unscanned artifacts; the seeded artifact has no
        // scan_results rows.
        sqlx::query(
            "INSERT INTO scan_policies (name, repository_id, max_severity, block_unscanned, \
                                        block_on_fail, is_enabled) \
             VALUES ($1, $2, 'critical', true, false, true)",
        )
        .bind(format!("gate-3143-generic-{}", fx.repo_id))
        .bind(fx.repo_id)
        .execute(&fx.pool)
        .await
        .expect("insert block_unscanned policy");

        let (blocked_status, blocked_body) =
            tdh::send(fx.router_with_auth(super::router()), tdh::get(uri.clone())).await;

        let _ = sqlx::query("DELETE FROM scan_policies WHERE repository_id = $1")
            .bind(fx.repo_id)
            .execute(&fx.pool)
            .await;

        // NEGATIVE CONTROL: removing the policy restores the download.
        let (after_status, after_body) =
            tdh::send(fx.router_with_auth(super::router()), tdh::get(uri.clone())).await;

        fx.teardown().await;

        assert_eq!(
            before_status,
            axum::http::StatusCode::OK,
            "positive control: with no scan policy the generic download must work"
        );
        assert_eq!(
            before_body.as_ref(),
            blob.as_ref(),
            "positive control: served bytes must be the seeded artifact"
        );
        assert_eq!(
            blocked_status,
            axum::http::StatusCode::FORBIDDEN,
            "#3143: an unscanned artifact under block_unscanned must be refused with 403 on \
             the generic path, got {blocked_status} body={:?}",
            String::from_utf8_lossy(&blocked_body)
        );
        assert_ne!(
            blocked_body.as_ref(),
            blob.as_ref(),
            "#3143: artifact bytes must not be served when the policy blocks"
        );
        assert_eq!(
            after_status,
            axum::http::StatusCode::OK,
            "negative control: removing the policy must restore the download"
        );
        assert_eq!(
            after_body.as_ref(),
            blob.as_ref(),
            "negative control: bytes restored"
        );
    }

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
