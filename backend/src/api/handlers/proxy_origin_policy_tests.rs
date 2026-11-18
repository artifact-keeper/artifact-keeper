//! #4506: a scan policy's origin predicates gate content a Remote serves from
//! its proxy cache or its upstream, not only `artifacts` rows.
//!
//! Router-level: every request goes through `create_router` with a real
//! `ProxyService` over a mock upstream, so the generic REST download, the
//! `/general/` route, the Maven format route and a virtual over the
//! Remote are the production paths. The first fetch fills the proxy cache, a
//! policy is attached, and the cached path (and an uncached one) must then be
//! refused with the hosted download gate's 403, without contacting the
//! upstream. An allowlist naming the upstream serves again.

#[cfg(ak_test_shard = "router")]
#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use bytes::Bytes;
    use uuid::Uuid;
    use wiremock::matchers::{method, path as wm_path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use crate::api::handlers::test_db_helpers as tdh;
    use crate::api::SharedState;
    use crate::models::security::{OriginPolicyPredicates, PolicyPredicates};
    use crate::services::policy_service::PolicyService;

    const GENERIC_PATH: &str = "o/1/o.bin";
    const MAVEN_PATH: &str = "com/acme/lib/1.0/lib-1.0.jar";
    const BYTES: &[u8] = b"proxied-bytes-4506";

    struct Rig {
        pool: sqlx::PgPool,
        state: SharedState,
        upstream: MockServer,
        user: Uuid,
        bearer: String,
        generic: (Uuid, String),
        maven: (Uuid, String),
        virt: (Uuid, String),
        _root: tempfile::TempDir,
    }

    impl Rig {
        async fn new(pool: sqlx::PgPool) -> Self {
            let upstream = MockServer::start().await;
            for p in [GENERIC_PATH, "o/2/uncached.bin", MAVEN_PATH] {
                Mock::given(method("GET"))
                    .and(wm_path(format!("/{p}")))
                    .respond_with(ResponseTemplate::new(200).set_body_bytes(BYTES.to_vec()))
                    .mount(&upstream)
                    .await;
            }
            let (g_id, g_key, _) = tdh::create_repo(&pool, "remote", "generic").await;
            let (m_id, m_key, _) = tdh::create_repo(&pool, "remote", "maven").await;
            let (v_id, v_key, _) = tdh::create_repo(&pool, "virtual", "generic").await;
            for id in [g_id, m_id] {
                sqlx::query("UPDATE repositories SET upstream_url = $1 WHERE id = $2")
                    .bind(upstream.uri())
                    .bind(id)
                    .execute(&pool)
                    .await
                    .expect("point remote at the mock upstream");
            }
            tdh::link_virtual_member(&pool, v_id, g_id, 1).await;
            let (user, _) = tdh::create_user(&pool).await;
            for id in [g_id, m_id, v_id] {
                tdh::grant_repo_role(&pool, id, user, "reader").await;
            }
            let root = tempfile::tempdir().expect("storage root");
            let root_path = root.path().to_str().expect("utf8").to_string();
            let proxy = tdh::build_proxy_service_with_fs(pool.clone(), &root_path);
            let state = tdh::build_state_with_proxy(pool.clone(), &root_path, proxy);
            let bearer = tdh::bearer_for(&state, user).await;
            Self {
                pool,
                state,
                upstream,
                user,
                bearer,
                generic: (g_id, g_key),
                maven: (m_id, m_key),
                virt: (v_id, v_key),
                _root: root,
            }
        }

        async fn get(&self, uri: String) -> (StatusCode, Bytes) {
            let app = crate::api::routes::create_router(self.state.clone());
            let req = Request::builder()
                .method("GET")
                .uri(uri)
                .header("authorization", &self.bearer)
                .body(Body::empty())
                .expect("request");
            tdh::send(app, req).await
        }

        fn generic_rest(&self, p: &str) -> String {
            format!("/api/v1/repositories/{}/download/{p}", self.generic.1)
        }

        async fn policy(&self, repo_id: Uuid, origin: OriginPolicyPredicates) {
            PolicyService::new(self.pool.clone())
                .create_policy(
                    &format!("4506-{}", Uuid::new_v4()),
                    Some(repo_id),
                    "critical",
                    false,
                    false,
                    None,
                    None,
                    false,
                    Some(PolicyPredicates {
                        origin,
                        ..Default::default()
                    }),
                )
                .await
                .expect("create origin policy");
        }

        async fn clear_policies(&self) {
            for id in [self.generic.0, self.maven.0, self.virt.0] {
                sqlx::query("DELETE FROM scan_policies WHERE repository_id = $1")
                    .bind(id)
                    .execute(&self.pool)
                    .await
                    .expect("delete policies");
            }
        }

        async fn upstream_hits(&self, p: &str) -> usize {
            self.upstream
                .received_requests()
                .await
                .unwrap_or_default()
                .iter()
                .filter(|r| r.url.path() == format!("/{p}"))
                .count()
        }

        async fn teardown(self) {
            self.clear_policies().await;
            sqlx::query("DELETE FROM virtual_repo_members WHERE virtual_repo_id = $1")
                .bind(self.virt.0)
                .execute(&self.pool)
                .await
                .ok();
            for id in [self.virt.0, self.maven.0] {
                sqlx::query("DELETE FROM proxy_cache_artifacts WHERE repository_id = $1")
                    .bind(id)
                    .execute(&self.pool)
                    .await
                    .ok();
                tdh::cleanup(&self.pool, id, self.user).await;
            }
            sqlx::query("DELETE FROM proxy_cache_artifacts WHERE repository_id = $1")
                .bind(self.generic.0)
                .execute(&self.pool)
                .await
                .ok();
            tdh::cleanup(&self.pool, self.generic.0, self.user).await;
        }
    }

    fn assert_blocked(what: &str, (status, body): (StatusCode, Bytes)) {
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "{what}: a denied upstream must block the proxied download: {}",
            String::from_utf8_lossy(&body)
        );
    }

    fn assert_served(what: &str, (status, body): (StatusCode, Bytes)) {
        assert_eq!(
            status,
            StatusCode::OK,
            "{what}: {}",
            String::from_utf8_lossy(&body)
        );
        assert_eq!(body.as_ref(), BYTES, "{what}");
    }

    #[tokio::test]
    async fn origin_policy_gates_proxy_cache_only_content_4506() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let rig = Rig::new(pool).await;
        let maven_uri = format!("/maven/{}/{MAVEN_PATH}", rig.maven.1);

        // Fill the proxy cache: only `proxy_cache_artifacts` rows result.
        assert_served(
            "generic first fetch",
            rig.get(rig.generic_rest(GENERIC_PATH)).await,
        );
        assert_served("maven first fetch", rig.get(maven_uri.clone()).await);
        let rows: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM artifacts WHERE repository_id = ANY($1) AND NOT is_deleted",
        )
        .bind(vec![rig.generic.0, rig.maven.0])
        .fetch_one(&rig.pool)
        .await
        .expect("count artifacts rows");
        assert_eq!(rows, 0, "a proxy fetch writes no artifacts row (#1280)");

        // Deny the upstream.
        let denied = rig.upstream.uri();
        for id in [rig.generic.0, rig.maven.0] {
            rig.policy(
                id,
                OriginPolicyPredicates {
                    denied_upstreams: vec![denied.clone()],
                    ..Default::default()
                },
            )
            .await;
        }
        let before = rig.upstream_hits("o/2/uncached.bin").await;
        assert_blocked(
            "generic REST, cached",
            rig.get(rig.generic_rest(GENERIC_PATH)).await,
        );
        assert_blocked(
            "generic /general/, cached",
            rig.get(format!("/general/{}/{GENERIC_PATH}", rig.generic.1))
                .await,
        );
        assert_blocked(
            "generic REST, uncached",
            rig.get(rig.generic_rest("o/2/uncached.bin")).await,
        );
        assert_eq!(
            rig.upstream_hits("o/2/uncached.bin").await,
            before,
            "a refused path must not contact the upstream"
        );
        assert_blocked("maven, cached", rig.get(maven_uri.clone()).await);
        // Through a virtual the member's refusal is not served either. (The
        // generic REST route answers any failed member walk with its 404, as
        // it does for a blocked hosted member.)
        let (status, body) = rig
            .get(format!(
                "/api/v1/repositories/{}/download/{GENERIC_PATH}",
                rig.virt.1
            ))
            .await;
        assert!(
            !status.is_success() && body.as_ref() != BYTES,
            "virtual over the remote must not serve refused content: {status}"
        );

        // `allowed_kinds` without `proxy` refuses proxied content too.
        rig.clear_policies().await;
        rig.policy(
            rig.generic.0,
            OriginPolicyPredicates {
                allowed_kinds: vec!["hosted".to_string()],
                ..Default::default()
            },
        )
        .await;
        assert_blocked(
            "allowed_kinds=[hosted]",
            rig.get(rig.generic_rest(GENERIC_PATH)).await,
        );

        // Control: an allowlist naming the upstream, and the `proxy` kind,
        // serves again.
        rig.clear_policies().await;
        rig.policy(
            rig.generic.0,
            OriginPolicyPredicates {
                allowed_upstreams: vec![rig.upstream.uri()],
                allowed_kinds: vec!["proxy".to_string()],
                allowed_repositories: vec![rig.generic.1.clone()],
                ..Default::default()
            },
        )
        .await;
        assert_served(
            "allowlisted upstream",
            rig.get(rig.generic_rest(GENERIC_PATH)).await,
        );
        assert_served("no policy on maven", rig.get(maven_uri).await);

        rig.teardown().await;
    }

    /// #6069: a released-jar GET reaches the origin gate twice for the same
    /// Remote (the content fetch and the cached `.sha1` read behind
    /// `X-Checksum-SHA1`, #4573), and the per-request memo evaluates it once.
    /// The header still rides on an allowed jar; once the upstream is denied
    /// the jar is a 403 with no checksum header and no upstream contact.
    #[tokio::test]
    async fn maven_jar_get_evaluates_the_origin_gate_once_6069() {
        use sha1::Digest as _;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let rig = Rig::new(pool).await;
        let sha1_hex = hex::encode(sha1::Sha1::digest(BYTES));
        Mock::given(method("GET"))
            .and(wm_path(format!("/{MAVEN_PATH}.sha1")))
            .respond_with(ResponseTemplate::new(200).set_body_string(sha1_hex.clone()))
            .mount(&rig.upstream)
            .await;
        let maven_uri = format!("/maven/{}/{MAVEN_PATH}", rig.maven.1);
        let get = |uri: String| async {
            let req = Request::builder()
                .method("GET")
                .uri(uri)
                .header("authorization", &rig.bearer)
                .body(Body::empty())
                .expect("request");
            tdh::send_with_headers(crate::api::routes::create_router(rig.state.clone()), req).await
        };
        let sha1_header = |h: &axum::http::HeaderMap| {
            h.get("x-checksum-sha1")
                .map(|v| v.to_str().expect("ascii header").to_string())
        };

        // Cold GET commits the jar and, through its digest gate, the `.sha1`.
        let (status, body, _) = get(maven_uri.clone()).await;
        assert_served("maven cold fetch", (status, body));
        let cache = rig._root.path().join("proxy-cache").join(&rig.maven.1);
        tdh::await_proxy_sidecar(&cache.join(MAVEN_PATH).join("__cache_meta__.json")).await;
        tdh::await_proxy_sidecar(
            &cache
                .join(format!("{MAVEN_PATH}.sha1"))
                .join("__cache_meta__.json"),
        )
        .await;

        use crate::services::proxy_service::origin_gate_evaluations;
        let evaluations_before = origin_gate_evaluations::count(rig.maven.0);
        let lookups_before = origin_gate_evaluations::key_lookups(&rig.maven.1);
        let (status, body, headers) = get(maven_uri.clone()).await;
        let warm_key_lookups = origin_gate_evaluations::key_lookups(&rig.maven.1) - lookups_before;
        let warm_evaluations = origin_gate_evaluations::count(rig.maven.0) - evaluations_before;
        assert_served("maven warm fetch", (status, body));
        assert_eq!(
            warm_evaluations, 1,
            "one warm jar GET evaluates the Remote's origin gate once, not once per read"
        );
        assert_eq!(
            warm_key_lookups, 0,
            "the jar fetch gates first and the sidecar read reuses its pass, so the \
             Remote is never looked up again by key"
        );
        assert_eq!(
            sha1_header(&headers).as_deref(),
            Some(sha1_hex.as_str()),
            "a warm allowed jar carries the SHA-1 of its cached `.sha1`"
        );

        rig.policy(
            rig.maven.0,
            OriginPolicyPredicates {
                denied_upstreams: vec![rig.upstream.uri()],
                ..Default::default()
            },
        )
        .await;
        let hits_before = rig.upstream_hits(MAVEN_PATH).await
            + rig.upstream_hits(&format!("{MAVEN_PATH}.sha1")).await;
        let (status, body, headers) = get(maven_uri).await;
        let hits_after = rig.upstream_hits(MAVEN_PATH).await
            + rig.upstream_hits(&format!("{MAVEN_PATH}.sha1")).await;
        rig.teardown().await;

        assert_blocked("maven, cached, denied upstream", (status, body));
        assert_eq!(
            sha1_header(&headers),
            None,
            "a refused jar must not carry its cached sidecar's checksum"
        );
        assert_eq!(
            hits_after, hits_before,
            "a refused jar never contacts the upstream"
        );
    }
}
