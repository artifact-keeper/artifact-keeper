//! #4570: `git lfs pull` from a private repository. The batch response for a
//! download must hand git-lfs a download action it can follow: an action
//! marked `authenticated: true` must carry the credentials the object GET
//! needs, because git-lfs sends that GET with the action's headers only.
//!
//! Router-level: every request goes through `create_router`, so
//! `repo_visibility_middleware`, the batch handler and the object download
//! are the production ones. Covers an anonymous caller, an authenticated user
//! without a grant, and a user with a read grant.

// The whole module is a `#[cfg(test)] mod` block so that
// `scripts/ci/check-token-mint-surface.sh` (#1315) recognises its
// `generate_api_token` calls as test-only.
#[cfg(ak_test_shard = "router")]
#[cfg(test)]
mod tests {
    use crate::crypto::digest::Sha256;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use base64::Engine;
    use bytes::Bytes;
    use std::sync::Arc;
    use uuid::Uuid;

    use crate::api::handlers::test_db_helpers as tdh;
    use crate::api::SharedState;
    use crate::services::auth_service::AuthService;

    const OBJECT: &[u8] = b"git-lfs object bytes for #4570";
    const HOST: &str = "lfs.example.test";

    struct Rig {
        pool: sqlx::PgPool,
        state: SharedState,
        repo_id: Uuid,
        repo_key: String,
        oid: String,
        reader: Uuid,
        reader_name: String,
        outsider: Uuid,
        outsider_name: String,
    }

    impl Rig {
        async fn new(pool: sqlx::PgPool) -> Self {
            let (repo_id, repo_key, dir) = tdh::create_repo(&pool, "local", "gitlfs").await;
            let (reader, reader_name) = tdh::create_user(&pool).await;
            let (outsider, outsider_name) = tdh::create_user(&pool).await;
            tdh::grant_repo_role(&pool, repo_id, reader, "reader").await;
            let state = tdh::build_state(pool.clone(), dir.to_str().expect("utf8"));

            let oid = hex::encode(Sha256::digest(OBJECT));
            let info = tdh::make_repo_info(repo_id, &repo_key, &dir, "local", None);
            tdh::seed_artifact_with_checksum(
                &state,
                &pool,
                &info,
                &format!("gitlfs/{}/{}", &oid[..2], oid),
                &format!("lfs/objects/{}/{}", &oid[..2], oid),
                &oid,
                "",
                "application/octet-stream",
                Bytes::from_static(OBJECT),
                reader,
                &oid,
            )
            .await;
            Self {
                pool,
                state,
                repo_id,
                repo_key,
                oid,
                reader,
                reader_name,
                outsider,
                outsider_name,
            }
        }

        /// `Basic user:<api token>`, the credential git-lfs sends from a
        /// credential helper (pip-netrc / Artifactory style).
        async fn basic(&self, user: Uuid, username: &str) -> String {
            let (token, _) =
                AuthService::new(self.pool.clone(), Arc::new(self.state.config.clone()))
                    .generate_api_token(user, "lfs-4570", vec!["read:artifacts".to_string()], None)
                    .await
                    .expect("mint API token");
            let creds =
                base64::engine::general_purpose::STANDARD.encode(format!("{username}:{token}"));
            format!("Basic {creds}")
        }

        async fn batch_download(
            &self,
            authorization: Option<&str>,
        ) -> (StatusCode, serde_json::Value) {
            let app = crate::api::routes::create_router(self.state.clone());
            let body = serde_json::json!({
                "operation": "download",
                "transfers": ["basic"],
                "objects": [{"oid": self.oid, "size": OBJECT.len()}],
            });
            let mut req = Request::builder()
                .method("POST")
                .uri(format!("/lfs/{}/objects/batch", self.repo_key))
                .header("host", HOST)
                .header("accept", "application/vnd.git-lfs+json")
                .header("content-type", "application/vnd.git-lfs+json");
            if let Some(a) = authorization {
                req = req.header("authorization", a);
            }
            let req = req.body(Body::from(body.to_string())).expect("request");
            let (status, bytes) = tdh::send(app, req).await;
            let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
            (status, json)
        }

        /// Follow a download action the way git-lfs does: GET the href with
        /// exactly the action's headers and nothing else.
        async fn follow(&self, action: &serde_json::Value) -> (StatusCode, Bytes) {
            let href = action["href"].as_str().expect("href");
            let path = href
                .split_once(HOST)
                .map(|(_, p)| p.to_string())
                .unwrap_or_else(|| panic!("href {href} names the request host"));
            let mut req = Request::builder()
                .method("GET")
                .uri(path)
                .header("host", HOST);
            if let Some(headers) = action["header"].as_object() {
                for (name, value) in headers {
                    req = req.header(name.as_str(), value.as_str().expect("header value"));
                }
            }
            let app = crate::api::routes::create_router(self.state.clone());
            tdh::send(app, req.body(Body::empty()).expect("request")).await
        }

        async fn teardown(self) {
            tdh::cleanup(&self.pool, self.repo_id, self.reader).await;
            tdh::cleanup_user(&self.pool, self.outsider).await;
        }
    }

    /// The reported bug: a reader's batch download action is marked
    /// `authenticated: true`, so git-lfs follows it with the action's headers
    /// only; they must authorize the object GET.
    #[tokio::test]
    async fn reader_can_follow_the_download_action_on_a_private_repo_4570() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let rig = Rig::new(pool).await;
        let auth = rig.basic(rig.reader, &rig.reader_name).await;

        let (status, json) = rig.batch_download(Some(&auth)).await;
        assert_eq!(status, StatusCode::OK, "{json}");
        let object = &json["objects"][0];
        let action = &object["actions"]["download"];
        assert!(
            action.is_object(),
            "reader must get a download action: {json}"
        );
        if object["authenticated"] == serde_json::json!(true) {
            assert!(
                action["header"]["Authorization"].is_string(),
                "an action marked authenticated must carry the credentials the object GET \
                 needs: {object}"
            );
        }
        let (status, bytes) = rig.follow(action).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "git-lfs follows the action with its headers only; the GET must succeed: {}",
            String::from_utf8_lossy(&bytes)
        );
        assert_eq!(bytes.as_ref(), OBJECT);
        rig.teardown().await;
    }

    /// Anonymous callers and users without a grant get no download action on a
    /// private repository.
    #[tokio::test]
    async fn anonymous_and_grantless_callers_get_no_download_action_4570() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let rig = Rig::new(pool).await;

        let (status, json) = rig.batch_download(None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "anonymous: {json}");

        let outsider = rig.basic(rig.outsider, &rig.outsider_name).await;
        let (status, json) = rig.batch_download(Some(&outsider)).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "no grant: {json}");
        assert!(json.get("objects").is_none(), "no grant: {json}");

        // The object itself stays closed to both.
        let href = serde_json::json!({
            "href": format!("https://{HOST}/lfs/{}/objects/{}", rig.repo_key, rig.oid),
            "header": {},
        });
        let (status, _) = rig.follow(&href).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "anonymous object GET");
        let with_outsider = serde_json::json!({
            "href": href["href"],
            "header": {"Authorization": outsider},
        });
        let (status, _) = rig.follow(&with_outsider).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "grant-less object GET");
        rig.teardown().await;
    }
}
