//! `GET/PUT/DELETE /api/v1/repositories/{key}/proxy-cache-cap` (#4660): the
//! byte cap on a Remote repository's proxy cache, and its current usage.
//!
//! Mounted on the `/repositories` nest from `routes.rs`; the enforcement lives
//! in [`crate::services::proxy_cache_cap`].

use axum::{
    extract::{Path, State},
    routing::get,
    Extension, Json, Router,
};
use serde::{Deserialize, Serialize};
use utoipa::{OpenApi, ToSchema};

use crate::api::handlers::repositories::{
    require_repo_admin, require_repo_write_access, require_visible,
};
use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::error::{AppError, Result};
use crate::models::repository::{Repository, RepositoryType};
use crate::services::proxy_cache_cap::{self, CacheUsage, AT_CAP_BEHAVIOUR};
use crate::services::repository_service::RepositoryService;

pub fn repo_router() -> Router<SharedState> {
    Router::new().route(
        "/:key/proxy-cache-cap",
        get(get_proxy_cache_cap)
            .put(set_proxy_cache_cap)
            .delete(delete_proxy_cache_cap),
    )
}

/// Body of `PUT .../proxy-cache-cap`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct SetProxyCacheCapRequest {
    /// The most bytes the repository's proxy cache may hold. Must be positive;
    /// remove the cap with `DELETE`.
    pub cap_bytes: i64,
}

/// A Remote repository's proxy-cache cap and current usage.
#[derive(Debug, Serialize, ToSchema)]
pub struct ProxyCacheCapResponse {
    pub repository_key: String,
    /// The cap in bytes, or `null` when the cache is uncapped.
    pub cap_bytes: Option<i64>,
    /// What happens when a fill takes the cache over the cap: `evict_lru`
    /// (least recently used entries are evicted until usage is back under the
    /// cap; new fills are refused only while eviction cannot get there).
    pub at_cap: String,
    /// What the cache holds now.
    pub usage: CacheUsage,
    /// The most recent eviction left the cache over its cap, so new fills are
    /// served without being cached (this replica's view).
    pub refusing_fills: bool,
}

/// Resolve `key` to a Remote repository the caller administers. The cap
/// decides what the cache keeps, the same tier as the upstream filter and the
/// cache TTL, so reading and changing it both need the repository `admin`
/// action.
async fn cap_repo(
    state: &SharedState,
    auth: Option<AuthExtension>,
    key: &str,
    write: bool,
) -> Result<Repository> {
    let auth = auth.ok_or_else(|| AppError::Authentication("Authentication required".into()))?;
    auth.require_scope(if write {
        "write:repositories"
    } else {
        "read:repositories"
    })?;
    let service = RepositoryService::new(state.db.clone());
    let repo = service.get_by_key(key).await?;
    // #5610: a caller who cannot read the repository (no grant on a private
    // one, or a token whose repository list leaves it out) gets the
    // unknown-key 404 before the token-scope 403, the wrong-type 400 or the
    // admin 403 below, any of which would confirm that the key exists and
    // whether it is a Remote.
    require_visible(&repo, &Some(auth.clone()), &service).await?;
    if !auth.can_access_repo(repo.id) {
        return Err(AppError::Authorization(
            "Token does not have access to this repository".to_string(),
        ));
    }
    if repo.repo_type != RepositoryType::Remote {
        return Err(AppError::Validation(
            "A proxy-cache cap applies to remote repositories only".to_string(),
        ));
    }
    if write {
        require_repo_write_access(&auth, &repo, &service).await?;
    }
    require_repo_admin(&auth, repo.id, &state.permission_service).await?;
    Ok(repo)
}

async fn response(state: &SharedState, repo: &Repository) -> Result<ProxyCacheCapResponse> {
    let cap_bytes = proxy_cache_cap::load_cap(&state.db, repo.id).await?;
    let usage = proxy_cache_cap::usage(&state.db, repo.id).await?;
    let refusing_fills = match state.proxy_service.as_ref() {
        Some(proxy) => !proxy.cache_cap().admits_fills(repo.id).await,
        None => false,
    };
    Ok(ProxyCacheCapResponse {
        repository_key: repo.key.clone(),
        cap_bytes,
        at_cap: AT_CAP_BEHAVIOUR.to_string(),
        usage,
        refusing_fills,
    })
}

/// Get the proxy-cache cap and usage of a remote repository
#[utoipa::path(
    get,
    path = "/{key}/proxy-cache-cap",
    context_path = "/api/v1/repositories",
    tag = "repositories",
    params(("key" = String, Path, description = "Repository key")),
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Cap and usage", body = ProxyCacheCapResponse),
        (status = 400, description = "Repository is not a remote repository"),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Repository admin required"),
        (status = 404, description = "Repository not found"),
    )
)]
pub async fn get_proxy_cache_cap(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(key): Path<String>,
) -> Result<Json<ProxyCacheCapResponse>> {
    let repo = cap_repo(&state, auth, &key, false).await?;
    Ok(Json(response(&state, &repo).await?))
}

/// Set the proxy-cache cap of a remote repository
///
/// Caps the bytes the repository's proxy cache holds. After every cache fill
/// the least recently used entries (by last serve or last write) are evicted
/// until usage is at or under the cap, so usage can exceed it briefly by the
/// fill that just committed. An object larger than the cap is served without
/// being cached. If eviction cannot get under the cap (storage refuses the
/// deletes), new fills are served without being cached until it can. Setting
/// a cap below current usage evicts at once. Evicted entries keep their
/// download history.
#[utoipa::path(
    put,
    path = "/{key}/proxy-cache-cap",
    context_path = "/api/v1/repositories",
    tag = "repositories",
    params(("key" = String, Path, description = "Repository key")),
    request_body = SetProxyCacheCapRequest,
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Cap saved; usage after the eviction it triggered", body = ProxyCacheCapResponse),
        (status = 400, description = "cap_bytes is not positive, or not a remote repository"),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Repository admin required"),
        (status = 404, description = "Repository not found"),
    )
)]
pub async fn set_proxy_cache_cap(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(key): Path<String>,
    Json(payload): Json<SetProxyCacheCapRequest>,
) -> Result<Json<ProxyCacheCapResponse>> {
    let repo = cap_repo(&state, auth, &key, true).await?;
    proxy_cache_cap::save_cap(&state.db, repo.id, Some(payload.cap_bytes)).await?;
    if let Some(proxy) = state.proxy_service.as_ref() {
        let cap = proxy.cache_cap();
        cap.invalidate(repo.id).await;
        // Apply a cap below current usage now rather than at the next fill.
        cap.enforce(repo.id, payload.cap_bytes).await?;
    }
    Ok(Json(response(&state, &repo).await?))
}

/// Remove the proxy-cache cap of a remote repository
#[utoipa::path(
    delete,
    path = "/{key}/proxy-cache-cap",
    context_path = "/api/v1/repositories",
    tag = "repositories",
    params(("key" = String, Path, description = "Repository key")),
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Cap removed", body = ProxyCacheCapResponse),
        (status = 400, description = "Repository is not a remote repository"),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Repository admin required"),
        (status = 404, description = "Repository not found"),
    )
)]
pub async fn delete_proxy_cache_cap(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(key): Path<String>,
) -> Result<Json<ProxyCacheCapResponse>> {
    let repo = cap_repo(&state, auth, &key, true).await?;
    proxy_cache_cap::save_cap(&state.db, repo.id, None).await?;
    if let Some(proxy) = state.proxy_service.as_ref() {
        proxy.cache_cap().invalidate(repo.id).await;
    }
    Ok(Json(response(&state, &repo).await?))
}

#[derive(OpenApi)]
#[openapi(
    paths(get_proxy_cache_cap, set_proxy_cache_cap, delete_proxy_cache_cap),
    components(schemas(SetProxyCacheCapRequest, ProxyCacheCapResponse, CacheUsage))
)]
pub struct ProxyCacheCapApiDoc;

#[cfg(ak_test_shard = "handlers-2")]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::handlers::test_db_helpers as tdh;
    use crate::models::access_scope::AccessScope;
    use axum::http::{HeaderMap, StatusCode};
    use bytes::Bytes;
    use uuid::Uuid;

    type Answer = (StatusCode, Bytes, HeaderMap);

    /// Send `method` to `/{key}/proxy-cache-cap` as `auth` through the real
    /// router, returning status, body and headers.
    async fn call(state: &SharedState, auth: AuthExtension, method: &str, key: &str) -> Answer {
        let router = tdh::router_with_auth(repo_router(), state.clone(), auth);
        let mut b = axum::http::Request::builder()
            .method(method)
            .uri(format!("/{key}/proxy-cache-cap"));
        let body = if method == "PUT" {
            b = b.header("content-type", "application/json");
            r#"{"cap_bytes": 1048576}"#
        } else {
            ""
        };
        let req = b.body(axum::body::Body::from(body)).unwrap();
        tdh::send_with_headers(router, req).await
    }

    fn assert_unknown_key(case: &str, existing: &Answer, missing: &Answer) {
        assert_eq!(existing.0, StatusCode::NOT_FOUND, "{case}: {existing:?}");
        assert_eq!(
            existing, missing,
            "{case}: an existing private key must answer exactly as an unknown key"
        );
        let v: serde_json::Value = serde_json::from_slice(&existing.1).expect("json body");
        assert_eq!(
            v,
            serde_json::json!({"code": "NOT_FOUND", "message": "Repository not found"}),
            "{case}"
        );
    }

    /// #5610: a caller who cannot read a private repository gets, on every
    /// method of `/{key}/proxy-cache-cap`, exactly what an unknown key
    /// answers (status, headers, body), whatever the repository's type: a
    /// logged-in user with no grant, and a token whose repository list leaves
    /// the key out (even the repository owner's). Before the fix a local or
    /// virtual key answered the wrong-type 400, a remote key's `GET` the
    /// admin 403, and the out-of-scope token the token-scope 403. Nothing is
    /// stored by a refused `PUT`.
    #[tokio::test]
    async fn non_reader_gets_the_unknown_key_404_on_every_method_and_type() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (remote_id, remote_key, remote_dir) = tdh::create_repo(&pool, "remote", "npm").await;
        let (local_id, local_key, local_dir) = tdh::create_repo(&pool, "local", "npm").await;
        let (virtual_id, virtual_key, virtual_dir) =
            tdh::create_repo(&pool, "virtual", "npm").await;
        let (stranger, stranger_name) = tdh::create_user(&pool).await;
        let (owner, owner_name) = tdh::create_user(&pool).await;
        for id in [remote_id, local_id, virtual_id] {
            tdh::grant_repo_role(&pool, id, owner, "repository-owner").await;
        }
        let state = tdh::build_state(pool.clone(), &remote_dir.to_string_lossy());
        let unknown = format!("ak5610-unknown-{}", Uuid::new_v4());

        let stranger_auth = tdh::make_auth(stranger, &stranger_name);
        let scoped_elsewhere = AuthExtension {
            is_api_token: true,
            allowed_repo_ids: AccessScope::Restricted(vec![Uuid::new_v4()]),
            ..tdh::make_auth(owner, &owner_name)
        };
        let mut answers = Vec::new();
        for (caller, auth) in [
            ("no grant", stranger_auth),
            ("token scoped elsewhere", scoped_elsewhere),
        ] {
            for key in [&remote_key, &local_key, &virtual_key] {
                for method in ["GET", "PUT", "DELETE"] {
                    let existing = call(&state, auth.clone(), method, key).await;
                    let missing = call(&state, auth.clone(), method, &unknown).await;
                    answers.push((format!("{caller} {method} {key}"), existing, missing));
                }
            }
        }
        let stored = proxy_cache_cap::load_cap(&pool, remote_id).await.unwrap();
        tdh::cleanup_user(&pool, stranger).await;
        tdh::cleanup_user(&pool, owner).await;
        tdh::cleanup_member_repo(&pool, remote_id, &remote_dir).await;
        tdh::cleanup_member_repo(&pool, local_id, &local_dir).await;
        tdh::cleanup_member_repo(&pool, virtual_id, &virtual_dir).await;

        for (case, existing, missing) in &answers {
            assert_unknown_key(case, existing, missing);
        }
        assert_eq!(stored, None, "a refused PUT must not store a cap");
    }

    /// #5610: a caller who CAN read the repository already knows it exists,
    /// so the refusals that follow the visibility check are unchanged: a
    /// reader without `admin` gets the admin 403 on a private remote, and the
    /// wrong-type 400 on a private local key it reads. A global admin and the
    /// repository's owner still read and change the cap.
    #[tokio::test]
    async fn readers_keep_their_refusals_and_admins_succeed() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (remote_id, remote_key, remote_dir) = tdh::create_repo(&pool, "remote", "npm").await;
        let (local_id, local_key, local_dir) = tdh::create_repo(&pool, "local", "npm").await;
        let (reader, reader_name) = tdh::create_user(&pool).await;
        let (owner, owner_name) = tdh::create_user(&pool).await;
        tdh::grant_repo_role(&pool, remote_id, reader, "reader").await;
        tdh::grant_repo_role(&pool, local_id, reader, "reader").await;
        tdh::grant_repo_role(&pool, remote_id, owner, "repository-owner").await;
        let state = tdh::build_state(pool.clone(), &remote_dir.to_string_lossy());
        let reader_auth = tdh::make_auth(reader, &reader_name);

        let reader_get = call(&state, reader_auth.clone(), "GET", &remote_key).await;
        let reader_put = call(&state, reader_auth.clone(), "PUT", &remote_key).await;
        let reader_local = call(&state, reader_auth, "GET", &local_key).await;
        let admin_get = call(
            &state,
            tdh::admin_auth(Uuid::new_v4(), "ak5610-admin"),
            "GET",
            &remote_key,
        )
        .await;
        let owner_auth = tdh::make_auth(owner, &owner_name);
        let owner_put = call(&state, owner_auth.clone(), "PUT", &remote_key).await;
        let owner_delete = call(&state, owner_auth, "DELETE", &remote_key).await;
        tdh::cleanup_user(&pool, reader).await;
        tdh::cleanup_user(&pool, owner).await;
        tdh::cleanup_member_repo(&pool, remote_id, &remote_dir).await;
        tdh::cleanup_member_repo(&pool, local_id, &local_dir).await;

        assert_eq!(reader_get.0, StatusCode::FORBIDDEN, "{reader_get:?}");
        assert!(
            String::from_utf8_lossy(&reader_get.1).contains("Repository admin permission"),
            "{reader_get:?}"
        );
        assert_eq!(reader_put.0, StatusCode::FORBIDDEN, "{reader_put:?}");
        assert_eq!(reader_local.0, StatusCode::BAD_REQUEST, "{reader_local:?}");
        assert_eq!(admin_get.0, StatusCode::OK, "{admin_get:?}");
        let v: serde_json::Value = serde_json::from_slice(&admin_get.1).unwrap();
        assert_eq!(v["repository_key"], remote_key.as_str());
        assert_eq!(owner_put.0, StatusCode::OK, "{owner_put:?}");
        let v: serde_json::Value = serde_json::from_slice(&owner_put.1).unwrap();
        assert_eq!(v["cap_bytes"], 1_048_576);
        assert_eq!(owner_delete.0, StatusCode::OK, "{owner_delete:?}");
        let v: serde_json::Value = serde_json::from_slice(&owner_delete.1).unwrap();
        assert!(v["cap_bytes"].is_null(), "{v}");
    }
}
