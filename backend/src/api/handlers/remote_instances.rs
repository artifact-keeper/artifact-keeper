//! Remote-instance CRUD and proxy handlers.
//!
//! Allows the frontend to manage remote Artifact Keeper instances whose API
//! keys are stored encrypted on the backend, and to proxy requests through
//! the backend so that API keys never leave the server.

use axum::{
    body::Body,
    extract::{Extension, Path, State},
    response::Response,
    routing::{delete, get},
    Json, Router,
};
use bytes::Bytes;
use futures::Stream;
use once_cell::sync::Lazy;
use serde::Deserialize;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use utoipa::{OpenApi, ToSchema};
use uuid::Uuid;

use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::error::{AppError, Result};
use crate::services::remote_instance_service::{RemoteInstanceResponse, RemoteInstanceService};

use crate::api::validation::validate_outbound_url;

/// Default request-body limit (bytes) for the remote-instance proxy surface:
/// 32 MiB. The global body limit is disabled (`routes.rs`), so without a
/// route-scoped limit this management proxy would buffer an unbounded request
/// body. This is a control-plane management surface (allow-listed to `api/` /
/// `health` calls), not a bulk data plane, so a modest ceiling is appropriate.
const DEFAULT_PROXY_BODY_LIMIT_BYTES: usize = 32 * 1024 * 1024;

/// Resolve the request-body limit for the remote-instance proxy nest.
///
/// Defaults to [`DEFAULT_PROXY_BODY_LIMIT_BYTES`] (32 MiB) and is env-tunable
/// via `REMOTE_PROXY_BODY_LIMIT_BYTES` so an operator who genuinely proxies
/// larger management payloads can raise it without a code change (avoids a
/// silent 413 regression).
pub fn proxy_body_limit_bytes() -> usize {
    std::env::var("REMOTE_PROXY_BODY_LIMIT_BYTES")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(DEFAULT_PROXY_BODY_LIMIT_BYTES)
}

/// Default overall (headers + full body transfer) time budget for a single
/// proxied request, in seconds. Distinct from the client's idle read-timeout:
/// the read-timeout only bounds *inactivity*, so a cooperative-slow upstream
/// that dribbles bytes just often enough to reset the idle timer would never be
/// aborted. This absolute deadline bounds the whole relay regardless of per-read
/// activity. Generous by default because the proxy can forward large management
/// payloads; env-tunable via `REMOTE_PROXY_TOTAL_TIMEOUT_SECS` so an operator who
/// proxies genuinely large/slow downloads can raise it.
const DEFAULT_PROXY_TOTAL_TIMEOUT_SECS: u64 = 300;

/// Default cap on concurrent in-flight proxy requests **per user**. Each stalled
/// relay pins a backend task plus an upstream and a downstream socket, so an
/// unbounded number would let a single user exhaust the process file-descriptor
/// limit. A per-user cap keeps one user from starving others. Env-tunable via
/// `REMOTE_PROXY_MAX_INFLIGHT_PER_USER`.
const DEFAULT_PROXY_MAX_INFLIGHT_PER_USER: usize = 16;

/// Resolve the overall per-request time budget for a proxied relay.
fn proxy_total_timeout() -> Duration {
    let secs = std::env::var("REMOTE_PROXY_TOTAL_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(DEFAULT_PROXY_TOTAL_TIMEOUT_SECS);
    Duration::from_secs(secs)
}

/// Resolve the per-user concurrent-proxy cap.
fn proxy_max_inflight_per_user() -> usize {
    std::env::var("REMOTE_PROXY_MAX_INFLIGHT_PER_USER")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(DEFAULT_PROXY_MAX_INFLIGHT_PER_USER)
}

/// Per-user semaphores bounding concurrent in-flight proxy requests. Entries are
/// created lazily on first use; the set of distinct users is bounded, so the map
/// does not grow without limit in practice.
static PROXY_INFLIGHT: Lazy<Mutex<HashMap<Uuid, Arc<Semaphore>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// Try to acquire an in-flight slot for `user_id` from `map`, creating that
/// user's semaphore with `cap` permits on first use. Returns `None` when the
/// user is already at the cap (caller maps that to 429). Split from
/// [`acquire_proxy_permit`] so the capacity logic is unit-testable without
/// touching the process-global map or environment.
fn acquire_proxy_permit_from(
    map: &Mutex<HashMap<Uuid, Arc<Semaphore>>>,
    user_id: Uuid,
    cap: usize,
) -> Option<OwnedSemaphorePermit> {
    let sem = {
        let mut guard = map.lock().unwrap_or_else(|e| e.into_inner());
        guard
            .entry(user_id)
            .or_insert_with(|| Arc::new(Semaphore::new(cap)))
            .clone()
    };
    sem.try_acquire_owned().ok()
}

/// Acquire an in-flight proxy slot for `user_id`, or `None` if the per-user cap
/// is reached. The returned permit must be held for the whole relay (it is moved
/// into the response body so it is released only when streaming finishes or the
/// body is dropped).
fn acquire_proxy_permit(user_id: Uuid) -> Option<OwnedSemaphorePermit> {
    acquire_proxy_permit_from(&PROXY_INFLIGHT, user_id, proxy_max_inflight_per_user())
}

/// Response body wrapper for a proxied relay that (a) enforces an absolute
/// total-time deadline over the whole body transfer — terminating the stream
/// even when the upstream trickles bytes just under the idle read-timeout or
/// stalls entirely (the timer wakes the task at the deadline regardless of
/// upstream activity) — and (b) holds the per-user concurrency permit until the
/// body finishes, so a slot is released only when the relay actually completes.
struct GuardedProxyBody {
    inner: Pin<Box<dyn Stream<Item = reqwest::Result<Bytes>> + Send>>,
    deadline: Pin<Box<tokio::time::Sleep>>,
    // Held for the lifetime of the streamed body; released on drop.
    _permit: OwnedSemaphorePermit,
}

impl Stream for GuardedProxyBody {
    type Item = reqwest::Result<Bytes>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // Check the absolute deadline first so it fires even if `inner` is
        // stalled: polling the Sleep registers its timer waker, which wakes this
        // task at the deadline independent of any upstream chunk arriving.
        if self.deadline.as_mut().poll(cx).is_ready() {
            return Poll::Ready(None);
        }
        self.inner.as_mut().poll_next(cx)
    }
}

/// Build a small static `Response` with the given status and plain-text message.
fn proxy_status_response(status: axum::http::StatusCode, msg: &'static str) -> Response {
    let mut builder = Response::builder()
        .status(status)
        .header("content-type", "text/plain; charset=utf-8");
    if status == axum::http::StatusCode::TOO_MANY_REQUESTS {
        builder = builder.header("retry-after", "1");
    }
    builder
        .body(Body::from(msg))
        .expect("static proxy status response is always valid")
}

/// Build the router for `/api/v1/instances`.
pub fn router() -> Router<SharedState> {
    Router::new()
        .route("/", get(list_instances).post(create_instance))
        .route("/:id", delete(delete_instance))
        // Wildcard proxy: forward any sub-path to the remote instance
        .route(
            "/:id/proxy/*path",
            get(proxy_get)
                .post(proxy_post)
                .put(proxy_put)
                .delete(proxy_delete),
        )
}

// ---------------------------------------------------------------------------
// CRUD
// ---------------------------------------------------------------------------

/// List all remote instances for the authenticated user
#[utoipa::path(
    get,
    path = "",
    context_path = "/api/v1/instances",
    tag = "admin",
    responses(
        (status = 200, description = "List of remote instances", body = Vec<RemoteInstanceResponse>),
    ),
    security(("bearer_auth" = []))
)]
async fn list_instances(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
) -> Result<Json<Vec<RemoteInstanceResponse>>> {
    let instances = RemoteInstanceService::list(&state.db, auth.user_id).await?;
    Ok(Json(instances))
}

#[derive(Debug, Deserialize, ToSchema)]
struct CreateInstanceRequest {
    name: String,
    url: String,
    api_key: String,
}

/// Create a new remote instance
#[utoipa::path(
    post,
    path = "",
    context_path = "/api/v1/instances",
    tag = "admin",
    request_body = CreateInstanceRequest,
    responses(
        (status = 200, description = "Created remote instance", body = RemoteInstanceResponse),
    ),
    security(("bearer_auth" = []))
)]
async fn create_instance(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Json(req): Json<CreateInstanceRequest>,
) -> Result<Json<RemoteInstanceResponse>> {
    // Validate URL to prevent SSRF via the proxy endpoints
    validate_outbound_url(&req.url, "Remote instance URL")?;

    let instance =
        RemoteInstanceService::create(&state.db, auth.user_id, &req.name, &req.url, &req.api_key)
            .await?;
    Ok(Json(instance))
}

/// Delete a remote instance
#[utoipa::path(
    delete,
    path = "/{id}",
    context_path = "/api/v1/instances",
    tag = "admin",
    params(
        ("id" = Uuid, Path, description = "Remote instance ID"),
    ),
    responses(
        (status = 200, description = "Instance deleted"),
    ),
    security(("bearer_auth" = []))
)]
async fn delete_instance(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<()> {
    RemoteInstanceService::delete(&state.db, id, auth.user_id).await
}

// ---------------------------------------------------------------------------
// Proxy helpers
// ---------------------------------------------------------------------------

/// Validate that the proxy path is safe and does not contain attempts to
/// escape to arbitrary hosts or internal services.
fn validate_proxy_path(path: &str) -> Result<()> {
    // Reject paths that could manipulate the URL to reach other hosts
    if path.contains("://") || path.starts_with("//") {
        return Err(AppError::Validation(
            "Proxy path must not contain a URL scheme or protocol-relative prefix".into(),
        ));
    }
    // Reject path traversal attempts
    if path.contains("..") {
        return Err(AppError::Validation(
            "Proxy path must not contain path traversal sequences".into(),
        ));
    }
    // Only allow proxying to /api/ paths on the remote instance
    let normalized = path.trim_start_matches('/');
    if !normalized.starts_with("api/") && !normalized.starts_with("health") {
        return Err(AppError::Validation(
            "Proxy path must start with api/ or health".into(),
        ));
    }
    Ok(())
}

/// Build the full target URL on the remote instance.
fn build_target_url(base: &str, path: &str) -> String {
    format!("{}/{}", base.trim_end_matches('/'), path)
}

/// Convert a reqwest response into an axum response, forwarding status and
/// content-type.
///
/// The upstream body is *streamed* straight through to the client via
/// [`Body::from_stream`] rather than being buffered into memory first. This
/// path is a pure pass-through — it performs no checksum verification and no
/// cache-tee, so nothing here needs the whole body resident. Streaming removes
/// the unbounded-memory (OOM) vector for arbitrarily large or endless upstream
/// responses while preserving correctness for any size (large legitimate
/// proxied downloads keep working with no artificial ceiling).
///
/// The stream is wrapped in a [`GuardedProxyBody`] that enforces the overall
/// `deadline` (total-timeout) over the whole body transfer and holds the
/// concurrency `permit` until streaming finishes.
fn reqwest_to_axum(
    resp: reqwest::Response,
    deadline: tokio::time::Instant,
    permit: OwnedSemaphorePermit,
) -> Result<Response> {
    let status = axum::http::StatusCode::from_u16(resp.status().as_u16())
        .unwrap_or(axum::http::StatusCode::INTERNAL_SERVER_ERROR);
    let content_type = resp.headers().get("content-type").cloned();
    // Forward the upstream content-length when present; omit it for chunked
    // upstreams (Body::from_stream yields a chunked response) rather than
    // fabricate one.
    let content_length = resp.headers().get("content-length").cloned();

    let body = GuardedProxyBody {
        inner: Box::pin(resp.bytes_stream()),
        deadline: Box::pin(tokio::time::sleep_until(deadline)),
        _permit: permit,
    };

    let mut builder = Response::builder().status(status);
    if let Some(ct) = content_type {
        builder = builder.header("content-type", ct);
    }
    if let Some(cl) = content_length {
        builder = builder.header("content-length", cl);
    }
    builder
        .body(Body::from_stream(body))
        .map_err(|e| AppError::Internal(format!("Failed to build response: {e}")))
}

/// Shared proxy dispatch for all four verbs. Validates the sub-path, resolves
/// the decrypted remote URL + API key, forwards the request to the remote
/// instance and streams the response back. `body` is `Some` only for verbs
/// that carry a request body (POST/PUT); it is attached zero-copy via
/// [`reqwest::Body::from`] with a JSON content-type.
///
/// Three layers bound resource use so a hostile/slow upstream cannot exhaust the
/// backend: the proxy client's idle connect/read timeout (bounds inactivity), an
/// overall total-time budget applied to both the header phase and the streamed
/// body via [`GuardedProxyBody`] (bounds a cooperative trickle that never idles),
/// and a per-user concurrency cap (bounds file-descriptor/socket exhaustion;
/// over the cap → 429).
async fn send_proxy_request(
    state: &SharedState,
    auth: &AuthExtension,
    id: Uuid,
    path: &str,
    method: reqwest::Method,
    body: Option<axum::body::Bytes>,
) -> Result<Response> {
    validate_proxy_path(path)?;

    // Bound concurrent in-flight proxy relays per user. The permit is held for
    // the whole relay (moved into the response body below) and released only
    // when streaming completes or the body is dropped.
    let permit = match acquire_proxy_permit(auth.user_id) {
        Some(permit) => permit,
        None => {
            return Ok(proxy_status_response(
                axum::http::StatusCode::TOO_MANY_REQUESTS,
                "Too many concurrent proxy requests for this user; retry shortly",
            ));
        }
    };

    let (url, api_key) = RemoteInstanceService::get_decrypted(&state.db, id, auth.user_id).await?;
    let target = build_target_url(&url, path);

    // Absolute deadline for the entire relay (headers + full body transfer).
    let deadline = tokio::time::Instant::now() + proxy_total_timeout();

    let mut req = crate::services::http_client::proxy_client()
        .request(method, &target)
        .bearer_auth(&api_key);
    if let Some(body) = body {
        req = req
            .header("content-type", "application/json")
            .body(reqwest::Body::from(body));
    }

    // Bound the header/connect phase by the same total budget; the body phase is
    // bounded by GuardedProxyBody using the shared deadline.
    let resp = match tokio::time::timeout_at(deadline, req.send()).await {
        Ok(Ok(resp)) => resp,
        Ok(Err(e)) => return Err(AppError::Internal(format!("Proxy request failed: {e}"))),
        Err(_elapsed) => {
            return Ok(proxy_status_response(
                axum::http::StatusCode::GATEWAY_TIMEOUT,
                "Upstream proxy request exceeded the total time budget",
            ));
        }
    };

    reqwest_to_axum(resp, deadline, permit)
}

// ---------------------------------------------------------------------------
// Proxy handlers
// ---------------------------------------------------------------------------

/// Proxy a GET request to a remote instance
#[utoipa::path(
    get,
    path = "/{id}/proxy/{path}",
    context_path = "/api/v1/instances",
    tag = "admin",
    params(
        ("id" = Uuid, Path, description = "Remote instance ID"),
        ("path" = String, Path, description = "Sub-path to proxy"),
    ),
    responses(
        (status = 200, description = "Proxied response"),
    ),
    security(("bearer_auth" = []))
)]
async fn proxy_get(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path((id, path)): Path<(Uuid, String)>,
) -> Result<Response> {
    send_proxy_request(&state, &auth, id, &path, reqwest::Method::GET, None).await
}

/// Proxy a POST request to a remote instance
#[utoipa::path(
    post,
    path = "/{id}/proxy/{path}",
    context_path = "/api/v1/instances",
    tag = "admin",
    params(
        ("id" = Uuid, Path, description = "Remote instance ID"),
        ("path" = String, Path, description = "Sub-path to proxy"),
    ),
    request_body(content = inline(String), content_type = "application/octet-stream"),
    responses(
        (status = 200, description = "Proxied response"),
    ),
    security(("bearer_auth" = []))
)]
async fn proxy_post(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path((id, path)): Path<(Uuid, String)>,
    body: axum::body::Bytes,
) -> Result<Response> {
    send_proxy_request(&state, &auth, id, &path, reqwest::Method::POST, Some(body)).await
}

/// Proxy a PUT request to a remote instance
#[utoipa::path(
    put,
    path = "/{id}/proxy/{path}",
    context_path = "/api/v1/instances",
    tag = "admin",
    params(
        ("id" = Uuid, Path, description = "Remote instance ID"),
        ("path" = String, Path, description = "Sub-path to proxy"),
    ),
    request_body(content = inline(String), content_type = "application/octet-stream"),
    responses(
        (status = 200, description = "Proxied response"),
    ),
    security(("bearer_auth" = []))
)]
async fn proxy_put(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path((id, path)): Path<(Uuid, String)>,
    body: axum::body::Bytes,
) -> Result<Response> {
    send_proxy_request(&state, &auth, id, &path, reqwest::Method::PUT, Some(body)).await
}

/// Proxy a DELETE request to a remote instance
#[utoipa::path(
    delete,
    path = "/{id}/proxy/{path}",
    context_path = "/api/v1/instances",
    tag = "admin",
    params(
        ("id" = Uuid, Path, description = "Remote instance ID"),
        ("path" = String, Path, description = "Sub-path to proxy"),
    ),
    responses(
        (status = 200, description = "Proxied response"),
    ),
    security(("bearer_auth" = []))
)]
async fn proxy_delete(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path((id, path)): Path<(Uuid, String)>,
) -> Result<Response> {
    send_proxy_request(&state, &auth, id, &path, reqwest::Method::DELETE, None).await
}

#[derive(OpenApi)]
#[openapi(
    paths(
        list_instances,
        create_instance,
        delete_instance,
        proxy_get,
        proxy_post,
        proxy_put,
        proxy_delete,
    ),
    components(schemas(CreateInstanceRequest, RemoteInstanceResponse,))
)]
pub struct RemoteInstancesApiDoc;

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;

    // -----------------------------------------------------------------------
    // build_target_url
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_target_url_basic() {
        let url = build_target_url("http://example.com", "api/v1/packages");
        assert_eq!(url, "http://example.com/api/v1/packages");
    }

    #[test]
    fn test_build_target_url_trailing_slash_removed() {
        let url = build_target_url("http://example.com/", "api/v1/packages");
        assert_eq!(url, "http://example.com/api/v1/packages");
    }

    #[test]
    fn test_build_target_url_multiple_trailing_slashes() {
        let url = build_target_url("http://example.com///", "api/v1");
        // trim_end_matches('/') removes all trailing slashes
        assert_eq!(url, "http://example.com/api/v1");
    }

    #[test]
    fn test_build_target_url_no_trailing_slash() {
        let url = build_target_url("http://example.com", "health");
        assert_eq!(url, "http://example.com/health");
    }

    #[test]
    fn test_build_target_url_with_port() {
        let url = build_target_url("http://localhost:8080", "api/v1/repos");
        assert_eq!(url, "http://localhost:8080/api/v1/repos");
    }

    #[test]
    fn test_build_target_url_with_port_trailing_slash() {
        let url = build_target_url("http://localhost:8080/", "api/v1/repos");
        assert_eq!(url, "http://localhost:8080/api/v1/repos");
    }

    #[test]
    fn test_build_target_url_empty_path() {
        let url = build_target_url("http://example.com", "");
        assert_eq!(url, "http://example.com/");
    }

    #[test]
    fn test_build_target_url_with_base_path() {
        let url = build_target_url("http://example.com/prefix", "api/v1/data");
        assert_eq!(url, "http://example.com/prefix/api/v1/data");
    }

    #[test]
    fn test_build_target_url_with_base_path_trailing_slash() {
        let url = build_target_url("http://example.com/prefix/", "api/v1/data");
        assert_eq!(url, "http://example.com/prefix/api/v1/data");
    }

    #[test]
    fn test_build_target_url_https() {
        let url = build_target_url("https://registry.example.com", "api/v1/artifacts");
        assert_eq!(url, "https://registry.example.com/api/v1/artifacts");
    }

    // -----------------------------------------------------------------------
    // CreateInstanceRequest deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_create_instance_request_deserialize() {
        let json = serde_json::json!({
            "name": "production-registry",
            "url": "https://registry.prod.example.com",
            "api_key": "secret-api-key-123"
        });
        let req: CreateInstanceRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.name, "production-registry");
        assert_eq!(req.url, "https://registry.prod.example.com");
        assert_eq!(req.api_key, "secret-api-key-123");
    }

    #[test]
    fn test_create_instance_request_missing_name_fails() {
        let json = serde_json::json!({
            "url": "http://example.com",
            "api_key": "key"
        });
        let result: std::result::Result<CreateInstanceRequest, _> = serde_json::from_value(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_create_instance_request_missing_url_fails() {
        let json = serde_json::json!({
            "name": "test",
            "api_key": "key"
        });
        let result: std::result::Result<CreateInstanceRequest, _> = serde_json::from_value(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_create_instance_request_missing_api_key_fails() {
        let json = serde_json::json!({
            "name": "test",
            "url": "http://example.com"
        });
        let result: std::result::Result<CreateInstanceRequest, _> = serde_json::from_value(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_create_instance_request_empty_strings() {
        let json = serde_json::json!({
            "name": "",
            "url": "",
            "api_key": ""
        });
        // Should succeed at deserialization level (validation is handled elsewhere)
        let req: CreateInstanceRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.name, "");
        assert_eq!(req.url, "");
        assert_eq!(req.api_key, "");
    }

    #[test]
    fn test_create_instance_request_special_chars_in_name() {
        let json = serde_json::json!({
            "name": "My Registry (Production) - v2",
            "url": "https://registry.example.com",
            "api_key": "key-with-dashes_and_underscores"
        });
        let req: CreateInstanceRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.name, "My Registry (Production) - v2");
    }

    // -----------------------------------------------------------------------
    // Edge cases for build_target_url used by proxy handlers
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_target_url_deeply_nested_path() {
        let url = build_target_url(
            "http://registry.internal",
            "api/v1/repos/my-repo/packages/my-pkg/versions/1.0.0",
        );
        assert_eq!(
            url,
            "http://registry.internal/api/v1/repos/my-repo/packages/my-pkg/versions/1.0.0"
        );
    }

    #[test]
    fn test_build_target_url_with_query_in_path() {
        // The path could include query strings since it comes from the wildcard
        let url = build_target_url("http://example.com", "api/v1/search?q=hello&page=1");
        assert_eq!(url, "http://example.com/api/v1/search?q=hello&page=1");
    }

    #[test]
    fn test_build_target_url_preserves_path_slashes() {
        let url = build_target_url("http://example.com", "a/b/c/d/e");
        assert_eq!(url, "http://example.com/a/b/c/d/e");
    }

    // -----------------------------------------------------------------------
    // reqwest_to_axum — streaming pass-through
    // -----------------------------------------------------------------------

    /// Build a mock `reqwest::Response` from an in-memory `http::Response`
    /// (no network), so the conversion can be exercised offline.
    fn mock_reqwest_response(
        status: u16,
        content_type: Option<&str>,
        body: Vec<u8>,
    ) -> reqwest::Response {
        let mut builder = http::response::Builder::new().status(status);
        if let Some(ct) = content_type {
            builder = builder.header("content-type", ct);
        }
        builder = builder.header("content-length", body.len().to_string());
        reqwest::Response::from(builder.body(body).unwrap())
    }

    /// A far-future deadline and a fresh permit for exercising `reqwest_to_axum`
    /// without a total-timeout firing. Must be called inside a tokio runtime.
    fn test_deadline_and_permit() -> (tokio::time::Instant, OwnedSemaphorePermit) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
        let permit = Arc::new(Semaphore::new(1))
            .try_acquire_owned()
            .expect("permit available");
        (deadline, permit)
    }

    #[tokio::test]
    async fn test_reqwest_to_axum_forwards_status_and_content_type() {
        let resp = mock_reqwest_response(201, Some("application/json"), b"{\"ok\":true}".to_vec());
        let (deadline, permit) = test_deadline_and_permit();
        let axum_resp = reqwest_to_axum(resp, deadline, permit).expect("conversion should succeed");

        assert_eq!(axum_resp.status().as_u16(), 201);
        assert_eq!(
            axum_resp
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok()),
            Some("application/json")
        );

        // Test-only: drain the streamed body to assert its full contents.
        #[allow(clippy::disallowed_methods)]
        let bytes = axum::body::to_bytes(axum_resp.into_body(), usize::MAX)
            .await
            .expect("body readable");
        assert_eq!(&bytes[..], b"{\"ok\":true}");
    }

    #[tokio::test]
    async fn test_reqwest_to_axum_forwards_error_status_without_content_type() {
        let resp = mock_reqwest_response(502, None, b"upstream error".to_vec());
        let (deadline, permit) = test_deadline_and_permit();
        let axum_resp = reqwest_to_axum(resp, deadline, permit).expect("conversion should succeed");

        assert_eq!(axum_resp.status().as_u16(), 502);
        assert!(axum_resp.headers().get("content-type").is_none());
    }

    #[tokio::test]
    async fn test_reqwest_to_axum_streams_large_body_without_buffering() {
        // A large (16 MiB) upstream body must pass through intact. The handler
        // wraps it in a streaming body (`Body::from_stream`) rather than a
        // pre-buffered `Bytes`, so it never holds the whole payload before the
        // client starts receiving it.
        let size = 16 * 1024 * 1024;
        let payload = vec![0xABu8; size];
        let resp = mock_reqwest_response(200, Some("application/octet-stream"), payload.clone());
        let (deadline, permit) = test_deadline_and_permit();
        let axum_resp = reqwest_to_axum(resp, deadline, permit).expect("conversion should succeed");

        assert_eq!(axum_resp.status().as_u16(), 200);
        // content-length forwarded from the upstream when present.
        assert_eq!(
            axum_resp
                .headers()
                .get("content-length")
                .and_then(|v| v.to_str().ok()),
            Some(size.to_string().as_str())
        );

        // Test-only: drain the streamed body to assert its full contents.
        #[allow(clippy::disallowed_methods)]
        let bytes = axum::body::to_bytes(axum_resp.into_body(), usize::MAX)
            .await
            .expect("body readable");
        assert_eq!(bytes.len(), size);
        assert_eq!(&bytes[..], &payload[..]);
    }

    // -----------------------------------------------------------------------
    // proxy_body_limit_bytes — env-tunable request-body ceiling
    // -----------------------------------------------------------------------

    // Default + env override are checked in one test: both mutate the same
    // process-global env var, so keeping them serial avoids a parallel-run race.
    #[test]
    fn test_proxy_body_limit_default_and_env_override() {
        let saved = std::env::var("REMOTE_PROXY_BODY_LIMIT_BYTES").ok();

        // Default (no override) is 32 MiB.
        std::env::remove_var("REMOTE_PROXY_BODY_LIMIT_BYTES");
        assert_eq!(proxy_body_limit_bytes(), 32 * 1024 * 1024);

        // A valid numeric override is honored.
        std::env::set_var("REMOTE_PROXY_BODY_LIMIT_BYTES", "1048576");
        assert_eq!(proxy_body_limit_bytes(), 1_048_576);

        // A non-numeric value falls back to the default.
        std::env::set_var("REMOTE_PROXY_BODY_LIMIT_BYTES", "not-a-number");
        assert_eq!(proxy_body_limit_bytes(), 32 * 1024 * 1024);

        match saved {
            Some(v) => std::env::set_var("REMOTE_PROXY_BODY_LIMIT_BYTES", v),
            None => std::env::remove_var("REMOTE_PROXY_BODY_LIMIT_BYTES"),
        }
    }

    // -----------------------------------------------------------------------
    // total-timeout + per-user concurrency knobs
    // -----------------------------------------------------------------------

    #[test]
    fn test_proxy_total_timeout_default_and_override() {
        let saved = std::env::var("REMOTE_PROXY_TOTAL_TIMEOUT_SECS").ok();

        std::env::remove_var("REMOTE_PROXY_TOTAL_TIMEOUT_SECS");
        assert_eq!(proxy_total_timeout(), Duration::from_secs(300));

        std::env::set_var("REMOTE_PROXY_TOTAL_TIMEOUT_SECS", "15");
        assert_eq!(proxy_total_timeout(), Duration::from_secs(15));

        // Zero / non-numeric fall back to the default (never a 0-length budget).
        std::env::set_var("REMOTE_PROXY_TOTAL_TIMEOUT_SECS", "0");
        assert_eq!(proxy_total_timeout(), Duration::from_secs(300));
        std::env::set_var("REMOTE_PROXY_TOTAL_TIMEOUT_SECS", "nope");
        assert_eq!(proxy_total_timeout(), Duration::from_secs(300));

        match saved {
            Some(v) => std::env::set_var("REMOTE_PROXY_TOTAL_TIMEOUT_SECS", v),
            None => std::env::remove_var("REMOTE_PROXY_TOTAL_TIMEOUT_SECS"),
        }
    }

    #[test]
    fn test_proxy_max_inflight_default_and_override() {
        let saved = std::env::var("REMOTE_PROXY_MAX_INFLIGHT_PER_USER").ok();

        std::env::remove_var("REMOTE_PROXY_MAX_INFLIGHT_PER_USER");
        assert_eq!(proxy_max_inflight_per_user(), 16);

        std::env::set_var("REMOTE_PROXY_MAX_INFLIGHT_PER_USER", "3");
        assert_eq!(proxy_max_inflight_per_user(), 3);

        // Zero / non-numeric fall back to the default (never an unusable 0 cap).
        std::env::set_var("REMOTE_PROXY_MAX_INFLIGHT_PER_USER", "0");
        assert_eq!(proxy_max_inflight_per_user(), 16);
        std::env::set_var("REMOTE_PROXY_MAX_INFLIGHT_PER_USER", "x");
        assert_eq!(proxy_max_inflight_per_user(), 16);

        match saved {
            Some(v) => std::env::set_var("REMOTE_PROXY_MAX_INFLIGHT_PER_USER", v),
            None => std::env::remove_var("REMOTE_PROXY_MAX_INFLIGHT_PER_USER"),
        }
    }

    #[test]
    fn test_proxy_permit_caps_and_releases_per_user() {
        // Uses a local map + explicit cap so it is deterministic and does not
        // touch the process-global state or environment.
        let map = Mutex::new(HashMap::new());
        let user = Uuid::new_v4();

        let p1 = acquire_proxy_permit_from(&map, user, 2);
        let p2 = acquire_proxy_permit_from(&map, user, 2);
        let p3 = acquire_proxy_permit_from(&map, user, 2);
        assert!(
            p1.is_some() && p2.is_some(),
            "up to the cap must be admitted"
        );
        assert!(p3.is_none(), "over the cap must be refused (caller -> 429)");

        // A different user has an independent slot allowance.
        let other = acquire_proxy_permit_from(&map, Uuid::new_v4(), 2);
        assert!(
            other.is_some(),
            "cap is per-user; one user cannot starve another"
        );

        // Releasing a permit frees a slot for the same user.
        drop(p2);
        assert!(
            acquire_proxy_permit_from(&map, user, 2).is_some(),
            "releasing an in-flight slot admits the next request"
        );
    }

    #[tokio::test]
    async fn test_guarded_body_aborts_stalled_stream_at_deadline() {
        // A stream that never yields a chunk (endless/stalled upstream). The
        // absolute deadline must terminate the body rather than hang forever.
        let pending = futures::stream::pending::<reqwest::Result<Bytes>>();
        let permit = Arc::new(Semaphore::new(1))
            .try_acquire_owned()
            .expect("permit available");
        let deadline = tokio::time::Instant::now() + Duration::from_millis(150);
        let body = GuardedProxyBody {
            inner: Box::pin(pending),
            deadline: Box::pin(tokio::time::sleep_until(deadline)),
            _permit: permit,
        };

        let start = tokio::time::Instant::now();
        // Test-only: drain the guarded body; it must end at the deadline.
        #[allow(clippy::disallowed_methods)]
        let bytes = axum::body::to_bytes(Body::from_stream(body), usize::MAX)
            .await
            .expect("guarded body terminates cleanly");
        assert!(bytes.is_empty(), "stalled stream yields no bytes");
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "must abort at the ~150ms deadline, not hang"
        );
    }
}
