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
use serde::Deserialize;
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
fn reqwest_to_axum(resp: reqwest::Response) -> Result<Response> {
    let status = axum::http::StatusCode::from_u16(resp.status().as_u16())
        .unwrap_or(axum::http::StatusCode::INTERNAL_SERVER_ERROR);
    let content_type = resp.headers().get("content-type").cloned();
    // Forward the upstream content-length when present; omit it for chunked
    // upstreams (Body::from_stream yields a chunked response) rather than
    // fabricate one.
    let content_length = resp.headers().get("content-length").cloned();

    let mut builder = Response::builder().status(status);
    if let Some(ct) = content_type {
        builder = builder.header("content-type", ct);
    }
    if let Some(cl) = content_length {
        builder = builder.header("content-length", cl);
    }
    builder
        .body(Body::from_stream(resp.bytes_stream()))
        .map_err(|e| AppError::Internal(format!("Failed to build response: {e}")))
}

/// Shared proxy dispatch for all four verbs. Validates the sub-path, resolves
/// the decrypted remote URL + API key, forwards the request to the remote
/// instance and streams the response back. `body` is `Some` only for verbs
/// that carry a request body (POST/PUT); it is attached zero-copy via
/// [`reqwest::Body::from`] with a JSON content-type. The proxy client sets a
/// connect/read timeout so an endless upstream cannot pin a worker task.
async fn send_proxy_request(
    state: &SharedState,
    auth: &AuthExtension,
    id: Uuid,
    path: &str,
    method: reqwest::Method,
    body: Option<axum::body::Bytes>,
) -> Result<Response> {
    validate_proxy_path(path)?;
    let (url, api_key) = RemoteInstanceService::get_decrypted(&state.db, id, auth.user_id).await?;
    let target = build_target_url(&url, path);

    let mut req = crate::services::http_client::proxy_client()
        .request(method, &target)
        .bearer_auth(&api_key);
    if let Some(body) = body {
        req = req
            .header("content-type", "application/json")
            .body(reqwest::Body::from(body));
    }

    let resp = req
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("Proxy request failed: {e}")))?;

    reqwest_to_axum(resp)
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

    #[tokio::test]
    async fn test_reqwest_to_axum_forwards_status_and_content_type() {
        let resp = mock_reqwest_response(201, Some("application/json"), b"{\"ok\":true}".to_vec());
        let axum_resp = reqwest_to_axum(resp).expect("conversion should succeed");

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
        let axum_resp = reqwest_to_axum(resp).expect("conversion should succeed");

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
        let axum_resp = reqwest_to_axum(resp).expect("conversion should succeed");

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
}
