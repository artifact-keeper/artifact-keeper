//! WASM plugin protocol proxy handler.
//!
//! Routes HTTP requests to WASM plugins that implement the request-handler
//! interface (v2 WIT). This allows plugins to serve native client protocols
//! like PEP 503 (pip) or repodata (dnf) directly from WASM.

use axum::{
    body::{Body, Bytes},
    extract::{Path, State},
    http::{HeaderMap, Method, Response, StatusCode},
    routing::any,
    Extension, Router,
};

use crate::api::extractors::RequestBaseUrl;
use crate::api::handlers::repositories::require_visible;
use crate::api::middleware::auth::{unauthorized_response, AuthExtension};
use crate::api::SharedState;
use crate::error::AppError;
use crate::services::repository_service::RepositoryService;
use crate::services::wasm_bindings::{WasmHttpRequest, WasmRepoContext};
#[allow(unused_imports)]
use crate::services::wasm_runtime::WasmMetadata;

/// Create the WASM proxy router.
///
/// Mounts at `/ext` and handles `/:format_key/:repo_key/*path`.
pub fn router() -> Router<SharedState> {
    Router::new()
        .route("/:format_key/:repo_key", any(handle_wasm_request))
        .route("/:format_key/:repo_key/", any(handle_wasm_request))
        .route("/:format_key/:repo_key/*path", any(handle_wasm_request))
}

/// Extract a named parameter from the path params list.
fn extract_param<'a>(params: &'a [(String, String)], key: &str) -> &'a str {
    params
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
        .unwrap_or("")
}

/// Normalize a sub-path to always have a leading slash.
fn normalize_path(sub_path: &str) -> String {
    if sub_path.is_empty() {
        "/".to_string()
    } else if sub_path.starts_with('/') {
        sub_path.to_string()
    } else {
        format!("/{}", sub_path)
    }
}

/// Headers the /ext proxy forwards into plugin memory.
///
/// GHSA-9rqp-mgmw-5879: the proxy previously copied ALL client request
/// headers into the WASM request, including `Authorization: Bearer`,
/// `Cookie`, and `Proxy-Authorization` — handing the caller's credentials to
/// plugin code that has no legitimate need for them (and that a malicious or
/// compromised plugin could exfiltrate). Only the benign protocol /
/// content-negotiation headers a protocol plugin legitimately needs are
/// forwarded; credential and hop-by-hop headers are never copied. Header
/// names in a `HeaderMap` are already lowercase, so the allowlist is matched
/// lowercase.
const FORWARDED_HEADER_ALLOWLIST: &[&str] = &[
    "accept",
    "accept-encoding",
    "accept-language",
    "content-length",
    "content-type",
    "host",
    "if-modified-since",
    "if-none-match",
    "if-range",
    "range",
    "user-agent",
];

/// Convert HTTP headers to a list of string pairs, skipping non-UTF-8 values
/// and any header outside [`FORWARDED_HEADER_ALLOWLIST`].
fn headers_to_pairs(headers: &HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .filter(|(k, _)| FORWARDED_HEADER_ALLOWLIST.contains(&k.as_str()))
        .filter_map(|(k, v)| v.to_str().ok().map(|v| (k.to_string(), v.to_string())))
        .collect()
}

/// Check whether a repository's format key matches the expected format key.
/// Returns an error message string if they don't match, or None if they match.
fn check_format_key_match(
    repo_key: &str,
    repo_format_key: Option<&str>,
    expected_format_key: &str,
) -> Option<String> {
    if repo_format_key != Some(expected_format_key) {
        Some(format!(
            "Repository '{}' uses format '{}', not '{}'",
            repo_key,
            repo_format_key.unwrap_or("none"),
            expected_format_key
        ))
    } else {
        None
    }
}

/// Convert raw artifact row data to WasmMetadata.
fn artifact_to_wasm_metadata(
    path: String,
    version: Option<String>,
    content_type: String,
    size_bytes: i64,
    checksum_sha256: String,
) -> WasmMetadata {
    WasmMetadata {
        path,
        version,
        content_type,
        size_bytes: size_bytes as u64,
        checksum_sha256: Some(checksum_sha256),
    }
}

async fn handle_wasm_request(
    State(state): State<SharedState>,
    method: Method,
    headers: HeaderMap,
    base_url: RequestBaseUrl,
    Path(params): Path<Vec<(String, String)>>,
    Extension(auth): Extension<Option<AuthExtension>>,
    body: Bytes,
) -> Result<Response<Body>, Response<Body>> {
    let format_key = extract_param(&params, "format_key");
    let repo_key = extract_param(&params, "repo_key");
    let sub_path = extract_param(&params, "path");
    let request_path = normalize_path(sub_path);

    // 1. Check plugin registry exists
    let registry = state
        .plugin_registry
        .as_ref()
        .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "WASM plugins not enabled"))?;

    // 2. Check plugin exists and supports handle_request
    if !registry.has_handle_request(format_key).await {
        return Err(error_response(
            StatusCode::NOT_FOUND,
            &format!("No protocol handler for format '{}'", format_key),
        ));
    }

    // 3. Look up repo and verify format_key matches
    let repo_service = RepositoryService::new(state.db.clone());
    let repo = repo_service.get_by_key(repo_key).await.map_err(|_| {
        error_response(
            StatusCode::NOT_FOUND,
            &format!("Repository '{}' not found", repo_key),
        )
    })?;

    let repo_format_key = repo_service.get_format_key(repo.id).await.map_err(|_| {
        error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to look up format key",
        )
    })?;

    if let Some(msg) = check_format_key_match(repo_key, repo_format_key.as_deref(), format_key) {
        return Err(error_response(StatusCode::BAD_REQUEST, &msg));
    }

    // 3b. Defense in depth (GHSA-9rqp-mgmw-5879): enforce the canonical
    // visibility gate in the handler itself, not just in
    // `repo_visibility_middleware`. This handler hands the plugin the repo's
    // full artifact metadata, so it must not rely solely on the middleware
    // having resolved the right path segment. Reuse the REST
    // `require_visible` helper rather than open-coding a policy: public repos
    // are open to everyone (including anonymous); private repos require an
    // authenticated caller with admin rights or a role assignment, and
    // repository-scoped API tokens must cover this repo.
    if let Err(e) = require_visible(&repo, &auth, &repo_service).await {
        return Err(visibility_denial_response(&auth, e));
    }

    // 4. Gather artifact metadata from DB
    let artifacts = fetch_repo_artifacts(&state, repo.id).await.map_err(|e| {
        error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("Failed to fetch artifacts: {}", e),
        )
    })?;

    // 5. Build request and context
    let (wasm_request, wasm_context) = build_wasm_request(
        &headers,
        &method,
        base_url.as_str(),
        request_path,
        body,
        format_key,
        repo_key,
    );

    // 6. Execute plugin
    let response = registry
        .execute_handle_request(format_key, &wasm_request, &wasm_context, &artifacts)
        .await
        .map_err(|e| {
            tracing::error!("WASM handle_request error: {}", e);
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("Plugin error: {}", e),
            )
        })?;

    // 7. Convert WASM response to HTTP response
    wasm_response_to_http(response)
}

/// Build the WASM request and repo context from HTTP request components.
fn build_wasm_request(
    headers: &HeaderMap,
    method: &Method,
    request_base_url: &str,
    request_path: String,
    body: Bytes,
    format_key: &str,
    repo_key: &str,
) -> (WasmHttpRequest, WasmRepoContext) {
    let base_url = format!("{}/ext/{}/{}", request_base_url, format_key, repo_key);
    let download_base_url = format!(
        "{}/api/v1/repositories/{}/download",
        request_base_url, repo_key
    );
    let header_pairs = headers_to_pairs(headers);

    let wasm_request = WasmHttpRequest {
        method: method.to_string(),
        path: request_path,
        query: String::new(),
        headers: header_pairs,
        body: body.to_vec(),
    };
    let wasm_context = WasmRepoContext {
        repo_key: repo_key.to_string(),
        base_url,
        download_base_url,
    };
    (wasm_request, wasm_context)
}

/// Convert a WASM HTTP response to an axum HTTP response.
#[allow(clippy::result_large_err)]
fn wasm_response_to_http(
    response: crate::services::wasm_bindings::WasmHttpResponse,
) -> Result<Response<Body>, Response<Body>> {
    let mut builder = Response::builder().status(response.status);
    for (key, value) in &response.headers {
        builder = builder.header(key.as_str(), value.as_str());
    }
    builder
        .body(Body::from(response.body))
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))
}

/// Fetch all non-deleted artifacts for a repository as WasmMetadata.
async fn fetch_repo_artifacts(
    state: &SharedState,
    repo_id: uuid::Uuid,
) -> std::result::Result<Vec<WasmMetadata>, AppError> {
    #[derive(sqlx::FromRow)]
    struct ArtifactRow {
        path: String,
        version: Option<String>,
        content_type: String,
        size_bytes: i64,
        checksum_sha256: String,
    }

    let rows = sqlx::query_as::<_, ArtifactRow>(
        "SELECT path, version, content_type, size_bytes, checksum_sha256 \
         FROM artifacts WHERE repository_id = $1 AND is_deleted = false",
    )
    .bind(repo_id)
    .fetch_all(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(rows
        .into_iter()
        .map(|r| {
            artifact_to_wasm_metadata(
                r.path,
                r.version,
                r.content_type,
                r.size_bytes,
                r.checksum_sha256,
            )
        })
        .collect())
}

/// Map a `require_visible` denial on an /ext request to the same answer the
/// rest of the codebase gives (GHSA-9rqp-mgmw-5879). Anonymous callers get
/// the identical 401 + `WWW-Authenticate` challenge `repo_visibility_middleware`
/// emits, so package clients still retry with credentials; authenticated
/// callers without a grant get the existence-hiding 404, matching both the
/// REST path and the middleware's rule-less private-repo branch. A DB failure
/// inside the access check fails closed with a 500, never open.
fn visibility_denial_response(auth: &Option<AuthExtension>, err: AppError) -> Response<Body> {
    match err {
        AppError::NotFound(msg) => {
            if auth.is_none() {
                unauthorized_response()
            } else {
                error_response(StatusCode::NOT_FOUND, &msg)
            }
        }
        other => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("Repository access check failed: {}", other),
        ),
    }
}

/// Build a JSON error response.
fn error_response(status: StatusCode, message: &str) -> Response<Body> {
    let body = serde_json::json!({
        "code": status.canonical_reason().unwrap_or("ERROR"),
        "message": message,
    });
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap_or_default()))
        .unwrap()
}

#[allow(clippy::disallowed_methods)]
// streaming-invariant: test module exempt — buffering response bodies in test assertions is not an artifact path (#1608)
#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    // -----------------------------------------------------------------------
    // router
    // -----------------------------------------------------------------------

    #[test]
    fn test_router_creates_without_panic() {
        // Verifies the router function constructs all routes successfully.
        // The Router<SharedState> requires state at serve-time, not construction.
        let _r = router();
    }

    // -----------------------------------------------------------------------
    // extract_param
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_param_found() {
        let params = vec![
            ("format_key".to_string(), "pypi-custom".to_string()),
            ("repo_key".to_string(), "my-repo".to_string()),
        ];
        assert_eq!(extract_param(&params, "format_key"), "pypi-custom");
        assert_eq!(extract_param(&params, "repo_key"), "my-repo");
    }

    #[test]
    fn test_extract_param_missing() {
        let params = vec![("format_key".to_string(), "rpm".to_string())];
        assert_eq!(extract_param(&params, "repo_key"), "");
        assert_eq!(extract_param(&params, "path"), "");
    }

    #[test]
    fn test_extract_param_empty_list() {
        let params: Vec<(String, String)> = vec![];
        assert_eq!(extract_param(&params, "anything"), "");
    }

    // -----------------------------------------------------------------------
    // normalize_path
    // -----------------------------------------------------------------------

    #[test]
    fn test_normalize_path_empty() {
        assert_eq!(normalize_path(""), "/");
    }

    #[test]
    fn test_normalize_path_already_slash() {
        assert_eq!(normalize_path("/"), "/");
    }

    #[test]
    fn test_normalize_path_with_leading_slash() {
        assert_eq!(normalize_path("/simple/"), "/simple/");
        assert_eq!(normalize_path("/packages/my-lib"), "/packages/my-lib");
    }

    #[test]
    fn test_normalize_path_without_leading_slash() {
        assert_eq!(normalize_path("simple/"), "/simple/");
        assert_eq!(normalize_path("packages/my-lib"), "/packages/my-lib");
    }

    // -----------------------------------------------------------------------
    // headers_to_pairs
    // -----------------------------------------------------------------------

    #[test]
    fn test_headers_to_pairs_empty() {
        let headers = HeaderMap::new();
        assert!(headers_to_pairs(&headers).is_empty());
    }

    #[test]
    fn test_headers_to_pairs_basic() {
        let mut headers = HeaderMap::new();
        headers.insert("content-type", HeaderValue::from_static("text/html"));
        headers.insert("accept", HeaderValue::from_static("application/json"));
        let pairs = headers_to_pairs(&headers);
        assert_eq!(pairs.len(), 2);
        assert!(pairs
            .iter()
            .any(|(k, v)| k == "content-type" && v == "text/html"));
        assert!(pairs
            .iter()
            .any(|(k, v)| k == "accept" && v == "application/json"));
    }

    // -----------------------------------------------------------------------
    // error_response
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_error_response_not_found() {
        let resp = error_response(StatusCode::NOT_FOUND, "repo not found");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            resp.headers().get("content-type").unwrap(),
            "application/json"
        );
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["code"], "Not Found");
        assert_eq!(json["message"], "repo not found");
    }

    #[tokio::test]
    async fn test_error_response_internal() {
        let resp = error_response(StatusCode::INTERNAL_SERVER_ERROR, "something broke");
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["code"], "Internal Server Error");
        assert_eq!(json["message"], "something broke");
    }

    #[tokio::test]
    async fn test_error_response_bad_request() {
        let resp = error_response(StatusCode::BAD_REQUEST, "wrong format");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["code"], "Bad Request");
        assert_eq!(json["message"], "wrong format");
    }

    // -----------------------------------------------------------------------
    // headers_to_pairs (non-UTF-8 filtering)
    // -----------------------------------------------------------------------

    #[test]
    fn test_headers_to_pairs_skips_non_utf8() {
        let mut headers = HeaderMap::new();
        headers.insert("accept", HeaderValue::from_static("valid"));
        headers.insert(
            "user-agent",
            HeaderValue::from_bytes(&[0xff, 0xfe]).unwrap(),
        );
        let pairs = headers_to_pairs(&headers);
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].0, "accept");
        assert_eq!(pairs[0].1, "valid");
    }

    // -----------------------------------------------------------------------
    // headers_to_pairs credential filtering (GHSA-9rqp-mgmw-5879)
    // -----------------------------------------------------------------------

    #[test]
    fn test_headers_to_pairs_never_forwards_credentials() {
        // GHSA-9rqp-mgmw-5879: before the fix every client header was copied
        // into plugin memory, so a plugin received the caller's
        // `Authorization: Bearer` token (and any cookie / proxy credential).
        // Credential headers must be stripped; benign protocol headers pass.
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            HeaderValue::from_static("Bearer secret-token"),
        );
        headers.insert("cookie", HeaderValue::from_static("session=abc"));
        headers.insert(
            "proxy-authorization",
            HeaderValue::from_static("Basic eA=="),
        );
        headers.insert("x-api-key", HeaderValue::from_static("ak_secret"));
        headers.insert("x-nuget-apikey", HeaderValue::from_static("nuget-secret"));
        headers.insert("accept", HeaderValue::from_static("text/html"));
        headers.insert("user-agent", HeaderValue::from_static("pip/24.0"));
        headers.insert("range", HeaderValue::from_static("bytes=0-1023"));
        let pairs = headers_to_pairs(&headers);
        assert_eq!(
            pairs.len(),
            3,
            "only the benign allowlisted headers may reach the plugin"
        );
        for (name, value) in &pairs {
            assert!(
                FORWARDED_HEADER_ALLOWLIST.contains(&name.as_str()),
                "non-allowlisted header '{}' leaked into the WASM request",
                name
            );
            assert!(
                !value.contains("secret") && !value.contains("session=abc"),
                "credential material leaked into the WASM request"
            );
        }
        assert!(pairs.iter().any(|(k, _)| k == "accept"));
        assert!(pairs.iter().any(|(k, _)| k == "user-agent"));
        assert!(pairs.iter().any(|(k, _)| k == "range"));
    }

    #[test]
    fn test_build_wasm_request_omits_authorization_header() {
        // GHSA-9rqp-mgmw-5879, end-to-end through build_wasm_request: the
        // caller's Authorization header must not be present in the headers
        // the plugin sees.
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            HeaderValue::from_static("Bearer secret-token"),
        );
        headers.insert("accept", HeaderValue::from_static("application/json"));
        let (req, _ctx) = build_wasm_request(
            &headers,
            &Method::GET,
            "http://localhost:8080",
            "/simple/".to_string(),
            Bytes::new(),
            "pypi-custom",
            "my-pypi",
        );
        assert_eq!(req.headers.len(), 1);
        assert_eq!(req.headers[0].0, "accept");
        assert!(!req.headers.iter().any(|(k, _)| k == "authorization"));
    }

    // -----------------------------------------------------------------------
    // visibility_denial_response (GHSA-9rqp-mgmw-5879)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_visibility_denial_anonymous_gets_401_challenge() {
        // Anonymous on an inaccessible repo: the same 401 + WWW-Authenticate
        // challenge repo_visibility_middleware emits, so package clients
        // retry with credentials instead of treating the repo as missing.
        let resp = visibility_denial_response(
            &None,
            AppError::NotFound("Repository 'private' not found".to_string()),
        );
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert!(resp.headers().get("WWW-Authenticate").is_some());
    }

    #[tokio::test]
    async fn test_visibility_denial_authenticated_gets_existence_hiding_404() {
        // Authenticated WITHOUT a grant: existence-hiding 404, matching the
        // REST `require_visible` contract — the caller must not be able to
        // distinguish "private repo I can't see" from "no such repo".
        let auth = Some(AuthExtension {
            user_id: uuid::Uuid::new_v4(),
            username: "alice".to_string(),
            ..Default::default()
        });
        let resp = visibility_denial_response(
            &auth,
            AppError::NotFound("Repository 'private' not found".to_string()),
        );
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_visibility_denial_db_error_fails_closed_500() {
        // A DB failure inside the access check must fail closed (500), never
        // fall through to serving the repo.
        let resp = visibility_denial_response(&None, AppError::Database("down".to_string()));
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    // -----------------------------------------------------------------------
    // check_format_key_match
    // -----------------------------------------------------------------------

    #[test]
    fn test_format_key_match_ok() {
        assert!(check_format_key_match("my-repo", Some("pypi-custom"), "pypi-custom").is_none());
    }

    #[test]
    fn test_format_key_mismatch() {
        let msg = check_format_key_match("my-repo", Some("rpm-custom"), "pypi-custom").unwrap();
        assert!(msg.contains("my-repo"));
        assert!(msg.contains("rpm-custom"));
        assert!(msg.contains("pypi-custom"));
    }

    #[test]
    fn test_format_key_none() {
        let msg = check_format_key_match("my-repo", None, "pypi-custom").unwrap();
        assert!(msg.contains("none"));
        assert!(msg.contains("pypi-custom"));
    }

    // -----------------------------------------------------------------------
    // artifact_to_wasm_metadata
    // -----------------------------------------------------------------------

    #[test]
    fn test_artifact_to_wasm_metadata_basic() {
        let meta = artifact_to_wasm_metadata(
            "pkg/lib-1.0.tar.gz".to_string(),
            Some("1.0".to_string()),
            "application/gzip".to_string(),
            4096,
            "abc123".to_string(),
        );
        assert_eq!(meta.path, "pkg/lib-1.0.tar.gz");
        assert_eq!(meta.version, Some("1.0".to_string()));
        assert_eq!(meta.content_type, "application/gzip");
        assert_eq!(meta.size_bytes, 4096);
        assert_eq!(meta.checksum_sha256, Some("abc123".to_string()));
    }

    #[test]
    fn test_artifact_to_wasm_metadata_no_version() {
        let meta = artifact_to_wasm_metadata(
            "data.bin".to_string(),
            None,
            "application/octet-stream".to_string(),
            0,
            "def456".to_string(),
        );
        assert_eq!(meta.version, None);
        assert_eq!(meta.size_bytes, 0);
        assert_eq!(meta.checksum_sha256, Some("def456".to_string()));
    }

    #[test]
    fn test_artifact_to_wasm_metadata_large_size() {
        let meta = artifact_to_wasm_metadata(
            "big.iso".to_string(),
            Some("22.04".to_string()),
            "application/x-iso9660-image".to_string(),
            4_294_967_296, // > u32::MAX
            "sha".to_string(),
        );
        assert_eq!(meta.size_bytes, 4_294_967_296);
    }

    // -----------------------------------------------------------------------
    // build_wasm_request
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_wasm_request_localhost() {
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("localhost:8080"));
        headers.insert("accept", HeaderValue::from_static("text/html"));
        let (req, ctx) = build_wasm_request(
            &headers,
            &Method::GET,
            "http://localhost:8080",
            "/simple/".to_string(),
            Bytes::new(),
            "pypi-custom",
            "my-pypi",
        );
        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/simple/");
        assert!(req.body.is_empty());
        assert_eq!(req.headers.len(), 2);
        assert_eq!(ctx.repo_key, "my-pypi");
        assert_eq!(
            ctx.base_url,
            "http://localhost:8080/ext/pypi-custom/my-pypi"
        );
        assert_eq!(
            ctx.download_base_url,
            "http://localhost:8080/api/v1/repositories/my-pypi/download"
        );
    }

    #[test]
    fn test_build_wasm_request_uses_supplied_base_url() {
        let mut headers = HeaderMap::new();
        headers.insert("accept", HeaderValue::from_static("application/json"));
        let (req, ctx) = build_wasm_request(
            &headers,
            &Method::POST,
            "https://registry.example.com",
            "/upload".to_string(),
            Bytes::from(vec![0xde, 0xad]),
            "rpm-custom",
            "centos-repo",
        );
        assert_eq!(req.method, "POST");
        assert_eq!(req.body, vec![0xde, 0xad]);
        assert_eq!(req.headers.len(), 1);
        assert_eq!(ctx.repo_key, "centos-repo");
        assert_eq!(
            ctx.base_url,
            "https://registry.example.com/ext/rpm-custom/centos-repo"
        );
        assert_eq!(
            ctx.download_base_url,
            "https://registry.example.com/api/v1/repositories/centos-repo/download"
        );
    }

    #[test]
    fn test_build_wasm_request_uses_fallback_base_url() {
        let headers = HeaderMap::new();
        let (_, ctx) = build_wasm_request(
            &headers,
            &Method::GET,
            "http://localhost",
            "/".to_string(),
            Bytes::new(),
            "fmt",
            "repo",
        );
        assert_eq!(ctx.base_url, "http://localhost/ext/fmt/repo");
    }

    // -----------------------------------------------------------------------
    // wasm_response_to_http
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_wasm_response_to_http_ok() {
        let wasm_resp = crate::services::wasm_bindings::WasmHttpResponse {
            status: 200,
            headers: vec![
                ("content-type".to_string(), "text/html".to_string()),
                ("x-plugin".to_string(), "pypi-custom".to_string()),
            ],
            body: b"<html>index</html>".to_vec(),
        };
        let resp = wasm_response_to_http(wasm_resp).unwrap();
        assert_eq!(resp.status().as_u16(), 200);
        assert_eq!(resp.headers().get("content-type").unwrap(), "text/html");
        assert_eq!(resp.headers().get("x-plugin").unwrap(), "pypi-custom");
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        assert_eq!(body.as_ref(), b"<html>index</html>");
    }

    #[tokio::test]
    async fn test_wasm_response_to_http_empty() {
        let wasm_resp = crate::services::wasm_bindings::WasmHttpResponse {
            status: 404,
            headers: vec![],
            body: vec![],
        };
        let resp = wasm_response_to_http(wasm_resp).unwrap();
        assert_eq!(resp.status().as_u16(), 404);
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        assert!(body.is_empty());
    }

    #[tokio::test]
    async fn test_wasm_response_to_http_binary() {
        let wasm_resp = crate::services::wasm_bindings::WasmHttpResponse {
            status: 200,
            headers: vec![(
                "content-type".to_string(),
                "application/octet-stream".to_string(),
            )],
            body: vec![0x1f, 0x8b, 0x08, 0x00],
        };
        let resp = wasm_response_to_http(wasm_resp).unwrap();
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        assert_eq!(body.as_ref(), &[0x1f, 0x8b, 0x08, 0x00]);
    }
}
