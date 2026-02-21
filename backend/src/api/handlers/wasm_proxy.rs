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
    Router,
};

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

/// Determine the URL scheme based on the host header.
fn scheme_for_host(host: &str) -> &'static str {
    if host.contains("localhost") || host.contains("127.0.0.1") {
        "http"
    } else {
        "https"
    }
}

/// Convert HTTP headers to a list of string pairs, skipping non-UTF-8 values.
fn headers_to_pairs(headers: &HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
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
    Path(params): Path<Vec<(String, String)>>,
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

    // 4. Gather artifact metadata from DB
    let artifacts = fetch_repo_artifacts(&state, repo.id).await.map_err(|e| {
        error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("Failed to fetch artifacts: {}", e),
        )
    })?;

    // 5. Build request and context
    let (wasm_request, wasm_context) =
        build_wasm_request(&headers, &method, request_path, body, format_key, repo_key);

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
    request_path: String,
    body: Bytes,
    format_key: &str,
    repo_key: &str,
) -> (WasmHttpRequest, WasmRepoContext) {
    let host = headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost:8080");
    let scheme = scheme_for_host(host);
    let base_url = format!("{}://{}/ext/{}/{}", scheme, host, format_key, repo_key);
    let download_base_url = format!(
        "{}://{}/api/v1/repositories/{}/download",
        scheme, host, repo_key
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
    // scheme_for_host
    // -----------------------------------------------------------------------

    #[test]
    fn test_scheme_localhost() {
        assert_eq!(scheme_for_host("localhost:8080"), "http");
        assert_eq!(scheme_for_host("localhost"), "http");
    }

    #[test]
    fn test_scheme_loopback() {
        assert_eq!(scheme_for_host("127.0.0.1:8080"), "http");
        assert_eq!(scheme_for_host("127.0.0.1"), "http");
    }

    #[test]
    fn test_scheme_remote() {
        assert_eq!(scheme_for_host("registry.example.com"), "https");
        assert_eq!(scheme_for_host("artifacts.internal:443"), "https");
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
        headers.insert("good", HeaderValue::from_static("valid"));
        headers.insert("binary", HeaderValue::from_bytes(&[0xff, 0xfe]).unwrap());
        let pairs = headers_to_pairs(&headers);
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].0, "good");
        assert_eq!(pairs[0].1, "valid");
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
    fn test_build_wasm_request_remote_host() {
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("registry.example.com"));
        let (req, ctx) = build_wasm_request(
            &headers,
            &Method::POST,
            "/upload".to_string(),
            Bytes::from(vec![0xde, 0xad]),
            "rpm-custom",
            "centos-repo",
        );
        assert_eq!(req.method, "POST");
        assert_eq!(req.body, vec![0xde, 0xad]);
        assert_eq!(ctx.repo_key, "centos-repo");
        assert!(ctx.base_url.starts_with("https://"));
        assert!(ctx.download_base_url.starts_with("https://"));
    }

    #[test]
    fn test_build_wasm_request_no_host_header() {
        let headers = HeaderMap::new();
        let (_, ctx) = build_wasm_request(
            &headers,
            &Method::GET,
            "/".to_string(),
            Bytes::new(),
            "fmt",
            "repo",
        );
        assert!(ctx.base_url.starts_with("http://localhost:8080"));
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
