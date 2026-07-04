//! Custom Axum extractors used by handlers in this crate.
//!
//! ## Why a custom `Json` extractor?
//!
//! `axum::Json<T>` rejects malformed bodies with HTTP 422 Unprocessable Entity
//! and an opaque text/plain body. Our public API contract is that any client
//! error returns 400 Bad Request with a structured envelope:
//!
//! ```json
//! {"code": "VALIDATION_ERROR", "message": "<reason>"}
//! ```
//!
//! The [`Json`] wrapper in this module is a drop-in replacement for
//! `axum::Json` that delegates parsing to the upstream extractor and translates
//! any [`JsonRejection`](axum::extract::rejection::JsonRejection) into
//! [`AppError::Validation`], so the application's `IntoResponse` impl renders
//! the same envelope as every other 400 the server emits (#1368).
//!
//! Handlers swap `use axum::Json;` for `use crate::api::extractors::Json;` and
//! the rest of the signature (`Json(payload): Json<MyReq>`) is unchanged.
//! Responses keep using `Json` too because this type implements
//! [`IntoResponse`] by deferring to `axum::Json`.

use axum::{
    async_trait,
    extract::{rejection::JsonRejection, FromRequest, FromRequestParts, Request},
    http::{request::Parts, HeaderMap, Uri},
    response::{IntoResponse, Response},
};
use serde::Serialize;
use std::convert::Infallible;

use crate::error::AppError;

/// Drop-in replacement for `axum::Json` that maps deserialization failures to
/// `AppError::Validation` (HTTP 400 + `VALIDATION_ERROR` envelope) instead of
/// Axum's default 422 + plain-text body.
#[derive(Debug, Clone, Copy, Default)]
pub struct Json<T>(pub T);

#[async_trait]
impl<T, S> FromRequest<S> for Json<T>
where
    S: Send + Sync,
    axum::Json<T>: FromRequest<S, Rejection = JsonRejection>,
{
    type Rejection = AppError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        match axum::Json::<T>::from_request(req, state).await {
            Ok(axum::Json(value)) => Ok(Json(value)),
            Err(rejection) => Err(map_json_rejection(rejection)),
        }
    }
}

impl<T> IntoResponse for Json<T>
where
    T: Serialize,
{
    fn into_response(self) -> Response {
        axum::Json(self.0).into_response()
    }
}

impl<T> From<T> for Json<T> {
    fn from(value: T) -> Self {
        Json(value)
    }
}

/// Translate `JsonRejection` into `AppError::Validation`. The mapping
/// preserves the upstream error message (which already names the offending
/// field for missing-field and type-mismatch errors) so the caller can act on
/// it. Internal details (line/column numbers from serde_json) are passed
/// through because they help client developers diagnose malformed payloads —
/// none of the rejection variants leak server state.
fn map_json_rejection(rejection: JsonRejection) -> AppError {
    AppError::Validation(rejection.body_text())
}

/// Pure parser for `AK_EXTERNAL_URL`. Returns `Some(trimmed_url)` only when
/// the value is a syntactically valid `http`/`https` absolute URL with no
/// embedded userinfo. Kept separate from [`configured_external_url`] so the
/// validation rules can be unit-tested without poisoning the process-wide
/// `OnceLock`.
fn parse_external_url(raw: &str) -> Option<String> {
    let trimmed = raw.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return None;
    }
    let parsed = match url::Url::parse(trimmed) {
        Ok(u) => u,
        Err(e) => {
            tracing::warn!(
                value = %trimmed,
                error = %e,
                "AK_EXTERNAL_URL is not a valid URL; ignoring"
            );
            return None;
        }
    };
    if !matches!(parsed.scheme(), "http" | "https") {
        tracing::warn!(
            value = %trimmed,
            scheme = parsed.scheme(),
            "AK_EXTERNAL_URL scheme must be http or https; ignoring"
        );
        return None;
    }
    if parsed.host_str().map_or(true, str::is_empty) {
        tracing::warn!(
            value = %trimmed,
            "AK_EXTERNAL_URL must have a host; ignoring"
        );
        return None;
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        tracing::warn!(
            value = %trimmed,
            "AK_EXTERNAL_URL must not contain embedded credentials; ignoring"
        );
        return None;
    }
    Some(trimmed.to_string())
}

/// Operator-configured external base URL, read once from `AK_EXTERNAL_URL`
/// and cached for the process lifetime. When set, this overrides whatever
/// [`request_base_url_from_request`] derives from request metadata.
///
/// This is the ONLY *trusted* source of the SP base URL — the value comes
/// from a process env var set by the operator, never from
/// attacker-influenceable request headers (`Host`, `X-Forwarded-Host`, etc.).
/// Use [`trusted_external_url`] from outside this module when the caller
/// needs a base URL that must not be spoofable — e.g. when embedding it in
/// signed material like a SAML `AssertionConsumerServiceURL` that the SP
/// asks the IdP to POST assertions to (see PR #2040 review).
fn configured_external_url() -> Option<&'static str> {
    static CACHE: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();
    CACHE
        .get_or_init(|| {
            let raw = std::env::var("AK_EXTERNAL_URL").ok()?;
            parse_external_url(&raw)
        })
        .as_deref()
}

/// Public accessor for the *trusted* external base URL — the value of
/// `AK_EXTERNAL_URL` if the operator set it, otherwise `None`.
///
/// Prefer this over [`RequestBaseUrl`] whenever the resulting URL will
/// feed a security-relevant sink where an attacker-influenceable
/// request header could cause harm — the two production sinks that
/// motivated exposing this accessor are:
///
/// - the SAML `AssertionConsumerServiceURL` embedded in the outbound
///   AuthnRequest (a spoofed `Host` header could advertise an attacker
///   ACS and a permissive IdP would POST the signed assertion there),
/// - the SAML `Destination`/`Recipient` value the SP recomputes on the
///   ACS callback to validate the asserted delivery target.
///
/// Callers that only need a display URL (e.g. building a link back to
/// the app in an email) should keep using [`RequestBaseUrl`], which
/// falls back to request-derived headers when the env var is unset.
pub fn trusted_external_url() -> Option<&'static str> {
    configured_external_url()
}

/// External base URL derived from request metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestBaseUrl(pub String);

impl RequestBaseUrl {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[async_trait]
impl<S> FromRequestParts<S> for RequestBaseUrl
where
    S: Send + Sync,
{
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(Self(request_base_url_from_request(
            &parts.headers,
            Some(&parts.uri),
        )))
    }
}

/// Derive the external base URL from reverse-proxy headers and request URI.
///
/// Resolution order (#1021):
/// 1. `AK_EXTERNAL_URL` environment variable, if set.
/// 2. `X-Forwarded-Host` + `X-Forwarded-Proto`.
/// 3. The request URI authority (`:authority` for h2c / HTTP/2).
/// 4. The `Host` request header.
/// 5. `http://localhost` as a last-resort fallback.
pub fn request_base_url_from_request(headers: &HeaderMap, uri: Option<&Uri>) -> String {
    if let Some(external) = configured_external_url() {
        return external.to_string();
    }

    let scheme = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .or_else(|| uri.and_then(Uri::scheme_str))
        .unwrap_or("http");

    let host = headers
        .get("x-forwarded-host")
        .and_then(|v| v.to_str().ok())
        .or_else(|| uri.and_then(Uri::authority).map(|a| a.as_str()))
        .or_else(|| headers.get("host").and_then(|v| v.to_str().ok()))
        .unwrap_or("localhost");

    if host.contains("://") {
        host.to_string()
    } else {
        format!("{}://{}", scheme, host)
    }
}

#[allow(clippy::disallowed_methods)]
// streaming-invariant: test module exempt — buffering response bodies in test assertions is not an artifact path (#1608)
#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{header, HeaderMap, HeaderValue, Request, StatusCode, Uri, Version},
        response::IntoResponse,
    };
    use serde::Deserialize;

    fn request_base_url(headers: &HeaderMap) -> String {
        request_base_url_from_request(headers, None)
    }

    #[test]
    fn test_request_base_url_no_headers() {
        let headers = HeaderMap::new();
        assert_eq!(request_base_url(&headers), "http://localhost");
    }

    #[test]
    fn test_request_base_url_host_only() {
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("registry.example.com"));
        assert_eq!(request_base_url(&headers), "http://registry.example.com");
    }

    #[test]
    fn test_request_base_url_host_with_port() {
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("localhost:8080"));
        assert_eq!(request_base_url(&headers), "http://localhost:8080");
    }

    #[test]
    fn test_request_base_url_forwarded_proto() {
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("registry.example.com"));
        headers.insert("x-forwarded-proto", HeaderValue::from_static("https"));
        assert_eq!(request_base_url(&headers), "https://registry.example.com");
    }

    #[test]
    fn test_request_base_url_forwarded_host() {
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("backend:8080"));
        headers.insert(
            "x-forwarded-host",
            HeaderValue::from_static("registry.example.com:30443"),
        );
        headers.insert("x-forwarded-proto", HeaderValue::from_static("https"));
        assert_eq!(
            request_base_url(&headers),
            "https://registry.example.com:30443"
        );
    }

    #[test]
    fn test_request_base_url_forwarded_host_without_proto() {
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("backend:8080"));
        headers.insert(
            "x-forwarded-host",
            HeaderValue::from_static("registry.example.com"),
        );
        assert_eq!(request_base_url(&headers), "http://registry.example.com");
    }

    #[test]
    fn test_request_base_url_uses_uri_authority_before_host() {
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("backend:8080"));
        let uri = Uri::from_static("http://registry.example.com/v2/");

        assert_eq!(
            request_base_url_from_request(&headers, Some(&uri)),
            "http://registry.example.com"
        );
    }

    #[test]
    fn test_request_base_url_uses_uri_scheme() {
        let headers = HeaderMap::new();
        let uri = Uri::from_static("https://registry.example.com/v2/");

        assert_eq!(
            request_base_url_from_request(&headers, Some(&uri)),
            "https://registry.example.com"
        );
    }

    #[test]
    fn test_request_base_url_forwarded_host_takes_precedence_over_authority() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-proto", HeaderValue::from_static("https"));
        headers.insert(
            "x-forwarded-host",
            HeaderValue::from_static("external.example.com"),
        );
        let uri = Uri::from_static("http://internal.example.com/v2/");

        assert_eq!(
            request_base_url_from_request(&headers, Some(&uri)),
            "https://external.example.com"
        );
    }

    #[tokio::test]
    async fn test_request_base_url_extractor_uses_http2_authority_before_host() {
        let request = Request::builder()
            .version(Version::HTTP_2)
            .uri("http://registry.example.com/v2/")
            .header("host", "backend:8080")
            .body(())
            .unwrap();
        let (mut parts, _) = request.into_parts();

        let base_url = RequestBaseUrl::from_request_parts(&mut parts, &())
            .await
            .unwrap();

        assert_eq!(base_url.as_str(), "http://registry.example.com");
    }

    #[tokio::test]
    async fn test_request_base_url_extractor_forwarded_host_precedes_http2_authority() {
        let request = Request::builder()
            .version(Version::HTTP_2)
            .uri("http://internal.example.com/v2/")
            .header("host", "backend:8080")
            .header("x-forwarded-proto", "https")
            .header("x-forwarded-host", "external.example.com")
            .body(())
            .unwrap();
        let (mut parts, _) = request.into_parts();

        let base_url = RequestBaseUrl::from_request_parts(&mut parts, &())
            .await
            .unwrap();

        assert_eq!(base_url.as_str(), "https://external.example.com");
    }

    #[test]
    fn test_request_base_url_host_with_embedded_scheme() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "host",
            HeaderValue::from_static("https://already-absolute.example.com"),
        );
        assert_eq!(
            request_base_url(&headers),
            "https://already-absolute.example.com"
        );
    }

    #[test]
    fn test_parse_external_url_https() {
        assert_eq!(
            parse_external_url("https://registry.example.com"),
            Some("https://registry.example.com".to_string())
        );
    }

    #[test]
    fn test_parse_external_url_http() {
        assert_eq!(
            parse_external_url("http://localhost:8080"),
            Some("http://localhost:8080".to_string())
        );
    }

    #[test]
    fn test_parse_external_url_strips_trailing_slash() {
        assert_eq!(
            parse_external_url("https://registry.example.com/"),
            Some("https://registry.example.com".to_string())
        );
    }

    #[test]
    fn test_parse_external_url_trims_whitespace() {
        assert_eq!(
            parse_external_url("  https://registry.example.com/  "),
            Some("https://registry.example.com".to_string())
        );
    }

    #[test]
    fn test_parse_external_url_empty_rejected() {
        assert_eq!(parse_external_url(""), None);
        assert_eq!(parse_external_url("   "), None);
        assert_eq!(parse_external_url("/"), None);
    }

    #[test]
    fn test_parse_external_url_missing_scheme_rejected() {
        assert_eq!(parse_external_url("registry.example.com"), None);
        assert_eq!(parse_external_url("//registry.example.com"), None);
    }

    #[test]
    fn test_parse_external_url_non_http_scheme_rejected() {
        assert_eq!(parse_external_url("ftp://registry.example.com"), None);
        assert_eq!(parse_external_url("file:///etc/passwd"), None);
        assert_eq!(parse_external_url("javascript:alert(1)"), None);
    }

    #[test]
    fn test_parse_external_url_embedded_credentials_rejected() {
        assert_eq!(
            parse_external_url("https://user:pass@registry.example.com"),
            None
        );
        assert_eq!(
            parse_external_url("https://user@registry.example.com"),
            None
        );
    }

    #[test]
    fn test_parse_external_url_invalid_garbage_rejected() {
        assert_eq!(parse_external_url("https://"), None);
        assert_eq!(parse_external_url("not a url at all"), None);
    }

    #[test]
    fn test_parse_external_url_with_path_preserved() {
        assert_eq!(
            parse_external_url("https://example.com/registry"),
            Some("https://example.com/registry".to_string())
        );
    }

    #[derive(Debug, Deserialize)]
    struct Sample {
        name: String,
        count: i64,
    }

    fn json_request(body: &str) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_owned()))
            .unwrap()
    }

    /// A request whose body is not syntactically valid JSON must return 400 +
    /// `VALIDATION_ERROR`, not Axum's default 422.
    #[tokio::test]
    async fn invalid_json_syntax_returns_400_validation_error() {
        let req = json_request("{not valid json");
        let result = Json::<Sample>::from_request(req, &()).await;
        let err = result.expect_err("malformed JSON must be rejected");
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let body_bytes = axum::body::to_bytes(response.into_body(), 65_536)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(body["code"], "VALIDATION_ERROR");
        assert!(body["message"].is_string());
    }

    /// A request that parses as JSON but is missing a required field must
    /// also return 400 + `VALIDATION_ERROR` (regression for #1368).
    #[tokio::test]
    async fn missing_field_returns_400_validation_error() {
        let req = json_request(r#"{"count": 1}"#);
        let result = Json::<Sample>::from_request(req, &()).await;
        let err = result.expect_err("missing field must be rejected");
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let body_bytes = axum::body::to_bytes(response.into_body(), 65_536)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(body["code"], "VALIDATION_ERROR");
        // The upstream error message names the field; sanity-check the message
        // is non-empty without pinning to a fragile substring.
        assert!(!body["message"].as_str().unwrap_or("").is_empty());
    }

    /// A type mismatch (e.g. string where number is expected) must return
    /// 400 + `VALIDATION_ERROR`.
    #[tokio::test]
    async fn type_mismatch_returns_400_validation_error() {
        let req = json_request(r#"{"name": "x", "count": "not-a-number"}"#);
        let result = Json::<Sample>::from_request(req, &()).await;
        let err = result.expect_err("type mismatch must be rejected");
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let body_bytes = axum::body::to_bytes(response.into_body(), 65_536)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(body["code"], "VALIDATION_ERROR");
    }

    /// Missing `Content-Type: application/json` is also a malformed-input
    /// failure from the API contract's point of view and should surface as
    /// 400, not 415 / 422.
    #[tokio::test]
    async fn missing_content_type_returns_400_validation_error() {
        let req = Request::builder()
            .method("POST")
            .uri("/")
            .body(Body::from(r#"{"name": "x", "count": 1}"#))
            .unwrap();
        let result = Json::<Sample>::from_request(req, &()).await;
        let err = result.expect_err("missing content-type must be rejected");
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let body_bytes = axum::body::to_bytes(response.into_body(), 65_536)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(body["code"], "VALIDATION_ERROR");
    }

    /// A well-formed payload must still parse successfully and round-trip the
    /// inner value unchanged.
    #[tokio::test]
    async fn valid_json_is_extracted() {
        let req = json_request(r#"{"name": "x", "count": 7}"#);
        let extracted = Json::<Sample>::from_request(req, &()).await.unwrap();
        assert_eq!(extracted.0.name, "x");
        assert_eq!(extracted.0.count, 7);
    }

    // ---------------------------------------------------------------------
    // End-to-end route exercises: wire the extractor into a real `axum::Router`
    // and prove the rejection surfaces through `Service::call` as the same
    // `400 + {code, message}` envelope the failing E2E asserts expect (#1368).
    // The handler signatures and payload shapes here mirror the affected
    // `PUT /repositories/{key}/members` and `PUT /repositories/{key}/cache-ttl`
    // endpoints in `crate::api::handlers::repositories`.
    // ---------------------------------------------------------------------

    use axum::{routing::put, Router};
    use tower::ServiceExt;

    #[derive(Debug, Deserialize)]
    struct MemberInput {
        #[allow(dead_code)]
        member_key: String,
        #[allow(dead_code)]
        priority: i32,
    }

    #[derive(Debug, Deserialize)]
    struct UpdateMembersInput {
        #[allow(dead_code)]
        members: Vec<MemberInput>,
    }

    #[derive(Debug, Deserialize)]
    struct CacheTtlInput {
        #[allow(dead_code)]
        cache_ttl_seconds: i64,
    }

    async fn parse_envelope(response: axum::response::Response) -> (StatusCode, serde_json::Value) {
        let status = response.status();
        let body_bytes = axum::body::to_bytes(response.into_body(), 65_536)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        (status, body)
    }

    /// PUT /members where a member entry is missing `member_key` must
    /// surface as 400 + `VALIDATION_ERROR` (E2E: virtual-repo-malformed-input
    /// "PUT /members with member missing member_key returns 400").
    #[tokio::test]
    async fn route_put_members_missing_member_key_returns_400() {
        async fn handler(Json(_): Json<UpdateMembersInput>) -> &'static str {
            "ok"
        }
        let app: Router = Router::new().route("/members", put(handler));
        let req = Request::builder()
            .method("PUT")
            .uri("/members")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(r#"{"members": [{"priority": 1}]}"#))
            .unwrap();
        let response = app.oneshot(req).await.unwrap();
        let (status, body) = parse_envelope(response).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["code"], "VALIDATION_ERROR");
    }

    /// PUT /members where `priority` is a string instead of an integer must
    /// also surface as 400 + `VALIDATION_ERROR`.
    #[tokio::test]
    async fn route_put_members_priority_as_string_returns_400() {
        async fn handler(Json(_): Json<UpdateMembersInput>) -> &'static str {
            "ok"
        }
        let app: Router = Router::new().route("/members", put(handler));
        let req = Request::builder()
            .method("PUT")
            .uri("/members")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                r#"{"members": [{"member_key": "x", "priority": "high"}]}"#,
            ))
            .unwrap();
        let response = app.oneshot(req).await.unwrap();
        let (status, body) = parse_envelope(response).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["code"], "VALIDATION_ERROR");
    }

    /// PUT /cache-ttl with the `cache_ttl_seconds` field missing must
    /// surface as 400 + `VALIDATION_ERROR`.
    #[tokio::test]
    async fn route_put_cache_ttl_missing_field_returns_400() {
        async fn handler(Json(_): Json<CacheTtlInput>) -> &'static str {
            "ok"
        }
        let app: Router = Router::new().route("/cache-ttl", put(handler));
        let req = Request::builder()
            .method("PUT")
            .uri("/cache-ttl")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(r#"{}"#))
            .unwrap();
        let response = app.oneshot(req).await.unwrap();
        let (status, body) = parse_envelope(response).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["code"], "VALIDATION_ERROR");
    }

    /// PUT /cache-ttl with `cache_ttl_seconds` as a string instead of integer
    /// must surface as 400 + `VALIDATION_ERROR`.
    #[tokio::test]
    async fn route_put_cache_ttl_as_string_returns_400() {
        async fn handler(Json(_): Json<CacheTtlInput>) -> &'static str {
            "ok"
        }
        let app: Router = Router::new().route("/cache-ttl", put(handler));
        let req = Request::builder()
            .method("PUT")
            .uri("/cache-ttl")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(r#"{"cache_ttl_seconds": "forever"}"#))
            .unwrap();
        let response = app.oneshot(req).await.unwrap();
        let (status, body) = parse_envelope(response).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["code"], "VALIDATION_ERROR");
    }

    /// Reaffirmation that the Content-Type sniff also routes through our
    /// envelope rather than Axum's stock 415.
    #[tokio::test]
    async fn route_wrong_content_type_returns_400() {
        async fn handler(Json(_): Json<CacheTtlInput>) -> &'static str {
            "ok"
        }
        let app: Router = Router::new().route("/cache-ttl", put(handler));
        let req = Request::builder()
            .method("PUT")
            .uri("/cache-ttl")
            .header(header::CONTENT_TYPE, "text/plain")
            .body(Body::from(r#"{"cache_ttl_seconds": 60}"#))
            .unwrap();
        let response = app.oneshot(req).await.unwrap();
        let (status, body) = parse_envelope(response).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["code"], "VALIDATION_ERROR");
    }

    /// The wrapper must implement `IntoResponse` so handlers can return
    /// `Json<T>` directly without unwrapping into `axum::Json<T>`.
    #[tokio::test]
    async fn into_response_renders_json_body() {
        #[derive(Serialize)]
        struct Out {
            ok: bool,
        }
        let response = Json(Out { ok: true }).into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body_bytes = axum::body::to_bytes(response.into_body(), 65_536)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(body["ok"], true);
    }
}
