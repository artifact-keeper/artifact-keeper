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
    extract::{rejection::JsonRejection, FromRequest, Request},
    response::{IntoResponse, Response},
};
use serde::Serialize;

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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{header, Request, StatusCode},
        response::IntoResponse,
    };
    use serde::Deserialize;

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
