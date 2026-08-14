//! OCI distribution-spec error envelopes for global middleware (#3284).
//!
//! Global guard layers (`setup_guard`, `demo_guard`) run in front of the
//! nested `/v2` router, so they can refuse a request before it ever reaches
//! an `oci_v2` handler. The distribution spec is unambiguous about the shape
//! such a refusal must take (`spec.md`, "Error Codes"): *"A `4XX` response
//! code from the registry MAY return a body in any format. If the response
//! body is in JSON format, it MUST have the following format:
//! `{"errors":[{"code","message","detail"}]}`"*. A REST-shaped JSON body on
//! `/v2` is therefore a spec violation that docker/oras clients cannot
//! render — a fresh unconfigured instance reported a `docker login` failure
//! with no usable message.
//!
//! Guards that refuse a `/v2` request must build their response through
//! [`oci_denied_response`] instead of their REST body. `guest_access_guard`
//! is not routed through here: it *allowlists* `/v2` challenge paths instead
//! of refusing them (see `allowlist_oci_v2_challenge`).

use axum::{
    body::Body,
    http::{header::CONTENT_TYPE, Response as HttpResponse, StatusCode},
    response::Response,
};

/// True when `path` is on the OCI distribution surface (`/v2` or `/v2/...`),
/// where any JSON 4XX body must be the spec's error envelope.
pub(crate) fn is_oci_v2_path(path: &str) -> bool {
    path == "/v2" || path == "/v2/" || path.starts_with("/v2/")
}

/// Build a distribution-spec error envelope response:
/// `{"errors":[{"code":<code>,"message":<message>}]}`.
///
/// A minimal serializer-free construction on purpose: the middleware crate
/// half must not depend on the `oci_v2` handler module, and `code`/`message`
/// are compile-time controlled strings here (no user input), so
/// `serde_json::json!` gives correct escaping without new types.
pub(crate) fn oci_denied_response(status: StatusCode, code: &str, message: &str) -> Response {
    let body = serde_json::json!({
        "errors": [{ "code": code, "message": message }]
    });
    HttpResponse::builder()
        .status(status)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v2_paths_are_recognized() {
        assert!(is_oci_v2_path("/v2"));
        assert!(is_oci_v2_path("/v2/"));
        assert!(is_oci_v2_path("/v2/library/nginx/manifests/latest"));
        assert!(is_oci_v2_path("/v2/token"));
    }

    #[test]
    fn non_v2_paths_are_not_recognized() {
        assert!(!is_oci_v2_path("/api/v1/repositories"));
        assert!(!is_oci_v2_path("/v22/escape"));
        assert!(!is_oci_v2_path("/health"));
        assert!(!is_oci_v2_path(""));
    }

    #[tokio::test]
    #[allow(clippy::disallowed_methods)] // streaming-invariant: test-only read of a tiny middleware error body
    async fn denied_response_is_a_spec_envelope() {
        let resp = oci_denied_response(StatusCode::FORBIDDEN, "DENIED", "nope");
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            resp.headers().get(CONTENT_TYPE).unwrap(),
            "application/json"
        );
        let bytes = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["errors"][0]["code"], "DENIED");
        assert_eq!(json["errors"][0]["message"], "nope");
    }
}
