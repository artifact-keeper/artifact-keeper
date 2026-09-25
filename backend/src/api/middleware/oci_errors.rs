//! OCI distribution-spec error envelopes for global middleware (#3284).
//!
//! Global guard layers (`setup_guard`, `demo_guard`, `guest_access_guard`) run
//! in front of the nested `/v2` router, so they can refuse a request before it
//! ever reaches an `oci_v2` handler. The distribution spec is unambiguous about
//! the shape such a refusal must take (`spec.md`, "Error Codes"): *"A `4XX`
//! response code from the registry MAY return a body in any format. If the
//! response body is in JSON format, it MUST have the following format:
//! `{"errors":[{"code","message","detail"}]}`"*. A REST-shaped JSON body on
//! `/v2` is therefore a spec violation that docker/oras clients cannot
//! render — a fresh unconfigured instance reported a `docker login` failure
//! with no usable message.
//!
//! Guards that refuse a `/v2` request must build their response through
//! [`oci_denied_response`] instead of their REST body. `guest_access_guard`
//! refuses through [`oci_unauthorized_response`], which adds the token-endpoint
//! `WWW-Authenticate` challenge on top of that envelope (#3854): it no longer
//! allowlists the OCI content surface, so the guest-access policy is asked
//! there like on every other one. `/v2/token` remains allowlisted — it is the
//! credential exchange, and refuses the anonymous mint in the handler.
//!
//! The challenge itself is built here rather than in `oci_v2` so the guard and
//! the handlers emit byte-identical `WWW-Authenticate` values for the same
//! request; a second copy would drift, and a drifted realm points clients at
//! the wrong host.

use axum::{
    body::Body,
    http::{header::CONTENT_TYPE, Response as HttpResponse, StatusCode},
    response::Response,
};

/// Service identifier this registry advertises in `WWW-Authenticate` and
/// expects to see in the `?service=` query parameter on `/v2/token` (#1175).
/// Kept as a single module-level constant so the challenge-building sites
/// (here and in `oci_v2`) and the validation site cannot drift.
pub(crate) const OCI_TOKEN_SERVICE: &str = "artifact-keeper";

/// True when `path` is on the OCI distribution surface (`/v2` or `/v2/...`),
/// where any JSON 4XX body must be the spec's error envelope.
pub(crate) fn is_oci_v2_path(path: &str) -> bool {
    path == "/v2" || path == "/v2/" || path.starts_with("/v2/")
}

/// Escape a string so it is safe to embed in an HTTP `quoted-string` body
/// (RFC 7230 §3.2.6 ABNF):
///
/// ```text
/// qdtext       = HTAB / SP / %x21 / %x23-5B / %x5D-7E / obs-text
/// quoted-pair  = "\" ( HTAB / SP / VCHAR / obs-text )
/// obs-text     = %x80-FF
/// ```
///
/// `"` and `\` get the standard `quoted-pair` backslash escape. HTAB and
/// printable ASCII pass through verbatim. Everything else (CR, LF, NUL,
/// other control chars, and `obs-text` ≥ 0x80) is percent-encoded
/// byte-by-byte. CR/LF in particular **must** be dropped from the output:
/// `pull_scope` / `push_scope` interpolate the URL-decoded `image_name`
/// path parameter into the scope value, so a path containing
/// `…%0D%0A…` would otherwise inject a follow-on header into the 401
/// response. `obs-text` is percent-encoded rather than passed through so
/// the result remains valid for `HeaderValue::from_str` (which accepts
/// only ASCII-visible bytes plus HTAB).
pub(crate) fn auth_challenge_quoted_value(value: &str) -> String {
    use std::fmt::Write as _;

    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\t' | '\x20'..='\x21' | '\x23'..='\x5b' | '\x5d'..='\x7e' => escaped.push(ch),
            _ => {
                let mut buf = [0; 4];
                for byte in ch.encode_utf8(&mut buf).as_bytes() {
                    let _ = write!(&mut escaped, "%{byte:02X}");
                }
            }
        }
    }
    escaped
}

/// Build the `WWW-Authenticate` bearer challenge naming this registry's token
/// endpoint as the realm. `scope` is omitted when `None` — the form the
/// version check, `_catalog` and `guest_access_guard` all emit.
pub(crate) fn www_authenticate_header(base_url: &str, scope: Option<&str>) -> String {
    let realm = auth_challenge_quoted_value(&format!("{base_url}/v2/token"));
    let service = OCI_TOKEN_SERVICE;
    match scope {
        Some(s) => {
            let scope = auth_challenge_quoted_value(s);
            format!("Bearer realm=\"{realm}\",service=\"{service}\",scope=\"{scope}\"")
        }
        None => format!("Bearer realm=\"{realm}\",service=\"{service}\""),
    }
}

/// Build a distribution-spec error envelope response:
/// `{"errors":[{"code":<code>,"message":<message>}]}`.
///
/// A minimal serializer-free construction on purpose: the middleware crate
/// half must not depend on the `oci_v2` handler module's response types, and
/// `code`/`message` are compile-time controlled strings here (no user input),
/// so `serde_json::json!` gives correct escaping without new types.
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

/// The `401` a guard returns on the OCI surface: the spec's error envelope
/// plus the bearer challenge pointing at `<base_url>/v2/token`, so a container
/// client learns where to authenticate.
///
/// Deliberately carries no `Basic` challenge (it raises a browser's native
/// credential popup) and no `Cargo` challenge (meaningless on this surface).
/// The scope-less challenge form is correct here: the token endpoint derives a
/// token from the authenticated identity's permissions, not from the requested
/// scope, and a caller this guard refused obtains no token regardless.
pub(crate) fn oci_unauthorized_response(base_url: &str) -> Response {
    let mut response = oci_denied_response(
        StatusCode::UNAUTHORIZED,
        "UNAUTHORIZED",
        "authentication required",
    );
    if let Ok(challenge) =
        axum::http::HeaderValue::from_str(&www_authenticate_header(base_url, None))
    {
        response
            .headers_mut()
            .insert(axum::http::header::WWW_AUTHENTICATE, challenge);
    }
    response
}

#[cfg(ak_test_shard = "services-2")]
#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::header::WWW_AUTHENTICATE;

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

    #[tokio::test]
    #[allow(clippy::disallowed_methods)] // streaming-invariant: test-only read of a tiny middleware error body
    async fn unauthorized_response_is_envelope_plus_token_realm() {
        let resp = oci_unauthorized_response("https://registry.example.com");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let challenges: Vec<String> = resp
            .headers()
            .get_all(WWW_AUTHENTICATE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .map(String::from)
            .collect();
        assert_eq!(
            challenges,
            vec!["Bearer realm=\"https://registry.example.com/v2/token\",\
                 service=\"artifact-keeper\""
                .to_string()],
            "the OCI 401 carries exactly one Bearer challenge naming the token endpoint"
        );

        let bytes = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["errors"][0]["code"], "UNAUTHORIZED");
        assert_eq!(json["errors"][0]["message"], "authentication required");
    }

    #[test]
    fn unauthorized_response_carries_no_basic_or_cargo_challenge() {
        // A Basic challenge raises the browser's native credential popup and
        // Cargo is meaningless on the OCI surface (spec — "No browser
        // credential prompt on the OCI surface").
        let resp = oci_unauthorized_response("http://localhost:8080");
        let challenges: Vec<&str> = resp
            .headers()
            .get_all(WWW_AUTHENTICATE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .collect();
        assert!(
            !challenges
                .iter()
                .any(|v| v.starts_with("Basic") || *v == "Cargo"),
            "OCI 401 must carry only the Bearer challenge, got: {challenges:?}"
        );
    }

    #[test]
    fn challenge_realm_is_the_token_endpoint() {
        assert_eq!(
            www_authenticate_header("http://localhost:8080", None),
            "Bearer realm=\"http://localhost:8080/v2/token\",service=\"artifact-keeper\""
        );
    }

    #[test]
    fn auth_challenge_quoted_value_escapes_quote_and_backslash() {
        // `"` and `\` get the standard `quoted-pair` backslash escape so the
        // surrounding quotes in the WWW-Authenticate header aren't broken.
        assert_eq!(auth_challenge_quoted_value("a\"b"), "a\\\"b");
        assert_eq!(auth_challenge_quoted_value("a\\b"), "a\\\\b");
    }

    #[test]
    fn challenge_realm_quotes_are_escaped() {
        // The realm is derived from request headers, so a forged
        // `Host: evil"` must not break out of the quoted-string.
        let header = www_authenticate_header("http://evil\"", None);
        assert!(
            header.contains("realm=\"http://evil\\\"/v2/token\""),
            "unexpected challenge: {header}"
        );
    }
}
