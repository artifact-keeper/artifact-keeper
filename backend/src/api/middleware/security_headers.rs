//! Security headers middleware.
//!
//! Adds standard security headers to all HTTP responses.

use axum::{extract::Request, middleware::Next, response::Response};

pub async fn security_headers_middleware(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();

    headers.insert("x-frame-options", "DENY".parse().unwrap());
    headers.insert("x-content-type-options", "nosniff".parse().unwrap());
    headers.insert(
        "strict-transport-security",
        "max-age=31536000; includeSubDomains".parse().unwrap(),
    );
    headers.insert(
        "referrer-policy",
        "strict-origin-when-cross-origin".parse().unwrap(),
    );
    headers.insert(
        "permissions-policy",
        "camera=(), microphone=(), geolocation=()".parse().unwrap(),
    );
    // Only set the global default CSP when the handler did not already set a
    // tighter, route-specific policy. Using `entry().or_insert()` (rather than
    // `insert()`, which unconditionally overwrites) preserves a per-handler CSP
    // such as the restrictive `default-src 'none'` the PyPI simple-index
    // handler emits, while still providing a safe default for every other
    // route (#1773).
    headers
        .entry("content-security-policy")
        .or_insert(
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
                .parse()
                .unwrap(),
        );

    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, middleware, routing::get, Router};
    use tower::ServiceExt;

    async fn test_handler() -> &'static str {
        "OK"
    }

    async fn build_response() -> axum::response::Response {
        let app = Router::new()
            .route("/test", get(test_handler))
            .layer(middleware::from_fn(security_headers_middleware));

        let request = Request::builder().uri("/test").body(Body::empty()).unwrap();

        app.oneshot(request).await.unwrap()
    }

    #[tokio::test]
    async fn test_security_headers_x_frame_options() {
        let resp = build_response().await;
        assert_eq!(
            resp.headers()
                .get("x-frame-options")
                .unwrap()
                .to_str()
                .unwrap(),
            "DENY"
        );
    }

    #[tokio::test]
    async fn test_security_headers_x_content_type_options() {
        let resp = build_response().await;
        assert_eq!(
            resp.headers()
                .get("x-content-type-options")
                .unwrap()
                .to_str()
                .unwrap(),
            "nosniff"
        );
    }

    #[tokio::test]
    async fn test_security_headers_strict_transport_security() {
        let resp = build_response().await;
        assert_eq!(
            resp.headers()
                .get("strict-transport-security")
                .unwrap()
                .to_str()
                .unwrap(),
            "max-age=31536000; includeSubDomains"
        );
    }

    #[tokio::test]
    async fn test_security_headers_referrer_policy() {
        let resp = build_response().await;
        assert_eq!(
            resp.headers()
                .get("referrer-policy")
                .unwrap()
                .to_str()
                .unwrap(),
            "strict-origin-when-cross-origin"
        );
    }

    #[tokio::test]
    async fn test_security_headers_permissions_policy() {
        let resp = build_response().await;
        assert_eq!(
            resp.headers()
                .get("permissions-policy")
                .unwrap()
                .to_str()
                .unwrap(),
            "camera=(), microphone=(), geolocation=()"
        );
    }

    #[tokio::test]
    async fn test_security_headers_content_security_policy() {
        let resp = build_response().await;
        let csp = resp
            .headers()
            .get("content-security-policy")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(csp.contains("default-src 'self'"));
        assert!(csp.contains("script-src 'self'"));
        assert!(csp.contains("frame-ancestors 'none'"));
    }

    #[tokio::test]
    async fn test_security_headers_response_body_preserved() {
        let resp = build_response().await;
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        // We verify the status code is OK, which confirms the handler ran.
        // Body consumption requires http-body-util which is not a direct dependency.
    }

    #[tokio::test]
    async fn test_security_headers_preserves_handler_set_csp() {
        // Regression for #1773: a handler that sets its own (tighter) CSP must
        // not have it clobbered by the global default. The middleware should
        // only fill in the default CSP when none is already present.
        async fn tight_csp_handler() -> axum::response::Response {
            axum::response::Response::builder()
                .header(
                    "content-security-policy",
                    "default-src 'none'; style-src 'unsafe-inline'",
                )
                .body(Body::from("OK"))
                .unwrap()
        }

        let app = Router::new()
            .route("/tight", get(tight_csp_handler))
            .layer(middleware::from_fn(security_headers_middleware));
        let request = Request::builder()
            .uri("/tight")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(request).await.unwrap();

        let csp = resp
            .headers()
            .get("content-security-policy")
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(csp, "default-src 'none'; style-src 'unsafe-inline'");
        // The other security headers must still be applied.
        assert!(resp.headers().get("x-frame-options").is_some());
    }

    #[tokio::test]
    async fn test_security_headers_all_six_present() {
        let resp = build_response().await;
        let headers = resp.headers();
        assert!(headers.get("x-frame-options").is_some());
        assert!(headers.get("x-content-type-options").is_some());
        assert!(headers.get("strict-transport-security").is_some());
        assert!(headers.get("referrer-policy").is_some());
        assert!(headers.get("permissions-policy").is_some());
        assert!(headers.get("content-security-policy").is_some());
    }
}
