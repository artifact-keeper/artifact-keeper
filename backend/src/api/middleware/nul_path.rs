//! Reject a NUL byte anywhere in the decoded request path (#3622).
//!
//! A percent-encoded `%00` in a URL path is decoded by axum's `Path`
//! extractor into a literal `\0` in the extracted `String`. Postgres rejects
//! that byte at the wire protocol (`invalid byte sequence for encoding
//! "UTF8": 0x00`), so any handler that forwards a path segment into a query
//! turned a trivially craftable anonymous request into a `500 DATABASE_ERROR`
//! — one pool checkout plus one failing query per request, and a coarse
//! implementation-detail leak. #3545 fixed the four generic repository-scoped
//! routes at their own path extraction; the same class still reached the
//! driver through the format-native wildcard routes (`/maven/{key}/*path`,
//! `/rpm/{key}/packages/*path`, `/hex/{key}/tarballs/*path`,
//! `/puppet/{key}/v3/files/*path`, `/ansible/{key}/download/*path`, …) and
//! through the repository **key** segment itself
//! (`/api/v1/repositories/pub%00gen/artifacts/a`).
//!
//! There are ~40 format handlers, so this is a single shared boundary rather
//! than a per-handler check: a global layer that inspects the decoded path
//! before routing and refuses the request with a 400. A NUL is not
//! representable in a stored artifact path (uploads reject it in
//! `upload_service::validate_artifact_path`) nor in a repository key, so no
//! request that could ever have succeeded is affected. Deliberately NUL-only
//! — every other byte a client may legitimately percent-encode still routes
//! exactly as before.

use axum::{
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};

use super::oci_errors::{is_oci_v2_path, oci_denied_response};
use crate::error::AppError;

/// Whether the percent-decoded form of `raw_path` contains a NUL byte.
///
/// Pure (`&str` in, `bool` out) so the whole decision is unit-testable
/// without a router or a server. The two early returns keep this off the
/// allocation path for ordinary requests: a raw NUL cannot survive the HTTP
/// parser, and a path with no `%` decodes to itself.
pub(crate) fn decoded_path_has_nul(raw_path: &str) -> bool {
    if raw_path.contains('\0') {
        return true;
    }
    if !raw_path.contains('%') {
        return false;
    }
    // A decode failure means the escapes are not valid UTF-8 at all; leave
    // that to the extractor that already rejects it, and change nothing here.
    matches!(urlencoding::decode(raw_path), Ok(decoded) if decoded.contains('\0'))
}

/// Global layer rejecting a NUL byte in the decoded request path with a 400,
/// before routing and before any handler runs (#3622).
pub async fn nul_path_guard(request: Request, next: Next) -> Response {
    let path = request.uri().path();
    if decoded_path_has_nul(path) {
        // #3284: a refusal on the OCI surface must be the distribution-spec
        // error envelope — docker/oras clients cannot render the REST shape.
        if is_oci_v2_path(path) {
            return oci_denied_response(
                StatusCode::BAD_REQUEST,
                "NAME_INVALID",
                "request path must not contain a NUL byte",
            );
        }
        return AppError::Validation("request path must not contain a NUL byte".to_string())
            .into_response();
    }
    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, middleware, routing::get, Router};
    use tower::ServiceExt;

    #[test]
    fn decoded_nul_is_detected_anywhere_in_the_path() {
        // The exact vectors from #3622.
        assert!(decoded_path_has_nul("/maven/pub/a%00b"));
        assert!(decoded_path_has_nul("/rpm/pub/packages/a%00b"));
        assert!(decoded_path_has_nul(
            "/api/v1/repositories/pub%00gen/artifacts/a"
        ));
        // Upper-case escapes, and every position in a segment.
        assert!(decoded_path_has_nul("/x/%00a"));
        assert!(decoded_path_has_nul("/x/a%00"));
        assert!(decoded_path_has_nul("/x/legit.txt%00../../etc/passwd"));
        // A raw NUL (defensive: the HTTP parser should never hand us one).
        assert!(decoded_path_has_nul("/x/a\0b"));
    }

    #[test]
    fn ordinary_paths_are_untouched() {
        assert!(!decoded_path_has_nul("/"));
        assert!(!decoded_path_has_nul(
            "/maven/repo/com/acme/app/1.0/app-1.0.jar"
        ));
        assert!(!decoded_path_has_nul(
            "/npm/repo/@scope%2fname/-/name-1.0.0.tgz"
        ));
        assert!(!decoded_path_has_nul(
            "/x/%E6%97%A5%E6%9C%AC%E8%AA%9E.tar.gz"
        ));
        // Other control bytes are NOT rejected — read routes must keep
        // serving every path an upload could have stored.
        assert!(!decoded_path_has_nul("/x/weird%09name%0A.bin"));
        // Double-encoded: `%2500` decodes to the literal text "%00".
        assert!(!decoded_path_has_nul("/x/a%2500b"));
        // Invalid escapes decode-fail and are left to the extractor.
        assert!(!decoded_path_has_nul("/x/a%zzb"));
    }

    async fn ok_handler() -> &'static str {
        "OK"
    }

    fn guarded_router() -> Router {
        Router::new()
            .route("/*path", get(ok_handler))
            .layer(middleware::from_fn(nul_path_guard))
    }

    #[tokio::test]
    #[allow(clippy::disallowed_methods)] // streaming-invariant: test-only read of a tiny middleware error body
    async fn nul_in_path_is_400_validation_error_before_the_handler() {
        let resp = guarded_router()
            .oneshot(
                Request::builder()
                    .uri("/maven/pub/a%00b")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let bytes = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let body = String::from_utf8_lossy(&bytes).to_lowercase();
        assert!(
            body.contains("validation_error"),
            "boundary rejection must be a VALIDATION_ERROR, got: {body}"
        );
        assert!(
            !body.contains("database") && !body.contains("utf8"),
            "the 400 must not leak driver/database detail, got: {body}"
        );
    }

    #[tokio::test]
    async fn a_path_without_a_nul_still_reaches_the_handler() {
        let resp = guarded_router()
            .oneshot(
                Request::builder()
                    .uri("/maven/pub/a%2500b")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "the guard must fire on the NUL alone, not on every escaped path"
        );
    }

    #[tokio::test]
    #[allow(clippy::disallowed_methods)] // streaming-invariant: test-only read of a tiny middleware error body
    async fn nul_on_the_oci_surface_is_the_spec_envelope() {
        let resp = guarded_router()
            .oneshot(
                Request::builder()
                    .uri("/v2/li%00brary/manifests/latest")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let bytes = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["errors"][0]["code"], "NAME_INVALID");
    }

    // ---------------------------------------------------------------------
    // #3622 router-level regressions: the exact requests from the report,
    // driven through the PRODUCTION router (`create_router`) so the layer's
    // registration is part of what is pinned, anonymous, on a PUBLIC
    // repository. Each case carries a control on the same route WITHOUT the
    // NUL, so the 400 is attributable to the NUL alone and cannot be a route
    // that now rejects everything.
    // ---------------------------------------------------------------------

    /// Every format-native wildcard route named in #3622 500'd on `a%00b`
    /// because the decoded path reached Postgres. They must all 400 now.
    #[tokio::test]
    async fn format_native_nul_paths_are_400_not_db_500_db() {
        use crate::api::handlers::test_db_helpers as tdh;

        for (format, nul_uri, control_uri) in [
            ("maven", "/maven/{k}/a%00b", "/maven/{k}/a/b/c-1.0.jar"),
            ("rpm", "/rpm/{k}/packages/a%00b", "/rpm/{k}/packages/a.rpm"),
            (
                "hex",
                "/hex/{k}/tarballs/a%00b",
                "/hex/{k}/tarballs/a-1.0.0.tar",
            ),
            (
                "puppet",
                "/puppet/{k}/v3/files/a%00b",
                "/puppet/{k}/v3/files/a-b-1.0.0.tar.gz",
            ),
            (
                "ansible",
                "/ansible/{k}/download/a%00b",
                "/ansible/{k}/download/a-b-1.0.0.tar.gz",
            ),
        ] {
            let Some(fx) = tdh::Fixture::setup("local", format).await else {
                return;
            };
            tdh::publish_repo(&fx.pool, fx.repo_id).await;
            let app = crate::api::routes::create_router(fx.state.clone());

            let (status, body) =
                tdh::send(app.clone(), tdh::get(nul_uri.replace("{k}", &fx.repo_key))).await;
            assert_eq!(
                status,
                StatusCode::BAD_REQUEST,
                "{format}: a NUL in the path must be a 400 at the boundary, \
                 not a 500 from the driver (body: {})",
                String::from_utf8_lossy(&body)
            );
            let body = String::from_utf8_lossy(&body).to_lowercase();
            assert!(
                !body.contains("database") && !body.contains("utf8"),
                "{format}: the 400 must not leak driver detail, got: {body}"
            );

            // Control: the same route, same repository, no NUL — must keep
            // its ordinary (non-400) outcome, proving the guard fires on the
            // NUL alone and the request otherwise reaches the handler.
            let (control, _) =
                tdh::send(app, tdh::get(control_uri.replace("{k}", &fx.repo_key))).await;
            assert_eq!(
                control,
                StatusCode::NOT_FOUND,
                "{format}: a legitimate missing path must still 404"
            );

            fx.teardown().await;
        }
    }

    /// The repository **key** segment itself: `/api/v1/repositories/pub%00gen/
    /// artifacts/a` reached `get_by_key` with a NUL and 500'd.
    #[tokio::test]
    async fn nul_in_the_repository_key_is_400_not_db_500_db() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        tdh::publish_repo(&fx.pool, fx.repo_id).await;
        let app = crate::api::routes::create_router(fx.state.clone());

        let (status, body) = tdh::send(
            app.clone(),
            tdh::get("/api/v1/repositories/pub%00gen/artifacts/a".to_string()),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "a NUL in the repository key must be a 400 (body: {})",
            String::from_utf8_lossy(&body)
        );

        // Control 1: a non-existent key WITHOUT a NUL still 404s — the guard
        // did not turn every unknown key into a 400.
        let (control, _) = tdh::send(
            app.clone(),
            tdh::get("/api/v1/repositories/pub0gen/artifacts/a".to_string()),
        )
        .await;
        assert_eq!(
            control,
            StatusCode::NOT_FOUND,
            "an ordinary unknown repository key must still 404"
        );

        // Control 2: the real public repository, ordinary missing artifact.
        let (control, _) = tdh::send(
            app,
            tdh::get(format!(
                "/api/v1/repositories/{}/artifacts/really/not/here.bin",
                fx.repo_key
            )),
        )
        .await;
        assert_eq!(
            control,
            StatusCode::NOT_FOUND,
            "a legitimate missing artifact must still 404"
        );

        fx.teardown().await;
    }
}
