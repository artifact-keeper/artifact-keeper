//! Reject a NUL byte anywhere in the decoded request path (#3622) or raw
//! query string (#3673).
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
//!
//! #3673 extends the same boundary to the **raw query string**, which the path
//! check cannot see: `?name=a%00b` and `?format=a%00b` on
//! `/api/v1/search/advanced`, and `?prefix=a%00b` on `/api/v1/search/suggest`,
//! each decoded to a `\0` that `SearchService` binds verbatim, so every one of
//! them was the same anonymous `500 DATABASE_ERROR`. Guarding the raw query
//! here closes every **percent-encoded** query carrier at once — including
//! parameters added later — instead of the three named filters, and needs no
//! per-handler code.
//!
//! Two classes are outside this boundary by construction, and are refused at
//! their own decoders instead:
//!
//! * A parameter that carries its own encoding. `?cursor=` on the artifact
//!   listing is base64 over JSON, so a `\u0000` inside it becomes a real `\0`
//!   with no percent-escape for the fast path to see;
//!   `handlers::repositories::decode_keyset_cursor` rejects it there.
//! * A JSON **body**, which is a stream — rejecting on it here would mean
//!   walking every request's bytes, binary uploads included. The one such site
//!   in #3673, `LoginRequest::username`, is refused at its own field with
//!   `extractors::deserialize_nul_free_string`; the remaining body fields are
//!   tracked in #3713.
//!
//! Unlike the path half, this is not free of behaviour change: a request
//! carrying a NUL anywhere in its query string is now refused, including on
//! parameters that previously tolerated it by stripping (`?q=` / `?query=`,
//! where `sanitize_tsquery_lexeme` dropped the byte and returned 200) and on
//! routes that never read the parameter at all (health probes, an unused
//! tracking parameter beside a working search). None of those could return
//! artifact content, and a NUL in a query string has no legitimate meaning on
//! any route, so refusing them is the intended trade rather than a side
//! effect.

use axum::{
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};

use super::oci_errors::{is_oci_v2_path, oci_denied_response};
use crate::error::AppError;

/// Whether the percent-decoded form of `raw` contains a NUL byte.
///
/// Used for both halves of the guard: the request path and the raw query
/// string percent-decode by the same rules, so the same predicate answers
/// both.
///
/// Pure (`&str` in, `bool` out) so the whole decision is unit-testable
/// without a router or a server. The two early returns keep this off the
/// allocation path for ordinary requests: a raw NUL cannot survive the HTTP
/// parser, and a path with no `%` decodes to itself.
///
/// The decision is made on **bytes**, never on a `String`: a NUL is a byte and
/// finding one needs no UTF-8 judgement. `urlencoding::decode` is
/// `decode_binary` plus a `String::from_utf8`, so it fails on a path whose
/// decoded bytes are not valid UTF-8 *anywhere* — and one stray `%C0%80` or
/// `%FF` in any segment would then hide a `%00` sitting in another one
/// (`/maven/pub%00key/a%C0%80b`), which the key-decoding visibility middleware
/// would still bind to a query. `decode_binary` is infallible, so no escape
/// elsewhere can blind the check — the same shape reaches the query string as
/// `?prefix=a%00b&x=%FF`. A malformed escape (`%zz`) is copied through
/// literally by the decoder and yields no NUL, so it keeps whatever status it
/// had before.
pub(crate) fn decoded_has_nul(raw: &str) -> bool {
    if raw.contains('\0') {
        return true;
    }
    if !raw.contains('%') {
        return false;
    }
    urlencoding::decode_binary(raw.as_bytes()).contains(&0)
}

/// Global layer rejecting a NUL byte in the decoded request path (#3622) or
/// raw query string (#3673) with a 400, before routing and before any handler
/// runs.
pub async fn nul_path_guard(request: Request, next: Next) -> Response {
    let path = request.uri().path();
    if decoded_has_nul(path) {
        return nul_refusal(path, "request path must not contain a NUL byte");
    }
    if request.uri().query().is_some_and(decoded_has_nul) {
        return nul_refusal(path, "request query string must not contain a NUL byte");
    }
    next.run(request).await
}

/// The 400 both halves of the guard answer with. `path` selects the envelope
/// only — the message is the whole of the response's request-dependence, so a
/// refusal is byte-identical for a real target, an unknown one and an unrouted
/// one, and can never become an existence oracle.
fn nul_refusal(path: &str, message: &str) -> Response {
    // #3284: a refusal on the OCI surface must be the distribution-spec
    // error envelope — docker/oras clients cannot render the REST shape.
    if is_oci_v2_path(path) {
        return oci_denied_response(StatusCode::BAD_REQUEST, "NAME_INVALID", message);
    }
    AppError::Validation(message.to_string()).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, middleware, routing::get, Router};
    use tower::ServiceExt;

    #[test]
    fn decoded_nul_is_detected_anywhere_in_the_path() {
        // The exact vectors from #3622.
        assert!(decoded_has_nul("/maven/pub/a%00b"));
        assert!(decoded_has_nul("/rpm/pub/packages/a%00b"));
        assert!(decoded_has_nul(
            "/api/v1/repositories/pub%00gen/artifacts/a"
        ));
        // Upper-case escapes, and every position in a segment.
        assert!(decoded_has_nul("/x/%00a"));
        assert!(decoded_has_nul("/x/a%00"));
        assert!(decoded_has_nul("/x/legit.txt%00../../etc/passwd"));
        // A raw NUL (defensive: the HTTP parser should never hand us one).
        assert!(decoded_has_nul("/x/a\0b"));
    }

    /// An invalid-UTF-8 escape ANYWHERE else in the path must not hide a NUL.
    /// Deciding on a decoded `String` made any such escape return `Err`, which
    /// read as "no NUL" and walked the `%00` straight into
    /// `repo_visibility_middleware`, which decodes the key segment on its own
    /// and binds it — one pool checkout and one wire-protocol failure per
    /// anonymous request, exactly the primitive this guard exists to remove.
    #[test]
    fn a_non_utf8_escape_elsewhere_does_not_blind_the_guard() {
        // Overlong encoding of NUL in a later segment, NUL in the key segment.
        assert!(decoded_has_nul("/maven/pub%00key/a%C0%80b"));
        // A lone continuation byte, same shape.
        assert!(decoded_has_nul("/maven/re%00po/%FF"));
        // ...and the plain control still detected, so the pair differs only in
        // the invalid escape.
        assert!(decoded_has_nul("/maven/re%00po/x"));
    }

    #[test]
    fn ordinary_paths_are_untouched() {
        assert!(!decoded_has_nul("/"));
        assert!(!decoded_has_nul("/maven/repo/com/acme/app/1.0/app-1.0.jar"));
        assert!(!decoded_has_nul("/npm/repo/@scope%2fname/-/name-1.0.0.tgz"));
        assert!(!decoded_has_nul("/x/%E6%97%A5%E6%9C%AC%E8%AA%9E.tar.gz"));
        // Other control bytes are NOT rejected — read routes must keep
        // serving every path an upload could have stored.
        assert!(!decoded_has_nul("/x/weird%09name%0A.bin"));
        // Double-encoded: `%2500` decodes to the literal text "%00".
        assert!(!decoded_has_nul("/x/a%2500b"));
        // A malformed escape is copied through literally by the decoder, so
        // it yields no NUL and keeps whatever status it had before.
        assert!(!decoded_has_nul("/x/a%zzb"));
        // Invalid UTF-8 with no NUL anywhere: not our refusal to make. Axum's
        // own param decoding already answers these with a 400.
        assert!(!decoded_has_nul("/x/%FF"));
        assert!(!decoded_has_nul("/maven/repo/a%C0%80b"));
    }

    /// #3673: the raw query string, decoded by exactly the same rules. The
    /// three sites from the report, plus every shape the path tests pin, so
    /// the query half cannot drift away from the path half.
    #[test]
    fn decoded_nul_is_detected_anywhere_in_the_query_string() {
        // The exact vectors from #3673 (raw query, no leading `?`).
        assert!(decoded_has_nul("name=a%00b"));
        assert!(decoded_has_nul("format=a%00b"));
        assert!(decoded_has_nul("prefix=a%00b"));
        // Any position, any parameter — including one no handler reads.
        assert!(decoded_has_nul("page=1&name=%00"));
        assert!(decoded_has_nul("unused=a%00b"));
        assert!(decoded_has_nul("q=a\0b"));
        // An invalid-UTF-8 escape in another parameter must not blind it —
        // the #3665 bypass shape, now on the query string.
        assert!(decoded_has_nul("prefix=a%00b&x=%C0%80"));
        assert!(decoded_has_nul("x=%FF&name=%00"));
    }

    #[test]
    fn ordinary_query_strings_are_untouched() {
        assert!(!decoded_has_nul(""));
        assert!(!decoded_has_nul("name=app&format=maven&page=2"));
        assert!(!decoded_has_nul("q=%E6%97%A5%E6%9C%AC%E8%AA%9E"));
        assert!(!decoded_has_nul("name=a+b&path=x%2Fy"));
        // Double-encoded: `%2500` decodes to the literal text "%00", which is
        // an ordinary search term and must still reach the handler.
        assert!(!decoded_has_nul("name=a%2500b"));
        // Other control bytes are NOT rejected — NUL-only, like the path.
        assert!(!decoded_has_nul("name=weird%09name%0A"));
        // Invalid UTF-8 with no NUL: not our refusal to make.
        assert!(!decoded_has_nul("x=%FF"));
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

    /// Both halves must answer the OCI surface with the distribution-spec
    /// envelope: docker/oras cannot render the REST shape. The query row is
    /// what stops a later refactor of `nul_refusal` from handing those clients
    /// the wrong body on a query NUL with no test noticing.
    #[tokio::test]
    #[allow(clippy::disallowed_methods)] // streaming-invariant: test-only read of a tiny middleware error body
    async fn nul_on_the_oci_surface_is_the_spec_envelope() {
        for uri in [
            "/v2/li%00brary/manifests/latest",
            // #3673: the NUL is in the query, the path is perfectly valid.
            "/v2/library/manifests/latest?x=a%00b",
            "/v2/_catalog?n=1&last=a%00b",
        ] {
            let resp = guarded_router()
                .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{uri}");
            let bytes = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
            let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(
                json["errors"][0]["code"], "NAME_INVALID",
                "{uri}: an OCI client must get the spec envelope, not the REST shape"
            );
        }
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

    /// The mixed vector end to end (F1 of the #3665 review): a NUL in the
    /// **key** segment plus an invalid-UTF-8 escape elsewhere. Deciding on a
    /// decoded `String` let this through the guard, and
    /// `repo_visibility_middleware` — which percent-decodes the key segment on
    /// its own, before axum's `Path` extractor ever runs — bound `re\0po` to
    /// `SELECT ... FROM repositories WHERE key = $1`. The status was a
    /// fail-closed 401/404 rather than a 500, but the pool checkout and the
    /// wire-protocol failure this guard exists to remove both survived.
    #[tokio::test]
    async fn mixed_invalid_utf8_escape_is_still_refused_at_the_boundary_db() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(fx) = tdh::Fixture::setup("local", "maven").await else {
            return;
        };
        tdh::publish_repo(&fx.pool, fx.repo_id).await;
        let app = crate::api::routes::create_router(fx.state.clone());

        for uri in ["/maven/pub%00key/a%C0%80b", "/maven/re%00po/%FF"] {
            let (status, body) = tdh::send(app.clone(), tdh::get(uri.to_string())).await;
            assert_eq!(
                status,
                StatusCode::BAD_REQUEST,
                "{uri}: an invalid-UTF-8 escape elsewhere must not hide the NUL \
                 (body: {})",
                String::from_utf8_lossy(&body)
            );
        }

        // Control: percent escapes that are valid UTF-8 and carry no NUL are
        // untouched — the guard fires on the NUL, not on the presence of `%`.
        let (control, _) =
            tdh::send(app, tdh::get(format!("/maven/{}/a%C3%A9b", fx.repo_key))).await;
        assert_eq!(
            control,
            StatusCode::NOT_FOUND,
            "an escaped but NUL-free path must still reach the handler and 404"
        );

        fx.teardown().await;
    }

    /// The two properties the registration comment in `routes.rs` asserts:
    /// the refusal is emitted INSIDE correlation-id (so it still carries the
    /// header operators correlate on), and it is byte-identical for a real
    /// repository, an unknown one and an unrouted path — answering before
    /// authentication must not become an existence oracle.
    #[tokio::test]
    async fn nul_refusal_carries_correlation_id_and_is_byte_identical_db() {
        use crate::api::handlers::test_db_helpers as tdh;
        use crate::api::middleware::tracing::CORRELATION_ID_HEADER;

        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        tdh::publish_repo(&fx.pool, fx.repo_id).await;
        let app = crate::api::routes::create_router(fx.state.clone());

        let mut bodies: Vec<(String, bytes::Bytes)> = Vec::new();
        for uri in [
            // real, public repository
            format!("/api/v1/repositories/{}/artifacts/a%00b", fx.repo_key),
            // repository that does not exist
            "/api/v1/repositories/no%00such/artifacts/a".to_string(),
            // no route at all
            "/nothing/here/a%00b".to_string(),
        ] {
            let (status, body, headers) =
                tdh::send_with_headers(app.clone(), tdh::get(uri.clone())).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{uri}");
            assert!(
                headers.get(CORRELATION_ID_HEADER).is_some(),
                "{uri}: the refusal must be emitted inside correlation-id, so \
                 moving the layer outside it fails here rather than silently \
                 dropping the header"
            );
            bodies.push((uri, body));
        }
        let (first_uri, first) = &bodies[0];
        for (uri, body) in &bodies[1..] {
            assert_eq!(
                body, first,
                "{uri} and {first_uri} must be byte-identical: the refusal \
                 depends only on the request bytes, never on what exists"
            );
        }

        fx.teardown().await;
    }

    // ---------------------------------------------------------------------
    // #3673 router-level regressions: the four requests from the report,
    // driven through the PRODUCTION router (`create_router`), anonymous, each
    // with a control on the same route WITHOUT the NUL so the 400 is
    // attributable to the NUL alone.
    // ---------------------------------------------------------------------

    /// The three query-parameter sites. Each 500'd because the decoded `\0`
    /// was bound verbatim (`build_name_filter`, the suggest prefix); each must
    /// now be refused at the boundary, and the control must still be answered
    /// normally.
    #[tokio::test]
    async fn nul_in_search_query_params_is_400_not_db_500_db() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        tdh::publish_repo(&fx.pool, fx.repo_id).await;
        let app = crate::api::routes::create_router(fx.state.clone());

        for (nul_uri, control_uri) in [
            (
                "/api/v1/search/advanced?name=a%00b",
                "/api/v1/search/advanced?name=ab",
            ),
            (
                "/api/v1/search/advanced?format=a%00b",
                "/api/v1/search/advanced?format=ab",
            ),
            (
                "/api/v1/search/suggest?prefix=a%00b",
                "/api/v1/search/suggest?prefix=ab",
            ),
        ] {
            let (status, body) = tdh::send(app.clone(), tdh::get(nul_uri.to_string())).await;
            assert_eq!(
                status,
                StatusCode::BAD_REQUEST,
                "{nul_uri}: a NUL in the query string must be a 400 at the \
                 boundary, not a 500 from the driver (body: {})",
                String::from_utf8_lossy(&body)
            );
            let text = String::from_utf8_lossy(&body).to_lowercase();
            assert!(
                !text.contains("database") && !text.contains("utf8"),
                "{nul_uri}: the 400 must not leak driver detail, got: {text}"
            );

            // Control: the same parameter on the same route without the NUL
            // must still be answered normally, so the guard cannot be a route
            // that now rejects everything.
            let (control, body) = tdh::send(app.clone(), tdh::get(control_uri.to_string())).await;
            assert_eq!(
                control,
                StatusCode::OK,
                "{control_uri}: the same request without the NUL must still be \
                 answered normally (body: {})",
                String::from_utf8_lossy(&body)
            );
        }

        fx.teardown().await;
    }

    /// The JSON-body site: `username` reaches `WHERE username = $1` before
    /// anything else runs, so a `\0` in it was an anonymous 500 where the
    /// identical request without it is a 401. Refused by the field's
    /// `deserialize_nul_free_string` hook, inside the `Json` extractor.
    #[tokio::test]
    async fn nul_in_login_username_is_400_not_db_500_db() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let app = crate::api::routes::create_router(fx.state.clone());

        let login = |body: &str| {
            tdh::post(
                "/api/v1/auth/login".to_string(),
                "application/json",
                bytes::Bytes::copy_from_slice(body.as_bytes()),
            )
        };

        // `\u0000` is a well-formed JSON escape, so the body parses and the
        // NUL lands in the `String` — exactly the request from the report.
        let (status, body) = tdh::send(
            app.clone(),
            login(r#"{"username":"a\u0000b","password":"x"}"#),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "a NUL in the login username must be a 400 from the extractor, \
             not a 500 from the driver (body: {})",
            String::from_utf8_lossy(&body)
        );
        let text = String::from_utf8_lossy(&body).to_lowercase();
        assert!(
            !text.contains("database") && !text.contains("utf8"),
            "the 400 must not leak driver detail, got: {text}"
        );

        // Control: the same request with the NUL removed keeps its ordinary
        // outcome — an unknown user is still a 401, not a 400.
        let (control, body) = tdh::send(app, login(r#"{"username":"ab","password":"x"}"#)).await;
        assert_eq!(
            control,
            StatusCode::UNAUTHORIZED,
            "an ordinary unknown login must still 401 (body: {})",
            String::from_utf8_lossy(&body)
        );

        fx.teardown().await;
    }

    /// The query half of the guard must hold the two properties #3665 pins for
    /// the path half: the refusal carries X-Correlation-ID, and it is
    /// byte-identical for a real repository, an unknown one and an unrouted
    /// path — answering before authentication must not become an oracle.
    #[tokio::test]
    async fn nul_query_refusal_carries_correlation_id_and_is_byte_identical_db() {
        use crate::api::handlers::test_db_helpers as tdh;
        use crate::api::middleware::tracing::CORRELATION_ID_HEADER;

        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        tdh::publish_repo(&fx.pool, fx.repo_id).await;
        let app = crate::api::routes::create_router(fx.state.clone());

        let mut bodies: Vec<(String, bytes::Bytes)> = Vec::new();
        for uri in [
            // a real, routed surface
            "/api/v1/search/advanced?name=a%00b".to_string(),
            // a repository that exists, and one that does not
            format!("/api/v1/repositories/{}/artifacts?q=a%00b", fx.repo_key),
            "/api/v1/repositories/no-such-repo/artifacts?q=a%00b".to_string(),
            // no route at all
            "/nothing/here?x=a%00b".to_string(),
        ] {
            let (status, body, headers) =
                tdh::send_with_headers(app.clone(), tdh::get(uri.clone())).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{uri}");
            assert!(
                headers.get(CORRELATION_ID_HEADER).is_some(),
                "{uri}: the refusal must be emitted inside correlation-id, so \
                 moving the layer outside it fails here rather than silently \
                 dropping the header"
            );
            bodies.push((uri, body));
        }
        let (first_uri, first) = &bodies[0];
        for (uri, body) in &bodies[1..] {
            assert_eq!(
                body, first,
                "{uri} and {first_uri} must be byte-identical: the refusal \
                 depends only on the request bytes, never on what exists"
            );
        }

        fx.teardown().await;
    }

    /// #3673 round 2: a query parameter that carries its own encoding is
    /// invisible to this guard by construction — `?cursor=` on the artifact
    /// listing is base64 over JSON, so `serde_json` turns a ` `
    /// escape into a real `\0` with no `%` anywhere for `decoded_has_nul` to
    /// find. The cursor's two components are bound as `after_path` /
    /// `after_name`, so this was the same anonymous 500 on a public
    /// repository, WITH the query guard applied. Refused at its own decoder
    /// (`handlers::repositories::decode_keyset_cursor`); the regression lives
    /// here so every #3673 site is pinned in one place.
    #[tokio::test]
    async fn nul_in_a_base64_cursor_is_400_not_db_500_db() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        tdh::publish_repo(&fx.pool, fx.repo_id).await;
        let app = crate::api::routes::create_router(fx.state.clone());

        // base64url(`["a b",""]`) — no `%` in the request at all.
        let (status, body) = tdh::send(
            app.clone(),
            tdh::get(format!(
                "/api/v1/repositories/{}/artifacts?cursor=WyJhXHUwMDAwYiIsIiJd",
                fx.repo_key
            )),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "a NUL inside a base64 cursor must be a 400 from the cursor \
             decoder, not a 500 from the driver (body: {})",
            String::from_utf8_lossy(&body)
        );
        let text = String::from_utf8_lossy(&body).to_lowercase();
        assert!(
            !text.contains("database") && !text.contains("utf8"),
            "the 400 must not leak driver detail, got: {text}"
        );

        // Control: base64url(`["ab",""]`) — the same cursor without the NUL is
        // a well-formed cursor and must still be answered normally.
        let (control, body) = tdh::send(
            app,
            tdh::get(format!(
                "/api/v1/repositories/{}/artifacts?cursor=WyJhYiIsIiJd",
                fx.repo_key
            )),
        )
        .await;
        assert_eq!(
            control,
            StatusCode::OK,
            "a NUL-free cursor must still list normally (body: {})",
            String::from_utf8_lossy(&body)
        );

        fx.teardown().await;
    }
}
