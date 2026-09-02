//! Shared HTTP cache header helpers.
//!
//! Provides [`compute_etag`], [`check_conditional_request`], and
//! [`cacheable_response`] so handlers that serve cacheable resources (Conda
//! repodata, Maven `maven-metadata.xml`, future format index files) emit
//! consistent `ETag`, `Cache-Control`, and `If-None-Match` -> `304` behavior
//! without duplicating the boilerplate.
//!
//! Pattern lifted from `api/handlers/conda.rs::cacheable_response` and made
//! shared per #2079 so adding HTTP caching to a new format handler only
//! requires importing these three helpers — no copy/paste, no divergence.

use axum::body::Body;
use axum::http::header::{CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE, ETAG, IF_NONE_MATCH, VARY};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use sha2::{Digest, Sha256};

/// Default `Cache-Control` value used by [`cacheable_response`] for mutable
/// metadata resources (matches typical Maven Central / Nexus TTLs and lets
/// clients revalidate every minute without an unconditional refetch).
pub const DEFAULT_CACHE_CONTROL: &str = "public, max-age=60";

/// `Cache-Control` for a response whose body depends on WHO asked (#3406).
///
/// `private` forbids a *shared* cache from storing the response at all while
/// still letting the requesting client cache it for the same 60s. Note this is
/// not merely "nicer": under RFC 9111 §3.5 a shared cache must not store a
/// response to a request bearing `Authorization` **unless the response
/// explicitly permits it**, and `public` is exactly that explicit permission.
/// Emitting `public` on a credentialed request therefore *opts in* to the
/// unsafe behaviour rather than merely failing to opt out.
pub const PRIVATE_CACHE_CONTROL: &str = "private, max-age=60";

/// `Vary` value for a body selected by the request's `Accept` header.
pub const VARY_ACCEPT: &str = "Accept";

/// Choose the `Cache-Control` directive for a response whose body may depend on
/// the caller's identity (#3406).
///
/// AK's format indexes are caller-dependent: a virtual repository's listing is
/// built from the members the *caller* is authorized to read (#2073 / #3323 /
/// #3399), and a private repository's listing requires credentials at all. Two
/// callers therefore get different bodies for the same URL, so a shared cache
/// must not be allowed to store one and replay it to the other.
///
/// The credential test is deliberately shape-based (does the request carry a
/// credential), not outcome-based (did it authenticate): an anonymous read of a
/// public repo keeps the `public` directive and stays CDN-cacheable, which is
/// the case the 60s TTL exists for.
pub fn negotiated_cache_control(request_headers: &HeaderMap) -> &'static str {
    if crate::api::middleware::auth::request_carries_credentials(request_headers) {
        PRIVATE_CACHE_CONTROL
    } else {
        DEFAULT_CACHE_CONTROL
    }
}

/// Compute a quoted ETag from the SHA-256 of the response body bytes.
///
/// The double-quoted form is what `If-None-Match` carries on the wire, so we
/// always emit the canonical form here to keep equality comparison cheap and
/// avoid a quoting layer at the comparison site.
pub fn compute_etag(body: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(body);
    let hash = format!("{:x}", hasher.finalize());
    format!("\"{}\"", hash)
}

/// Check the request's `If-None-Match` against the computed ETag.
///
/// Returns a `304 Not Modified` [`Response`] when the client's cached version
/// matches (exact ETag, comma-separated list, or the wildcard `*`). Returns
/// `None` when the request should proceed to a full `200` response. The
/// returned `304` re-emits the matching `ETag` and `Cache-Control` so the
/// client can refresh its freshness lifetime without an unconditional GET.
pub fn check_conditional_request(headers: &HeaderMap, etag: &str) -> Option<Response> {
    check_conditional_request_with(headers, etag, DEFAULT_CACHE_CONTROL, None)
}

/// [`check_conditional_request`] with an explicit `Cache-Control` and `Vary`.
///
/// A `304` carries the same cache-key metadata as the `200` it stands in for —
/// a `304` that omits `Vary` lets a shared cache attach the revalidated
/// freshness to the *wrong* stored representation, which is the same RFC 9110
/// §12.5.1 defect one status code over (#3406).
pub fn check_conditional_request_with(
    headers: &HeaderMap,
    etag: &str,
    cache_control: &str,
    vary: Option<&str>,
) -> Option<Response> {
    let if_none_match = headers.get(IF_NONE_MATCH).and_then(|v| v.to_str().ok())?;
    if if_none_match == "*" || if_none_match.split(',').any(|t| t.trim() == etag) {
        let mut builder = Response::builder()
            .status(StatusCode::NOT_MODIFIED)
            .header(ETAG, etag)
            .header(CACHE_CONTROL, cache_control);
        if let Some(vary) = vary {
            builder = builder.header(VARY, vary);
        }
        Some(builder.body(Body::empty()).unwrap())
    } else {
        None
    }
}

/// Build a `200 OK` cacheable response with `ETag` + `Cache-Control`, or a
/// `304 Not Modified` if the request's `If-None-Match` already matches.
///
/// `content_type` is the response MIME type (e.g. `"text/xml"` for Maven
/// metadata, `"application/json"` for Conda repodata). `headers` must be the
/// request's `HeaderMap` so `If-None-Match` can be inspected.
pub fn cacheable_response(body: Vec<u8>, content_type: &str, headers: &HeaderMap) -> Response {
    cacheable_response_with(body, content_type, headers, DEFAULT_CACHE_CONTROL, None)
}

/// [`cacheable_response`] for a body the client SELECTED via request headers
/// (#3406).
///
/// Emits `Vary: Accept` so a shared cache keys the stored entry on the
/// selecting header, and downgrades `Cache-Control` to `private` when the
/// request carried a credential (see [`negotiated_cache_control`]).
///
/// Use this — not [`cacheable_response`] — wherever `content_type` is derived
/// from the request rather than fixed by the route. Without `Vary`, RFC 9110
/// §12.5.1 lets an intermediary serve the stored PEP 691 JSON index to a client
/// that asked for PEP 503 HTML (and validate one representation's `ETag`
/// against the other's) — `uv` rejects a simple index whose `Content-Type` is
/// not one it accepts, so the mis-served representation is a hard install
/// failure, not a cosmetic one.
pub fn negotiated_cacheable_response(
    body: Vec<u8>,
    content_type: &str,
    headers: &HeaderMap,
) -> Response {
    cacheable_response_with(
        body,
        content_type,
        headers,
        negotiated_cache_control(headers),
        Some(VARY_ACCEPT),
    )
}

/// [`cacheable_response`] with an explicit `Cache-Control` and `Vary`.
pub fn cacheable_response_with(
    body: Vec<u8>,
    content_type: &str,
    headers: &HeaderMap,
    cache_control: &str,
    vary: Option<&str>,
) -> Response {
    let etag = compute_etag(&body);

    if let Some(not_modified) = check_conditional_request_with(headers, &etag, cache_control, vary)
    {
        return not_modified;
    }

    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, content_type)
        .header(CONTENT_LENGTH, body.len().to_string())
        .header(ETAG, &etag)
        .header(CACHE_CONTROL, cache_control);
    if let Some(vary) = vary {
        builder = builder.header(VARY, vary);
    }
    builder.body(Body::from(body)).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn empty_headers() -> HeaderMap {
        HeaderMap::new()
    }

    #[test]
    fn etag_is_quoted_sha256() {
        let etag = compute_etag(b"hello");
        assert!(etag.starts_with('"'));
        assert!(etag.ends_with('"'));
        // sha256("hello") =
        //   2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
        assert!(etag.contains("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"));
    }

    #[test]
    fn etag_is_deterministic() {
        assert_eq!(compute_etag(b"abc"), compute_etag(b"abc"));
        assert_ne!(compute_etag(b"abc"), compute_etag(b"abd"));
    }

    #[test]
    fn etag_changes_with_content() {
        assert_ne!(compute_etag(b"content A"), compute_etag(b"content B"));
    }

    // Tests for check_conditional_request
    #[test]
    fn check_returns_some_on_exact_match() {
        let body = b"abc";
        let etag = compute_etag(body);
        let mut h = empty_headers();
        h.insert(IF_NONE_MATCH, HeaderValue::from_str(&etag).unwrap());
        let r = check_conditional_request(&h, &etag);
        assert!(r.is_some());
        let r = r.unwrap();
        assert_eq!(r.status(), StatusCode::NOT_MODIFIED);
        assert_eq!(r.headers().get(ETAG).unwrap().to_str().unwrap(), etag);
        assert_eq!(
            r.headers().get(CACHE_CONTROL).unwrap(),
            DEFAULT_CACHE_CONTROL
        );
    }

    #[test]
    fn check_returns_some_on_wildcard() {
        let etag = compute_etag(b"abc");
        let mut h = empty_headers();
        h.insert(IF_NONE_MATCH, HeaderValue::from_static("*"));
        assert!(check_conditional_request(&h, &etag).is_some());
    }

    #[test]
    fn check_returns_none_on_mismatch() {
        let etag = compute_etag(b"abc");
        let mut h = empty_headers();
        h.insert(
            IF_NONE_MATCH,
            HeaderValue::from_str("\"completely-different\"").unwrap(),
        );
        assert!(check_conditional_request(&h, &etag).is_none());
    }

    #[test]
    fn check_returns_none_without_if_none_match_header() {
        let etag = compute_etag(b"abc");
        let h = empty_headers();
        assert!(check_conditional_request(&h, &etag).is_none());
    }

    #[test]
    fn check_handles_comma_separated_list() {
        let etag = compute_etag(b"abc");
        let mut h = empty_headers();
        let list = format!("W/\"old1\", {}, W/\"old2\"", etag);
        h.insert(IF_NONE_MATCH, HeaderValue::from_str(&list).unwrap());
        assert!(check_conditional_request(&h, &etag).is_some());
    }

    // Tests for cacheable_response
    #[test]
    fn cacheable_response_200_on_new_request() {
        let body = b"hello".to_vec();
        let r = cacheable_response(body.clone(), "text/xml", &empty_headers());
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(r.headers().get(CONTENT_TYPE).unwrap(), "text/xml");
        assert_eq!(
            r.headers().get(CONTENT_LENGTH).unwrap().to_str().unwrap(),
            body.len().to_string()
        );
        let etag = r.headers().get(ETAG).unwrap().to_str().unwrap().to_string();
        assert_eq!(etag, compute_etag(&body));
        assert_eq!(
            r.headers().get(CACHE_CONTROL).unwrap(),
            DEFAULT_CACHE_CONTROL
        );
    }

    #[test]
    fn cacheable_response_304_on_matching_if_none_match() {
        let body = b"hello".to_vec();
        let etag = compute_etag(&body);
        let mut h = empty_headers();
        h.insert(IF_NONE_MATCH, HeaderValue::from_str(&etag).unwrap());
        let r = cacheable_response(body, "text/xml", &h);
        assert_eq!(r.status(), StatusCode::NOT_MODIFIED);
    }

    // -----------------------------------------------------------------------
    // #3406: content-negotiated responses must declare their selecting header
    // and must not invite a SHARED cache to store a credentialed response.
    // -----------------------------------------------------------------------

    fn accept(value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("accept", HeaderValue::from_str(value).unwrap());
        h
    }

    /// The non-negotiated helper is unchanged: no `Vary`, still `public`.
    /// Adding `Vary` unconditionally would needlessly fragment the caches of
    /// every fixed-`Content-Type` caller (Maven metadata, Conda repodata).
    #[test]
    fn plain_cacheable_response_declares_no_vary() {
        let r = cacheable_response(b"x".to_vec(), "text/xml", &empty_headers());
        assert!(r.headers().get(VARY).is_none());
        assert_eq!(
            r.headers().get(CACHE_CONTROL).unwrap(),
            DEFAULT_CACHE_CONTROL
        );
    }

    #[test]
    fn negotiated_response_declares_vary_accept() {
        let r = negotiated_cacheable_response(
            b"{}".to_vec(),
            "application/vnd.pypi.simple.v1+json",
            &accept("application/vnd.pypi.simple.v1+json"),
        );
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(r.headers().get(VARY).unwrap(), "Accept");
    }

    /// The core of #3406: the two representations of the SAME logical index
    /// carry different `ETag`s (the ETag is a hash of the body), so without
    /// `Vary: Accept` a shared cache may store one and serve it — or validate
    /// its `ETag` — for a client that asked for the other. Both halves must
    /// declare the selecting header.
    #[test]
    fn both_negotiated_representations_declare_vary_and_differ_by_etag() {
        let json = negotiated_cacheable_response(
            br#"{"files":[]}"#.to_vec(),
            "application/vnd.pypi.simple.v1+json",
            &accept("application/vnd.pypi.simple.v1+json"),
        );
        let html = negotiated_cacheable_response(
            b"<html></html>".to_vec(),
            "text/html; charset=utf-8",
            &accept("text/html"),
        );

        assert_eq!(json.headers().get(VARY).unwrap(), "Accept");
        assert_eq!(html.headers().get(VARY).unwrap(), "Accept");
        assert_ne!(
            json.headers().get(ETAG).unwrap(),
            html.headers().get(ETAG).unwrap(),
            "the two representations must not share an ETag; that is what makes \
             a missing Vary a cross-representation 304"
        );
        assert_ne!(
            json.headers().get(CONTENT_TYPE).unwrap(),
            html.headers().get(CONTENT_TYPE).unwrap()
        );
    }

    /// A `304` stands in for the `200` it revalidates, so it must carry the
    /// same cache-key metadata. A `304` without `Vary` lets a shared cache
    /// refresh the wrong stored representation.
    #[test]
    fn negotiated_304_carries_vary_and_cache_control() {
        let body = br#"{"files":[]}"#.to_vec();
        let etag = compute_etag(&body);
        let mut h = accept("application/vnd.pypi.simple.v1+json");
        h.insert(IF_NONE_MATCH, HeaderValue::from_str(&etag).unwrap());

        let r = negotiated_cacheable_response(body, "application/vnd.pypi.simple.v1+json", &h);
        assert_eq!(r.status(), StatusCode::NOT_MODIFIED);
        assert_eq!(r.headers().get(VARY).unwrap(), "Accept");
        assert_eq!(
            r.headers().get(CACHE_CONTROL).unwrap(),
            DEFAULT_CACHE_CONTROL
        );
    }

    /// An anonymous read of a public repo keeps `public`: the 60s shared-cache
    /// TTL exists for exactly this case and downgrading it wholesale would be a
    /// real regression for CDN-fronted deployments.
    #[test]
    fn anonymous_request_stays_publicly_cacheable() {
        assert_eq!(
            negotiated_cache_control(&accept("text/html")),
            DEFAULT_CACHE_CONTROL
        );
    }

    /// Every credential carrier `extract_token` accepts must downgrade the
    /// directive. A virtual repo's index is built from the members the CALLER
    /// may read (#2073/#3323/#3399), so `public` would let an intermediary
    /// replay one caller's filtered listing to another. Under RFC 9111 §3.5
    /// `public` is also the explicit permission that overrides a shared cache's
    /// default refusal to store an `Authorization`-bearing response.
    #[test]
    fn credentialed_request_is_private_for_every_carrier() {
        for (name, value) in [
            ("authorization", "Basic dXNlcjpwYXNz"),
            ("authorization", "Bearer tok"),
            ("x-api-key", "ak_key_abc"),
            ("cookie", "ak_access_token=jwt-here"),
        ] {
            let mut h = accept("application/vnd.pypi.simple.v1+json");
            h.insert(name, HeaderValue::from_str(value).unwrap());
            assert_eq!(
                negotiated_cache_control(&h),
                PRIVATE_CACHE_CONTROL,
                "a request credentialed via {name}: {value} must not be shared-cacheable"
            );

            let r = negotiated_cacheable_response(
                b"{}".to_vec(),
                "application/vnd.pypi.simple.v1+json",
                &h,
            );
            assert_eq!(
                r.headers().get(CACHE_CONTROL).unwrap(),
                PRIVATE_CACHE_CONTROL
            );
            assert_eq!(r.headers().get(VARY).unwrap(), "Accept");
        }
    }

    /// An unrelated cookie is not a credential and must not cost the public
    /// directive.
    #[test]
    fn unrelated_cookie_is_not_a_credential() {
        let mut h = accept("text/html");
        h.insert("cookie", HeaderValue::from_static("theme=dark; lang=en"));
        assert_eq!(negotiated_cache_control(&h), DEFAULT_CACHE_CONTROL);
    }
}
