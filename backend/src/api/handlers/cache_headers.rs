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
///
/// `vary`, when `Some`, is echoed as the `Vary` header on the `304`. Callers
/// whose representation is content-negotiated (e.g. PyPI's `Accept`-driven
/// HTML vs PEP 691 JSON) must pass it so a shared cache keys the stored `304`
/// on the same request dimension as the `200`, and never mixes variants.
pub fn check_conditional_request(
    headers: &HeaderMap,
    etag: &str,
    vary: Option<&str>,
) -> Option<Response> {
    let if_none_match = headers.get(IF_NONE_MATCH).and_then(|v| v.to_str().ok())?;
    if if_none_match == "*" || if_none_match.split(',').any(|t| t.trim() == etag) {
        let mut builder = Response::builder()
            .status(StatusCode::NOT_MODIFIED)
            .header(ETAG, etag)
            .header(CACHE_CONTROL, DEFAULT_CACHE_CONTROL);
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
///
/// `body` is generic over `Into<Body> + AsRef<[u8]>` so callers holding a
/// `bytes::Bytes` (e.g. a proxied upstream index) can pass it directly: the
/// ETag is hashed from `body.as_ref()` and the body is moved into the response
/// without an intermediate `Vec` copy. `Vec<u8>` and `String` callers keep
/// working unchanged.
///
/// `vary`, when `Some`, is emitted as the `Vary` header on both the `200` and
/// the `304` (see [`check_conditional_request`]). Pass `Some("Accept")` for
/// responses whose representation is selected by the request `Accept` header so
/// shared caches don't serve one client's variant to another; pass `None` for
/// single-representation resources.
pub fn cacheable_response(
    body: impl Into<Body> + AsRef<[u8]>,
    content_type: &str,
    headers: &HeaderMap,
    vary: Option<&str>,
) -> Response {
    let etag = compute_etag(body.as_ref());

    if let Some(not_modified) = check_conditional_request(headers, &etag, vary) {
        return not_modified;
    }

    let content_length = body.as_ref().len();
    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, content_type)
        .header(CONTENT_LENGTH, content_length.to_string())
        .header(ETAG, &etag)
        .header(CACHE_CONTROL, DEFAULT_CACHE_CONTROL);
    if let Some(vary) = vary {
        builder = builder.header(VARY, vary);
    }
    builder.body(body.into()).unwrap()
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
        let r = check_conditional_request(&h, &etag, None);
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
        assert!(check_conditional_request(&h, &etag, None).is_some());
    }

    #[test]
    fn check_returns_none_on_mismatch() {
        let etag = compute_etag(b"abc");
        let mut h = empty_headers();
        h.insert(
            IF_NONE_MATCH,
            HeaderValue::from_str("\"completely-different\"").unwrap(),
        );
        assert!(check_conditional_request(&h, &etag, None).is_none());
    }

    #[test]
    fn check_returns_none_without_if_none_match_header() {
        let etag = compute_etag(b"abc");
        let h = empty_headers();
        assert!(check_conditional_request(&h, &etag, None).is_none());
    }

    #[test]
    fn check_handles_comma_separated_list() {
        let etag = compute_etag(b"abc");
        let mut h = empty_headers();
        let list = format!("W/\"old1\", {}, W/\"old2\"", etag);
        h.insert(IF_NONE_MATCH, HeaderValue::from_str(&list).unwrap());
        assert!(check_conditional_request(&h, &etag, None).is_some());
    }

    // Tests for cacheable_response
    #[test]
    fn cacheable_response_200_on_new_request() {
        let body = b"hello".to_vec();
        let r = cacheable_response(body.clone(), "text/xml", &empty_headers(), None);
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
        let r = cacheable_response(body, "text/xml", &h, None);
        assert_eq!(r.status(), StatusCode::NOT_MODIFIED);
    }

    #[test]
    fn cacheable_response_accepts_bytes_body_with_same_etag() {
        // The zero-copy proxy path passes a `bytes::Bytes`; it must hash and
        // serve identically to the `Vec<u8>` path.
        let raw = b"proxied index body".to_vec();
        let via_bytes = cacheable_response(
            bytes::Bytes::from(raw.clone()),
            "text/html",
            &empty_headers(),
            None,
        );
        assert_eq!(via_bytes.status(), StatusCode::OK);
        assert_eq!(
            via_bytes.headers().get(ETAG).unwrap().to_str().unwrap(),
            compute_etag(&raw)
        );

        let etag = compute_etag(&raw);
        let mut h = empty_headers();
        h.insert(IF_NONE_MATCH, HeaderValue::from_str(&etag).unwrap());
        let not_modified = cacheable_response(bytes::Bytes::from(raw), "text/html", &h, None);
        assert_eq!(not_modified.status(), StatusCode::NOT_MODIFIED);
    }

    #[test]
    fn cacheable_response_emits_vary_on_200_and_304() {
        let body = b"hello".to_vec();
        let r = cacheable_response(body.clone(), "text/html", &empty_headers(), Some("Accept"));
        assert_eq!(r.headers().get(VARY).unwrap(), "Accept");

        let etag = compute_etag(&body);
        let mut h = empty_headers();
        h.insert(IF_NONE_MATCH, HeaderValue::from_str(&etag).unwrap());
        let nm = cacheable_response(body, "text/html", &h, Some("Accept"));
        assert_eq!(nm.status(), StatusCode::NOT_MODIFIED);
        assert_eq!(nm.headers().get(VARY).unwrap(), "Accept");
    }
}
