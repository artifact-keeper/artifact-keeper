//! Public endpoint for presigned download URLs (#4417).
//!
//! The backend talks to its object store over whatever address it can reach
//! (`S3_ENDPOINT`, `AZURE_STORAGE_ENDPOINT`), which in a cluster is usually an
//! in-cluster service name such as `http://storage-minio:9000`. A presigned
//! redirect hands that URL to the *client*, which cannot resolve it. The
//! public endpoint is the address clients use instead. It is used only to
//! build (and, for S3, to sign) the URLs handed to clients; the backend's own
//! storage calls keep the internal endpoint.

use crate::error::{AppError, Result};

/// Whether the public endpoint may carry a path.
///
/// S3 SigV4 signs the request path, so an S3 public endpoint behind a reverse
/// proxy that strips a path prefix would produce URLs the object store
/// rejects; the S3 public endpoint must therefore be a bare origin. Azure SAS
/// tokens sign the account/container/blob names but not the host or path, and
/// a path-style endpoint (Azurite, some gateways) carries the account name in
/// the path, so Azure allows one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EndpointPath {
    /// Origin only (`scheme://host[:port]`).
    Forbidden,
    /// Origin plus an optional path (trailing slash removed).
    Allowed,
}

/// Parse and validate an operator-supplied public endpoint.
///
/// Empty (or whitespace-only) means "not configured" and returns `Ok(None)`,
/// so presigned URLs keep the internal endpoint exactly as before. Otherwise
/// the value must be an absolute `http`/`https` URL with a host and no
/// userinfo, query or fragment (and no path when `path` is
/// [`EndpointPath::Forbidden`]). This is operator configuration, so there is
/// no SSRF filtering: the check only rejects values that cannot be a working
/// endpoint, at startup rather than as broken redirects later.
///
/// The returned value is normalised: lower-cased scheme and host, default
/// port dropped, no trailing slash.
pub(crate) fn parse_public_endpoint(
    var: &str,
    raw: &str,
    path: EndpointPath,
) -> Result<Option<String>> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(None);
    }
    // The value is echoed into a fatal startup error (or a WARN for a
    // secondary backend), so never with its userinfo: a value refused for
    // carrying credentials must not log them (#4503).
    let shown = redact_userinfo(raw);
    let invalid = |why: &str| AppError::Config(format!("{var}={shown:?} is invalid: {why}"));
    let url = url::Url::parse(raw).map_err(|e| invalid(&format!("not an absolute URL ({e})")))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(invalid("the scheme must be http or https"));
    }
    if url.host_str().is_none_or(str::is_empty) {
        return Err(invalid("the URL has no host"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(invalid("credentials (user:password@) are not allowed"));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(invalid("a query string or fragment is not allowed"));
    }
    let url_path = url.path().trim_end_matches('/');
    if path == EndpointPath::Forbidden && !url_path.is_empty() {
        return Err(invalid(
            "a path is not allowed; give only scheme://host[:port] (the signature covers \
             the request path, so a path-rewriting proxy would invalidate it)",
        ));
    }
    let origin = &url[..url::Position::BeforePath];
    Ok(Some(format!("{origin}{url_path}")))
}

/// `raw` with any userinfo (`user:password@`) in its authority replaced by
/// `***`, for error messages (#4503). Works on the raw text, not on a parsed
/// URL, so a value too malformed to parse is redacted too: the authority is
/// what follows `scheme://` (or the start, without one) up to the first `/`,
/// `?` or `#`, and everything before its last `@` is userinfo.
fn redact_userinfo(raw: &str) -> String {
    let start = raw.find("://").map_or(0, |i| i + 3);
    let rest = &raw[start..];
    let authority_len = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    match rest[..authority_len].rfind('@') {
        Some(at) => format!("{}***{}", &raw[..start], &rest[at..]),
        None => raw.to_string(),
    }
}

/// Read and validate the public endpoint named `var` from the environment.
/// Unset behaves like empty: no public endpoint.
pub(crate) fn public_endpoint_from_env(var: &str, path: EndpointPath) -> Result<Option<String>> {
    match std::env::var(var) {
        Ok(raw) => parse_public_endpoint(var, &raw, path),
        Err(_) => Ok(None),
    }
}

#[cfg(ak_test_shard = "services-2")]
#[cfg(test)]
mod tests {
    use super::*;

    fn parse(raw: &str, path: EndpointPath) -> Result<Option<String>> {
        parse_public_endpoint("S3_PUBLIC_ENDPOINT", raw, path)
    }

    #[test]
    fn unset_or_blank_means_not_configured() {
        for raw in ["", "   ", "\t\n"] {
            assert_eq!(parse(raw, EndpointPath::Forbidden).unwrap(), None);
        }
    }

    #[test]
    fn accepts_and_normalises_origins() {
        for (raw, want) in [
            ("https://s3.example.com", "https://s3.example.com"),
            ("https://s3.example.com/", "https://s3.example.com"),
            ("  https://S3.Example.COM  ", "https://s3.example.com"),
            (
                "http://storage.example.com:9000",
                "http://storage.example.com:9000",
            ),
            ("https://s3.example.com:443/", "https://s3.example.com"),
            ("http://10.0.0.5:9000/", "http://10.0.0.5:9000"),
            ("http://[::1]:9000", "http://[::1]:9000"),
        ] {
            assert_eq!(
                parse(raw, EndpointPath::Forbidden).unwrap().as_deref(),
                Some(want),
                "{raw}"
            );
        }
    }

    #[test]
    fn rejects_malformed_values() {
        for raw in [
            "storage.example.com",
            "storage.example.com:9000",
            "ftp://storage.example.com",
            "s3://bucket",
            "https://",
            "https://user:pw@storage.example.com",
            "https://user@storage.example.com",
            "https://storage.example.com?x=1",
            "https://storage.example.com#frag",
            "https://storage.example.com/s3",
        ] {
            let err = parse(raw, EndpointPath::Forbidden).expect_err(raw);
            let msg = err.to_string();
            assert!(msg.contains("S3_PUBLIC_ENDPOINT"), "{raw}: {msg}");
        }
    }

    /// #4503: a value refused for carrying credentials (or for anything
    /// else) never echoes them into the startup error or WARN.
    #[test]
    fn rejection_messages_never_contain_credentials_4503() {
        // Generated per run so no credential-shaped literal is committed.
        let secret = uuid::Uuid::new_v4().simple().to_string();
        for (raw, shown) in [
            (
                format!("http://svc:{secret}@192.168.42.150:32613"),
                "http://***@192.168.42.150:32613",
            ),
            (
                format!("https://{secret}@storage.example.com/s3"),
                "https://***@storage.example.com/s3",
            ),
            // Rejected for another reason first, still redacted.
            (
                format!("ftp://svc:{secret}@storage.example.com"),
                "ftp://***@storage.example.com",
            ),
            // No scheme: not an absolute URL, still redacted.
            (
                format!("svc:{secret}@storage.example.com:9000"),
                "***@storage.example.com:9000",
            ),
        ] {
            for (var, path) in [
                ("S3_PUBLIC_ENDPOINT", EndpointPath::Forbidden),
                ("AZURE_STORAGE_PUBLIC_ENDPOINT", EndpointPath::Allowed),
            ] {
                let msg = parse_public_endpoint(var, &raw, path)
                    .expect_err(&raw)
                    .to_string();
                assert!(!msg.contains(&secret), "{var}: {msg}");
                assert!(!msg.contains("svc"), "{var}: {msg}");
                assert!(msg.contains(var) && msg.contains(shown), "{var}: {msg}");
            }
        }
    }

    #[test]
    fn redact_userinfo_leaves_other_values_alone_4503() {
        for raw in [
            "https://s3.example.com",
            "https://storage.example.com/path@v1",
            "https://storage.example.com?x=a@b",
            "not a url",
            "",
        ] {
            assert_eq!(redact_userinfo(raw), raw);
        }
        assert_eq!(
            redact_userinfo("http://a@b@host:1/p"),
            "http://***@host:1/p"
        );
    }

    #[test]
    fn path_is_kept_only_where_allowed() {
        assert_eq!(
            parse(
                "http://blob.example.com:10000/devstoreaccount1/",
                EndpointPath::Allowed
            )
            .unwrap()
            .as_deref(),
            Some("http://blob.example.com:10000/devstoreaccount1")
        );
        assert!(parse("https://gw.example.com/s3", EndpointPath::Forbidden).is_err());
        // Query strings stay forbidden even where a path is allowed.
        assert!(parse("https://blob.example.com/acct?sv=1", EndpointPath::Allowed).is_err());
    }

    #[test]
    fn reads_from_env() {
        const VAR: &str = "AK_TEST_PUBLIC_ENDPOINT_4417";
        std::env::remove_var(VAR);
        assert_eq!(
            public_endpoint_from_env(VAR, EndpointPath::Forbidden).unwrap(),
            None
        );
        std::env::set_var(VAR, "https://dl.example.com/");
        assert_eq!(
            public_endpoint_from_env(VAR, EndpointPath::Forbidden)
                .unwrap()
                .as_deref(),
            Some("https://dl.example.com")
        );
        std::env::set_var(VAR, "not a url");
        assert!(public_endpoint_from_env(VAR, EndpointPath::Forbidden).is_err());
        std::env::remove_var(VAR);
    }
}
