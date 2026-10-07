//! Per-Remote allowlist of trusted cross-origin OCI Bearer token realms (#3591).
//!
//! # Why this exists
//!
//! GHSA-78h6-3wp8-2542 pinned the forwarding of a Remote repository's
//! configured upstream credentials to the upstream's own ORIGIN: when an OCI
//! registry answers `401 WWW-Authenticate: Bearer realm="..."` and the realm
//! names a different scheme, host or port, the token request goes out
//! WITHOUT the credentials (see `UpstreamClient::exchange_bearer_then`). The
//! realm is upstream-controlled, so that default is what stops a hostile or
//! compromised registry from collecting the credentials.
//!
//! Some registries legitimately serve their token endpoint from another
//! origin: GitLab (`registry.example.com` -> `gitlab.example.com/jwt/auth`)
//! and Docker Hub (`registry-1.docker.io` -> `auth.docker.io`) are the common
//! cases. Under the strict rule a credentialed remote for either can never
//! authenticate. This module lets a repository administrator name, per Remote
//! repository, the exact realm origins the credentials may follow.
//!
//! # Rules (enforced on write by [`normalize_trusted_realms`])
//!
//! * `https` only: a credential must never be sent in clear text to a
//!   cross-origin endpoint.
//! * An ORIGIN, not a URL: `scheme://host[:port]`, no userinfo, path, query
//!   or fragment. Stored in the canonical serialization (lowercase host,
//!   default port elided) so a match is an exact string comparison.
//! * No wildcards and no suffix matching: `https://*.example.com` is
//!   rejected, and `https://example.com` does not trust `auth.example.com`.
//! * SSRF-validated exactly like an upstream URL
//!   ([`validate_outbound_url`]); the realm is SSRF-checked again at request
//!   time regardless.
//!
//! # Storage
//!
//! A JSON array of origin strings in `repository_config` under
//! [`OCI_TRUSTED_BEARER_REALMS_KEY`]. Not a secret (it names hosts, no
//! credentials), so it is stored in plain text and echoed back on the
//! repository API.

use std::collections::BTreeSet;

use sqlx::PgPool;
use uuid::Uuid;

use crate::api::validation::validate_outbound_url;
use crate::error::{AppError, Result};

/// `repository_config` key holding the JSON array of trusted realm origins.
/// Deliberately the same string as the API field name, which is also what
/// validation errors call it.
pub const OCI_TRUSTED_BEARER_REALMS_KEY: &str = "oci_trusted_bearer_realms";

/// Upper bound on the number of trusted origins per repository. A registry
/// needs one token service; a handful covers mirrors and migrations.
pub const MAX_TRUSTED_REALMS: usize = 16;

/// Upper bound on one entry's length (before normalization).
const MAX_ORIGIN_LEN: usize = 512;

/// Canonical origin (`scheme://host[:port]`, lowercase host, default port
/// elided) of a parsed URL, or `None` for an opaque origin (no host).
fn canonical_origin(url: &reqwest::Url) -> Option<String> {
    let origin = url.origin();
    origin.is_tuple().then(|| origin.ascii_serialization())
}

/// Syntactic rules for one trusted realm origin, with NO network or SSRF
/// check: https, an origin with no userinfo, path, query or fragment, no
/// wildcard. Returns the canonical origin, or why the input is not one. Pure
/// and DNS-free, so it is also what the read path uses ([`parse_stored`]).
fn syntactic_origin(input: &str) -> std::result::Result<String, String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err("must not be empty".to_string());
    }
    if trimmed.len() > MAX_ORIGIN_LEN {
        return Err(format!("is longer than {MAX_ORIGIN_LEN} characters"));
    }
    if trimmed.contains('*') {
        return Err("contains a wildcard; list each exact origin instead".to_string());
    }
    let url = reqwest::Url::parse(trimmed).map_err(|_| "is not a valid URL".to_string())?;
    if url.scheme() != "https" {
        return Err("must use https".to_string());
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("must not contain credentials".to_string());
    }
    if (url.path() != "/" && !url.path().is_empty())
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(
            "must be an origin (https://host[:port]) without a path, query or fragment".to_string(),
        );
    }
    canonical_origin(&url).ok_or_else(|| "must have a host".to_string())
}

/// Validate one operator-supplied trusted realm origin and return its
/// canonical form: the [`syntactic_origin`] rules plus the same SSRF check
/// as an upstream URL. Write path only; see the module docs for the rules.
pub fn normalize_trusted_realm(input: &str) -> Result<String> {
    let origin = syntactic_origin(input).map_err(|why| {
        AppError::Validation(format!(
            "{OCI_TRUSTED_BEARER_REALMS_KEY}: '{}' {why}",
            input.trim().chars().take(80).collect::<String>()
        ))
    })?;
    validate_outbound_url(&origin, "OCI trusted bearer realm")?;
    Ok(origin)
}

/// Validate and canonicalize a whole allowlist: every entry must pass
/// [`normalize_trusted_realm`]; duplicates (after canonicalization) collapse;
/// the result is sorted for a stable stored/echoed representation.
pub fn normalize_trusted_realms(inputs: &[String]) -> Result<Vec<String>> {
    if inputs.len() > MAX_TRUSTED_REALMS {
        return Err(AppError::Validation(format!(
            "{OCI_TRUSTED_BEARER_REALMS_KEY} accepts at most {MAX_TRUSTED_REALMS} origins"
        )));
    }
    let set = inputs
        .iter()
        .map(|s| normalize_trusted_realm(s))
        .collect::<Result<BTreeSet<String>>>()?;
    Ok(set.into_iter().collect())
}

/// Whether an upstream-supplied OCI bearer `realm` URL's origin is one of the
/// repository's trusted origins. Exact canonical-origin equality only, and
/// `https` only (stored entries are all `https`, but the realm's scheme is
/// checked explicitly so a downgrade can never match). Unparseable realms
/// never match.
pub fn realm_is_trusted(realm: &str, trusted: &[String]) -> bool {
    let Ok(url) = reqwest::Url::parse(realm) else {
        return false;
    };
    if url.scheme() != "https" {
        return false;
    }
    match canonical_origin(&url) {
        Some(origin) => trusted.contains(&origin),
        None => false,
    }
}

/// Decode the stored JSON value. Purely syntactic: the SSRF check ran when
/// the list was written, and the realm itself is SSRF-validated again on
/// every token request, so the read path does no DNS lookup and an entry
/// never vanishes from the API because of a transient resolution. A
/// malformed value, or an entry that is not already a canonical https origin
/// (only possible if the row was edited outside the API), fails CLOSED: it
/// is dropped rather than trusted.
pub fn parse_stored(value: &str) -> Vec<String> {
    match serde_json::from_str::<Vec<String>>(value) {
        Ok(list) => list
            .into_iter()
            .filter(|s| syntactic_origin(s).as_deref() == Ok(s.as_str()))
            .collect(),
        Err(_) => {
            tracing::warn!(
                target: "security",
                "stored {OCI_TRUSTED_BEARER_REALMS_KEY} is not a JSON string array; \
                 treating it as empty (no cross-origin realm is trusted)"
            );
            Vec::new()
        }
    }
}

/// Load a repository's trusted realm origins (empty when unset).
pub async fn load_trusted_realms(db: &PgPool, repo_id: Uuid) -> Result<Vec<String>> {
    let value: Option<String> = sqlx::query_scalar(
        "SELECT value FROM repository_config WHERE repository_id = $1 AND key = $2",
    )
    .bind(repo_id)
    .bind(OCI_TRUSTED_BEARER_REALMS_KEY)
    .fetch_optional(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;
    Ok(value.as_deref().map(parse_stored).unwrap_or_default())
}

/// Persist an already-normalized allowlist. An empty list removes the row,
/// restoring the strict same-origin default.
pub async fn save_trusted_realms(db: &PgPool, repo_id: Uuid, normalized: &[String]) -> Result<()> {
    if normalized.is_empty() {
        sqlx::query("DELETE FROM repository_config WHERE repository_id = $1 AND key = $2")
            .bind(repo_id)
            .bind(OCI_TRUSTED_BEARER_REALMS_KEY)
            .execute(db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
        return Ok(());
    }
    let value = serde_json::to_string(normalized).map_err(|e| {
        AppError::Internal(format!("serialize {OCI_TRUSTED_BEARER_REALMS_KEY}: {e}"))
    })?;
    sqlx::query(
        "INSERT INTO repository_config (repository_id, key, value) \
         VALUES ($1, $2, $3) \
         ON CONFLICT (repository_id, key) DO UPDATE SET value = $3, updated_at = NOW()",
    )
    .bind(repo_id)
    .bind(OCI_TRUSTED_BEARER_REALMS_KEY)
    .bind(value)
    .execute(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn normalizes_to_canonical_origin() {
        assert_eq!(
            normalize_trusted_realm("https://Auth.Docker.IO").unwrap(),
            "https://auth.docker.io"
        );
        assert_eq!(
            normalize_trusted_realm("  https://gitlab.example.com/  ").unwrap(),
            "https://gitlab.example.com"
        );
        // Default port elided, non-default port kept.
        assert_eq!(
            normalize_trusted_realm("https://gitlab.example.com:443").unwrap(),
            "https://gitlab.example.com"
        );
        assert_eq!(
            normalize_trusted_realm("https://gitlab.example.com:8443").unwrap(),
            "https://gitlab.example.com:8443"
        );
    }

    #[test]
    fn rejects_non_https() {
        for bad in [
            "http://gitlab.example.com",
            "ftp://gitlab.example.com",
            "gitlab.example.com",
        ] {
            assert!(
                normalize_trusted_realm(bad).is_err(),
                "{bad} must be rejected"
            );
        }
    }

    #[test]
    fn rejects_wildcards_paths_userinfo_and_empty() {
        for bad in [
            "https://*.example.com",
            "*",
            "https://gitlab.example.com/jwt/auth",
            "https://gitlab.example.com/?x=1",
            "https://gitlab.example.com/#f",
            "https://user:pw@gitlab.example.com",
            "https://user@gitlab.example.com",
            "",
            "   ",
        ] {
            assert!(
                normalize_trusted_realm(bad).is_err(),
                "{bad:?} must be rejected"
            );
        }
        let long = format!("https://{}.example.com", "a".repeat(MAX_ORIGIN_LEN));
        assert!(normalize_trusted_realm(&long).is_err());
    }

    #[test]
    fn rejects_ssrf_targets() {
        for bad in [
            "https://127.0.0.1",
            "https://localhost",
            "https://169.254.169.254",
            "https://[::1]",
            "https://metadata.google.internal",
        ] {
            assert!(
                normalize_trusted_realm(bad).is_err(),
                "{bad} must be rejected"
            );
        }
    }

    #[test]
    fn list_dedupes_sorts_and_bounds() {
        let out = normalize_trusted_realms(&s(&[
            "https://gitlab.example.com",
            "https://auth.docker.io",
            "https://GITLAB.example.com:443/",
        ]))
        .unwrap();
        assert_eq!(
            out,
            s(&["https://auth.docker.io", "https://gitlab.example.com"])
        );
        assert!(normalize_trusted_realms(&[]).unwrap().is_empty());

        let too_many: Vec<String> = (0..=MAX_TRUSTED_REALMS)
            .map(|i| format!("https://r{i}.example.com"))
            .collect();
        assert!(normalize_trusted_realms(&too_many).is_err());
        // One bad entry fails the whole list.
        assert!(
            normalize_trusted_realms(&s(&["https://ok.example.com", "http://x.example.com"]))
                .is_err()
        );
    }

    #[test]
    fn realm_matching_is_exact_origin() {
        let trusted = s(&["https://auth.docker.io", "https://gitlab.example.com:8443"]);
        assert!(realm_is_trusted("https://auth.docker.io/token", &trusted));
        assert!(realm_is_trusted(
            "https://AUTH.docker.io:443/token?x=y",
            &trusted
        ));
        assert!(realm_is_trusted(
            "https://gitlab.example.com:8443/jwt/auth",
            &trusted
        ));
        for bad in [
            // scheme downgrade
            "http://auth.docker.io/token",
            // lookalikes / suffix / prefix tricks
            "https://auth.docker.io.evil.example/token",
            "https://evilauth.docker.io/token",
            "https://x.auth.docker.io/token",
            "https://auth.docker.io@evil.example/token",
            // port mismatch both ways
            "https://auth.docker.io:8443/token",
            "https://gitlab.example.com/jwt/auth",
            "not a url",
        ] {
            assert!(
                !realm_is_trusted(bad, &trusted),
                "{bad} must not be trusted"
            );
        }
        assert!(!realm_is_trusted("https://auth.docker.io/token", &[]));
    }

    #[test]
    fn parse_stored_fails_closed() {
        assert_eq!(
            parse_stored(r#"["https://auth.docker.io"]"#),
            s(&["https://auth.docker.io"])
        );
        // A tampered row with a non-conforming entry keeps only valid ones.
        assert_eq!(
            parse_stored(r#"["http://auth.docker.io","https://auth.docker.io"]"#),
            s(&["https://auth.docker.io"])
        );
        // Non-canonical forms are dropped too: the API only ever stores the
        // canonical origin, so anything else was edited outside it.
        assert!(parse_stored(r#"["https://AUTH.docker.io","https://auth.docker.io/"]"#).is_empty());
        // No SSRF/DNS on read: a syntactically valid entry is kept as stored.
        assert_eq!(
            parse_stored(r#"["https://registry.internal.example"]"#),
            s(&["https://registry.internal.example"])
        );
        assert!(parse_stored("not json").is_empty());
        assert!(parse_stored(r#"{"a":1}"#).is_empty());
    }
}
