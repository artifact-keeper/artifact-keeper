//! Package names that are never sent to an external advisory feed (#5691).
//!
//! The dependency scanner asks OSV.dev (and the GitHub Advisory Database when
//! a token is set) about every dependency of a scanned artifact, and since
//! #4669 about the artifact's own coordinate as well. For a registry that
//! hosts internal libraries, that tells a third party which private packages
//! and versions exist, and the question has no security value: an internal
//! package has no public advisory record.
//!
//! `ADVISORY_EXCLUDE_PATTERNS` names those packages, as a comma- or
//! whitespace-separated list of package-URL globs:
//!
//! ```text
//! ADVISORY_EXCLUDE_PATTERNS=pkg:maven/com.example.internal/*,pkg:npm/@acme/*,pkg:pypi/acme-*
//! ```
//!
//! A pattern is matched against `pkg:<type>/<name>` (no version, no
//! qualifiers), case-insensitively; `*` matches any run of characters,
//! including `/`, and `?` one character. A Maven name is
//! `pkg:maven/<groupId>/<artifactId>`, an npm scope may be written `@acme` or
//! `%40acme`, and PyPI names compare in their PEP 503 normal form, so
//! `pkg:pypi/acme-*` also covers `Acme_Billing`. A conda package matches on
//! its conda name (`pkg:conda/...`), checked before the scanner rewrites it
//! into a PyPI alias or an unscoped query. A pattern without `pkg:`, with a
//! version or with qualifiers matches nothing and is warned about at startup.
//!
//! Unset or empty (the default) excludes nothing: every lookup is sent exactly
//! as before. An excluded dependency is left out of every external request,
//! recorded in the lookup's `not_queried` list, and does not degrade the
//! scan, since leaving it out is deliberate. It stays in the package
//! inventory and the SBOM, and local scanners (grype, trivy) still match it.

use crate::util::glob::glob_match;

/// The environment variable that holds the exclusion list.
pub const ADVISORY_EXCLUDE_PATTERNS_ENV: &str = "ADVISORY_EXCLUDE_PATTERNS";

/// A parsed `ADVISORY_EXCLUDE_PATTERNS` list. The default excludes nothing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AdvisoryExclusions {
    /// Normalised patterns (see [`normalize`]).
    patterns: Vec<String>,
    /// `(pattern as written, why it probably matches nothing)` for each
    /// pattern that looks misconfigured; reported at startup.
    suspicious: Vec<(String, &'static str)>,
}

impl AdvisoryExclusions {
    /// Parse a comma- or whitespace-separated pattern list. Empty entries are
    /// dropped, so a blank value excludes nothing.
    pub fn parse(raw: &str) -> Self {
        let written: Vec<&str> = raw
            .split(|c: char| c == ',' || c.is_whitespace())
            .map(str::trim)
            .filter(|p| !p.is_empty())
            .collect();
        Self {
            patterns: written.iter().map(|p| normalize(p)).collect(),
            suspicious: written
                .iter()
                .filter_map(|p| suspicion(p).map(|why| ((*p).to_string(), why)))
                .collect(),
        }
    }

    /// Patterns that look misconfigured and probably match nothing, with the
    /// reason: a missing `pkg:` prefix, a version, or purl qualifiers or a
    /// subpath (matching is on `pkg:<type>/<name>` only).
    pub fn suspicious(&self) -> &[(String, &'static str)] {
        &self.suspicious
    }

    /// Read [`ADVISORY_EXCLUDE_PATTERNS_ENV`]. Unset excludes nothing.
    pub fn from_env() -> Self {
        std::env::var(ADVISORY_EXCLUDE_PATTERNS_ENV)
            .map(|raw| Self::parse(&raw))
            .unwrap_or_default()
    }

    pub fn len(&self) -> usize {
        self.patterns.len()
    }

    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }

    /// True when the package `name` of feed ecosystem `ecosystem` (the OSV
    /// ecosystem string a `Dependency` carries) matches any pattern and must
    /// not be sent to an external advisory feed.
    pub fn excludes(&self, ecosystem: &str, name: &str) -> bool {
        if self.patterns.is_empty() {
            return false;
        }
        let subject = normalize(&format!("pkg:{}/{}", purl_type(ecosystem), name));
        self.patterns.iter().any(|p| glob_match(p, &subject))
    }
}

/// The package-URL type for an OSV ecosystem string. An ecosystem with no
/// mapping falls back to its lowercased name.
fn purl_type(ecosystem: &str) -> String {
    match ecosystem {
        "PyPI" | "pypi" => "pypi",
        "crates.io" => "cargo",
        "Maven" => "maven",
        "Go" => "golang",
        "NuGet" => "nuget",
        "RubyGems" => "gem",
        "Packagist" => "composer",
        "Debian" => "deb",
        "Alpine" => "apk",
        // A vendored native library belongs to no package ecosystem.
        crate::services::scanner_service::ECOSYSTEM_UNSCOPED => "generic",
        other => return other.to_ascii_lowercase(),
    }
    .to_string()
}

/// Why a pattern as written probably matches nothing, if it does.
fn suspicion(pattern: &str) -> Option<&'static str> {
    let lower = pattern.to_ascii_lowercase();
    let Some(rest) = lower.strip_prefix("pkg:") else {
        return Some("it does not start with `pkg:<type>/`");
    };
    if rest.contains('=') || rest.contains('#') {
        return Some(
            "it carries purl qualifiers or a subpath (`?k=v`, `#path`); only \
             `pkg:<type>/<name>` is matched, and `?` is a one-character wildcard",
        );
    }
    // A version is an `@` that does not open a path segment (`@acme/` is an
    // npm scope; `name@1.*` is a version).
    let name = rest.split_once('/').map_or("", |(_, n)| n);
    let decoded = name.replace("%40", "@");
    let bytes = decoded.as_bytes();
    if bytes
        .iter()
        .enumerate()
        .any(|(i, b)| *b == b'@' && i > 0 && bytes[i - 1] != b'/')
    {
        return Some("it names a version (`@...`); patterns match names only, never versions");
    }
    None
}

/// Fold a `pkg:<type>/<name>` string (a pattern or a subject) into the form
/// both sides are compared in: lowercase, `%40` decoded to `@`, a Maven
/// `groupId:artifactId` written with `/`, and a PyPI name in PEP 503 form
/// (every run of `-`, `_` and `.` read as one `-`). Applying the same fold to the pattern and the
/// subject keeps `*` and `?` intact while making the spellings agree.
fn normalize(raw: &str) -> String {
    let lower = raw.trim().to_lowercase().replace("%40", "@");
    if let Some(rest) = lower.strip_prefix("pkg:maven/") {
        return format!("pkg:maven/{}", rest.replace(':', "/"));
    }
    if let Some(rest) = lower.strip_prefix("pkg:pypi/") {
        // PEP 503: `re.sub(r"[-_.]+", "-", name)`.
        let mut name = String::with_capacity(rest.len());
        for c in rest.chars() {
            if matches!(c, '-' | '_' | '.') {
                if !name.ends_with('-') {
                    name.push('-');
                }
            } else {
                name.push(c);
            }
        }
        return format!("pkg:pypi/{name}");
    }
    lower
}

#[cfg(ak_test_shard = "services-2")]
#[cfg(test)]
mod tests {
    use super::*;

    fn ex(raw: &str) -> AdvisoryExclusions {
        AdvisoryExclusions::parse(raw)
    }

    #[test]
    fn unset_or_blank_excludes_nothing() {
        assert!(AdvisoryExclusions::default().is_empty());
        assert!(ex("").is_empty());
        assert!(ex(" , ,\n").is_empty());
        assert!(!ex("").excludes("npm", "@acme/billing"));
    }

    #[test]
    fn the_issue_examples_match_their_internal_packages_only() {
        let e = ex("pkg:maven/com.example.internal/*,pkg:npm/@acme/*, pkg:pypi/acme-*");
        assert_eq!(e.len(), 3);
        assert!(e.excludes("Maven", "com.example.internal:billing-lib"));
        assert!(e.excludes("npm", "@acme/billing"));
        assert!(e.excludes("PyPI", "acme-billing"));
        // Public packages keep their lookup.
        assert!(!e.excludes("Maven", "com.example:billing-lib"));
        assert!(!e.excludes("Maven", "org.apache.logging.log4j:log4j-core"));
        assert!(!e.excludes("npm", "@acmecorp/billing"));
        assert!(!e.excludes("npm", "lodash"));
        assert!(!e.excludes("PyPI", "requests"));
        // The type is part of the match: a same-named package in another
        // ecosystem is a different package.
        assert!(!e.excludes("npm", "acme-billing"));
    }

    #[test]
    fn spellings_of_the_same_package_agree() {
        // Case, npm scope encoding, PyPI normal form, Maven separator.
        assert!(ex("pkg:npm/%40acme/*").excludes("npm", "@acme/x"));
        assert!(ex("PKG:NPM/@ACME/*").excludes("npm", "@Acme/X"));
        assert!(ex("pkg:pypi/acme-*").excludes("PyPI", "Acme_Billing"));
        assert!(ex("pkg:pypi/acme_billing").excludes("PyPI", "acme.billing"));
        assert!(ex("pkg:pypi/acme-billing").excludes("PyPI", "Acme__Billing"));
        assert!(ex("pkg:pypi/acme_.billing").excludes("PyPI", "acme-billing"));
        assert!(ex("pkg:maven/com.acme:billing").excludes("Maven", "com.acme:billing"));
        assert!(ex("pkg:maven/com.acme/billing").excludes("Maven", "com.acme:billing"));
    }

    #[test]
    fn ecosystems_map_to_package_url_types() {
        assert!(ex("pkg:cargo/acme-*").excludes("crates.io", "acme-core"));
        assert!(ex("pkg:golang/git.acme.io/*").excludes("Go", "git.acme.io/lib/x"));
        assert!(ex("pkg:nuget/Acme.*").excludes("NuGet", "Acme.Billing"));
        assert!(ex("pkg:gem/acme-*").excludes("RubyGems", "acme-billing"));
        assert!(ex("pkg:composer/acme/*").excludes("Packagist", "acme/billing"));
        assert!(ex("pkg:generic/libacme*").excludes("*", "libacme.so"));
        assert!(ex("pkg:conda/acme-*").excludes("conda", "acme-tools"));
        // A wildcard type covers every ecosystem.
        let any = ex("pkg:*/acme-*");
        assert!(any.excludes("npm", "acme-x"));
        assert!(any.excludes("PyPI", "acme-x"));
        assert!(!any.excludes("npm", "lodash"));
    }

    #[test]
    fn misconfigured_patterns_are_reported() {
        let e = ex("@acme/*,pkg:npm/@acme/*,pkg:maven/com.acme/lib@1.*,\
                    pkg:maven/com.acme/lib?type=jar,pkg:npm/%40acme/x@2,pkg:golang/x.io/y#sub");
        let flagged: Vec<&str> = e.suspicious().iter().map(|(p, _)| p.as_str()).collect();
        assert_eq!(
            flagged,
            vec![
                "@acme/*",
                "pkg:maven/com.acme/lib@1.*",
                "pkg:maven/com.acme/lib?type=jar",
                "pkg:npm/%40acme/x@2",
                "pkg:golang/x.io/y#sub",
            ],
            "an npm scope is not a version; everything else here matches nothing"
        );
        assert!(ex("pkg:pypi/acme-*,pkg:*/acme-*").suspicious().is_empty());
    }

    #[test]
    fn a_pattern_is_anchored_at_both_ends() {
        let e = ex("pkg:npm/acme");
        assert!(e.excludes("npm", "acme"));
        assert!(!e.excludes("npm", "acme-extra"));
        assert!(!e.excludes("npm", "not-acme"));
    }
}
