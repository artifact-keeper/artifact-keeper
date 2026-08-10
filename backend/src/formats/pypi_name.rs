//! Validated, normalized PyPI project names (PEP 508 + PEP 503).
//!
//! # Why this module exists
//!
//! Artifact Keeper carried *two* PyPI name coercions and *zero* validation:
//!
//! * [`crate::api::handlers::pypi::normalize_pep503`] — the policy/gate form.
//!   It DROPS every character outside `[A-Za-z0-9._-]` without marking a
//!   separator. That drop is a deliberate stored-XSS boundary (#1377) and is
//!   correct as a *sanitizer*.
//! * [`crate::formats::pypi::PypiHandler::normalize_name`] — the fetch/cache-key
//!   form. It maps every non-alphanumeric character to `-`.
//!
//! On any character outside `[A-Za-z0-9._-]` the two disagree. `acme sdk`
//! becomes `acmesdk` for the gate and `acme-sdk` for the fetch, so a client
//! could clear a curation / dependency-confusion gate under one name and be
//! served a different package's bytes. That divergence has been re-introduced
//! three separate times (#3077, #3179, #3183), each time as a silent security
//! bug rather than a compile error.
//!
//! # The spec position
//!
//! **PEP 503** ("Simple Repository API", *Normalized Names*) defines
//! normalization as exactly:
//!
//! ```text
//! re.sub(r"[-_.]+", "-", name).lower()
//! ```
//!
//! That is the whole rule. It collapses runs of `-`, `_` and `.` into a single
//! `-` and lowercases. It says nothing about any other character — not because
//! other characters are permitted, but because the rule presupposes a name that
//! is already valid.
//!
//! **PEP 508** ("Dependency specification for Python Software Packages",
//! *Names*) supplies that missing precondition:
//!
//! > The format of a name is:
//! >
//! > ```text
//! > ^([A-Z0-9]|[A-Z0-9][A-Z0-9._-]*[A-Z0-9])$
//! > ```
//! >
//! > with `re.IGNORECASE`.
//!
//! So `acme sdk` is not a project name at all, and there is no correct
//! normalization for it — it is outside the input domain of PEP 503's rule.
//! Two coercions disagreeing about an input that has no correct answer is the
//! expected outcome, not an implementation slip.
//!
//! # What this module does
//!
//! [`NormalizedProjectName`] can only be constructed from a name that satisfies
//! the PEP 508 pattern, and it stores the PEP 503 normalized form. Because the
//! fetch and cache-key helpers take `&NormalizedProjectName` rather than
//! `&str`, a raw path segment cannot reach them: a fourth code path that
//! reaches for the wrong coercion now fails to compile instead of shipping a
//! silent gate bypass.
//!
//! # The invariant that makes this a *removal* of the divergence
//!
//! For every PEP 508-valid name, all three functions — PEP 503's reference
//! `re.sub`, `normalize_pep503`, and `PypiHandler::normalize_name` — agree
//! byte for byte. A valid name draws only on `[A-Za-z0-9._-]`, so
//! `normalize_pep503` never drops anything, and it begins and ends with an
//! alphanumeric, so neither the leading-separator skip nor the trailing-hyphen
//! pop fires. Validation therefore does not paper over the divergence; it
//! eliminates the inputs on which a divergence can exist. That equivalence is
//! asserted directly in `tests::all_three_normalizers_agree_on_every_valid_name`.
//!
//! This module deliberately does NOT weaken `normalize_pep503`. Its character
//! dropping remains the XSS boundary for names scraped out of upstream HTML,
//! which are not route input and are not validated here.

use once_cell::sync::Lazy;
use regex::Regex;

/// PEP 508 *Names*: `^([A-Z0-9]|[A-Z0-9][A-Z0-9._-]*[A-Z0-9])$` with
/// `re.IGNORECASE`.
///
/// Written with an explicit `[A-Za-z0-9]` class rather than the `(?i)` flag so
/// the accepted alphabet is ASCII and visible at the call site. A `(?i)`
/// `[A-Z]` in Rust's `regex` crate would additionally match the Kelvin sign
/// (U+212A) and the dotless/long variants under Unicode case folding, which
/// would let non-ASCII names through the very check that exists to exclude
/// them.
///
/// `\A`/`\z` rather than `^`/`$`: in Rust's `regex`, `$` also matches before a
/// trailing `\n`, so `^...$` would accept `"acme-sdk\n"` — a name carrying a
/// header-injection newline into every downstream URL.
static PEP508_NAME_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\A([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9._-]*[A-Za-z0-9])\z")
        .expect("PEP 508 name pattern is a valid regex")
});

/// The PEP 508 *Names* pattern in the spec's own `^`/`$` spelling, for putting
/// in an error message a publisher will read (#3198).
///
/// Spelled out separately from [`PEP508_NAME_RE`] rather than derived from it,
/// because the two are answering different questions: the regex is anchored
/// with `\A`/`\z` to close the trailing-newline hole Rust's `$` opens, which is
/// an implementation detail of *this* engine and would only confuse someone
/// comparing the message against PEP 508. The character class and the
/// alternation -- the parts a publisher has to satisfy -- are identical, and
/// `tests::message_pattern_matches_the_enforced_regex` asserts they stay that
/// way, so the message cannot drift from what is actually enforced.
pub const PEP508_NAME_PATTERN: &str = r"^([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9._-]*[A-Za-z0-9])$";

/// Does `name` satisfy the PEP 508 project-name pattern?
///
/// This is the *unnormalized* check: `Django`, `zope.interface` and
/// `a.b-c_d` are all valid names, they simply are not canonical ones.
pub fn is_valid_project_name(name: &str) -> bool {
    PEP508_NAME_RE.is_match(name)
}

/// A PyPI project name that has been validated against PEP 508 and stored in
/// PEP 503 canonical form.
///
/// The inner `String` is private and there is no `From<String>`, no
/// `Deref<Target = str>` and no public constructor other than [`Self::parse`],
/// so the only way to obtain one is to pass validation. That is the whole
/// point: helpers that fetch from an upstream or build a proxy-cache key take
/// `&NormalizedProjectName`, which makes "gate on one string, fetch with
/// another" unrepresentable rather than merely currently-fixed.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NormalizedProjectName(String);

impl NormalizedProjectName {
    /// Validate `raw` against PEP 508 and normalize it per PEP 503.
    ///
    /// Returns `None` for anything outside the PEP 508 alphabet — an empty
    /// segment, a leading or trailing `-`/`_`/`.`, whitespace, a control
    /// character, a path separator, or any non-ASCII character. Callers on a
    /// routed path must turn `None` into a 404: pypi.org has no route for a
    /// name that cannot exist, and returns 404 for exactly these inputs.
    pub fn parse(raw: &str) -> Option<Self> {
        if !is_valid_project_name(raw) {
            return None;
        }
        Some(Self(normalize_valid(raw)))
    }

    /// The PEP 503 canonical form.
    ///
    /// The single, explicit way out of the newtype. There is deliberately no
    /// `Deref<Target = str>`, no `AsRef<str>` and no `Into<String>`: any of
    /// those would let the canonical name be passed where a `&str` is expected
    /// through inference alone, which is exactly the implicitness this type
    /// exists to remove. Every unwrap should be visible at the call site.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for NormalizedProjectName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// PEP 503 normalization, `re.sub(r"[-_.]+", "-", name).lower()`, applied to a
/// name already known to satisfy PEP 508.
///
/// Private on purpose. Exposing it would recreate exactly the hazard this
/// module removes: a third bare `&str` -> `String` name coercion for a future
/// code path to pick by accident.
fn normalize_valid(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut in_separator_run = false;
    for c in name.chars() {
        if c == '-' || c == '_' || c == '.' {
            if !in_separator_run {
                out.push('-');
                in_separator_run = true;
            }
        } else {
            out.push(c.to_ascii_lowercase());
            in_separator_run = false;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::handlers::pypi::normalize_pep503;
    use crate::formats::pypi::PypiHandler;

    // -- PEP 508 acceptance -------------------------------------------------

    /// Every one of these satisfies
    /// `^([A-Z0-9]|[A-Z0-9][A-Z0-9._-]*[A-Z0-9])$`, so every one MUST be
    /// accepted. Over-rejection here does not fail one request, it takes the
    /// whole PyPI surface offline, so this list is deliberately weighted
    /// towards the unusual-but-legal.
    fn valid_names() -> Vec<&'static str> {
        vec![
            // Single character - the first alternation branch, and the only
            // shape for which the pattern's second branch cannot match.
            "a",
            "A",
            "0",
            "9",
            // Digits only.
            "123",
            "2024",
            // Two characters: the second branch with an empty middle.
            "ab",
            "a1",
            "1a",
            // Every separator the alphabet allows, interior.
            "a.b-c_d",
            "a-b",
            "a_b",
            "a.b",
            // Runs of separators are legal input (PEP 503 collapses them).
            "a__b",
            "a--b",
            "a._-b",
            // Mixed case.
            "MyPackage",
            "Django",
            "PyYAML",
            "Jinja2",
            // Real-world names with dots.
            "zope.interface",
            "ruamel.yaml",
            "backports.ssl_match_hostname",
            // Already canonical.
            "acme-sdk",
            "requests",
            // Long-ish and separator-dense but legal.
            "a-b-c-d-e-f-g-h",
        ]
    }

    /// None of these satisfies the PEP 508 pattern, so none is a project name
    /// and none has a correct normalization.
    fn invalid_names() -> Vec<&'static str> {
        vec![
            // Empty.
            "",
            // The motivating case: a space is outside the alphabet, and it is
            // exactly where the two legacy coercions disagreed.
            "acme sdk",
            " acme-sdk",
            "acme-sdk ",
            // Other out-of-alphabet characters.
            "acme!sdk",
            "acme@sdk",
            "acme/sdk",
            "acme\\sdk",
            "acme:sdk",
            "acme+sdk",
            "acme%20sdk",
            "acme#sdk",
            // Non-ASCII, including the Kelvin-sign / case-folding trap the
            // explicit ASCII class exists to exclude.
            "acmeésdk",
            "acme\u{212A}sdk",
            "пакет",
            // Control characters and newlines: `$` in Rust regex matches
            // before a trailing newline, which is why the pattern uses `\z`.
            "acme-sdk\n",
            "acme-sdk\r\n",
            "acme\tsdk",
            "acme\0sdk",
            // Leading / trailing separators - the pattern requires an
            // alphanumeric at both ends.
            "_leading",
            "-leading",
            ".leading",
            "trailing_",
            "trailing-",
            "trailing.",
            // Separator only.
            "-",
            "_",
            ".",
            "---",
            // Path traversal shapes, which the alphabet excludes for free.
            "..",
            "../etc/passwd",
            "a/../b",
            // The XSS payload the sanitizer boundary exists for. It is not a
            // name; rejecting it is strictly stronger than sanitizing it.
            "<script>alert(1)</script>",
        ]
    }

    #[test]
    fn accepts_every_valid_name() {
        for name in valid_names() {
            assert!(
                NormalizedProjectName::parse(name).is_some(),
                "PEP 508-valid name was rejected: {name:?}"
            );
        }
    }

    #[test]
    fn rejects_every_invalid_name() {
        for name in invalid_names() {
            assert!(
                NormalizedProjectName::parse(name).is_none(),
                "PEP 508-invalid name was accepted: {name:?}"
            );
        }
    }

    // -- PEP 503 normalization ----------------------------------------------

    #[test]
    fn normalizes_per_pep503() {
        let cases = [
            ("MyPackage", "mypackage"),
            ("my_package", "my-package"),
            ("my.package", "my-package"),
            ("My_Package.Name", "my-package-name"),
            ("my__package", "my-package"),
            ("my-package", "my-package"),
            ("a.b-c_d", "a-b-c-d"),
            ("a._-b", "a-b"),
            ("zope.interface", "zope-interface"),
            (
                "backports.ssl_match_hostname",
                "backports-ssl-match-hostname",
            ),
            ("Jinja2", "jinja2"),
            ("a", "a"),
            ("123", "123"),
        ];
        for (input, expected) in cases {
            let parsed = NormalizedProjectName::parse(input)
                .unwrap_or_else(|| panic!("{input:?} should be valid"));
            assert_eq!(parsed.as_str(), expected, "input {input:?}");
        }
    }

    /// PEP 503 normalization is idempotent, so a canonical name round-trips.
    #[test]
    fn normalization_is_idempotent() {
        for name in valid_names() {
            let once = NormalizedProjectName::parse(name).expect("valid");
            let twice = NormalizedProjectName::parse(once.as_str())
                .expect("PEP 503 output must itself be a valid PEP 508 name");
            assert_eq!(once, twice, "not idempotent for {name:?}");
        }
    }

    /// The load-bearing claim of this whole change.
    ///
    /// On the PEP 508-valid domain the two legacy coercions and the newtype all
    /// produce the same string, so validating at the edge does not change the
    /// answer for any name that has one — it only removes the inputs for which
    /// the two answers differed. If this ever fails, validation alone is no
    /// longer sufficient and the divergence is back.
    #[test]
    fn all_three_normalizers_agree_on_every_valid_name() {
        for name in valid_names() {
            let newtype = NormalizedProjectName::parse(name).expect("valid");
            assert_eq!(
                newtype.as_str(),
                normalize_pep503(name),
                "newtype vs normalize_pep503 disagree on {name:?}"
            );
            assert_eq!(
                newtype.as_str(),
                PypiHandler::normalize_name(name),
                "newtype vs PypiHandler::normalize_name disagree on {name:?}"
            );
        }
    }

    /// `PypiHandler::normalize_name` is the identity on canonical output, which
    /// is what lets the fetch helpers keep calling it without changing any URL
    /// or cache key for a well-formed name.
    #[test]
    fn legacy_fetch_normalizer_is_identity_on_canonical_form() {
        for name in valid_names() {
            let canonical = NormalizedProjectName::parse(name).expect("valid");
            assert_eq!(
                PypiHandler::normalize_name(canonical.as_str()),
                canonical.as_str(),
                "normalize_name is not the identity on canonical {canonical}"
            );
        }
    }

    /// The exact divergence from the issue, pinned so the motivation cannot be
    /// lost: on `acme sdk` the two legacy coercions really do differ, and the
    /// newtype refuses the input rather than picking a winner.
    #[test]
    fn documents_the_divergence_the_newtype_removes() {
        assert_eq!(normalize_pep503("acme sdk"), "acmesdk");
        assert_eq!(PypiHandler::normalize_name("acme sdk"), "acme-sdk");
        assert_ne!(
            normalize_pep503("acme sdk"),
            PypiHandler::normalize_name("acme sdk")
        );
        assert!(NormalizedProjectName::parse("acme sdk").is_none());
    }

    /// The canonical form never carries a character that could break out of a
    /// URL path segment, an HTML attribute, or a storage key.
    #[test]
    fn canonical_form_is_url_and_html_safe() {
        for name in valid_names() {
            let canonical = NormalizedProjectName::parse(name).expect("valid");
            assert!(
                canonical
                    .as_str()
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'),
                "canonical form {canonical} contains an unexpected character"
            );
        }
    }

    /// A single-character name is the shape most likely to be broken by an
    /// off-by-one in the pattern, and `a` is a real package on pypi.org.
    #[test]
    fn single_character_names_survive() {
        for name in ["a", "z", "A", "Z", "0", "9"] {
            let parsed = NormalizedProjectName::parse(name)
                .unwrap_or_else(|| panic!("single character {name:?} must be valid"));
            assert_eq!(parsed.as_str(), name.to_ascii_lowercase());
        }
    }

    /// The pattern shown to a rejected publisher (#3198) must be the pattern
    /// actually enforced, differing only in the anchors.
    ///
    /// An error message that tells someone how to spell a name is useless --
    /// worse than useless -- if it drifts from the check. Comparing the two
    /// with the anchors normalized away catches a change to one that is not
    /// made to the other, which is the realistic failure.
    #[test]
    fn message_pattern_matches_the_enforced_regex() {
        let enforced = PEP508_NAME_RE
            .as_str()
            .trim_start_matches(r"\A")
            .trim_end_matches(r"\z");
        let advertised = PEP508_NAME_PATTERN
            .trim_start_matches('^')
            .trim_end_matches('$');
        assert_eq!(
            enforced, advertised,
            "the PEP 508 pattern in the error message has drifted from the one enforced"
        );

        // And the advertised spelling must itself be a regex that accepts and
        // rejects the same names, so the message is something a publisher can
        // actually test their name against.
        let advertised_re = Regex::new(PEP508_NAME_PATTERN).expect("advertised pattern compiles");
        for name in valid_names() {
            assert!(
                advertised_re.is_match(name),
                "advertised pattern rejects the valid name {name:?}"
            );
        }
        for name in invalid_names() {
            // `$` in Rust's regex also matches before a trailing newline, which
            // is the one case where the advertised spelling is deliberately
            // laxer than the enforced one. Everything else must agree.
            if name.ends_with('\n') {
                continue;
            }
            assert!(
                !advertised_re.is_match(name),
                "advertised pattern accepts the invalid name {name:?}"
            );
        }
    }
}
