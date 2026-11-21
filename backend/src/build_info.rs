//! Build/version metadata baked in at compile time.
//!
//! `GIT_SHA` is provided by `build.rs` from the `GIT_SHA` build environment
//! variable, which every shipped build sets (the Docker Publish build arg,
//! release.yml's binaries), and is the literal `"unknown"` otherwise: a local
//! or CI test build, which no longer reads git so a commit does not recompile
//! the crate (#6181). Consumers must therefore treat `"unknown"` as a valid,
//! non-fatal value.

/// Semantic version of the running build, from `CARGO_PKG_VERSION`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Full git commit SHA of the build, or `"unknown"` when the build did not
/// set `GIT_SHA`. Baked by `build.rs`.
pub const GIT_SHA: &str = env!("GIT_SHA");

/// Length of the short SHA form, matching the `sha-<commit>` tag emitted by the
/// Docker Publish workflow so a log line can be matched to an exact image.
const SHORT_SHA_LEN: usize = 7;

/// Truncate a git SHA to its short form, leaving the `"unknown"` sentinel (and
/// any value already shorter than the short length) untouched.
fn shorten(sha: &str) -> &str {
    if sha == "unknown" || sha.len() < SHORT_SHA_LEN {
        sha
    } else {
        &sha[..SHORT_SHA_LEN]
    }
}

/// Short (7-char) git SHA of the build, or `"unknown"` when unavailable.
pub fn short_sha() -> &'static str {
    shorten(GIT_SHA)
}

#[cfg(ak_test_shard = "services-2")]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shortens_a_full_sha() {
        assert_eq!(shorten("abc1234def5678"), "abc1234");
    }

    #[test]
    fn leaves_unknown_untouched() {
        assert_eq!(shorten("unknown"), "unknown");
    }

    #[test]
    fn leaves_short_values_untouched() {
        assert_eq!(shorten("abc12"), "abc12");
    }

    #[test]
    fn exact_length_sha_is_unchanged() {
        assert_eq!(shorten("abc1234"), "abc1234");
    }

    #[test]
    fn version_is_non_empty() {
        assert!(!VERSION.is_empty());
    }
}
