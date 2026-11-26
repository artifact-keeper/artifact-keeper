//! Build/version metadata baked in at compile time, re-exported from the
//! `ak-build-info` crate (backend/crates/ak-build-info).
//!
//! `GIT_SHA` comes from the `GIT_SHA` build environment variable, which every
//! shipped build sets (the Docker Publish build arg, release.yml's binaries),
//! and is the literal `"unknown"` otherwise: a local or CI test build, which
//! does not read git, so a commit does not recompile the crate (#6181).
//! Consumers must therefore treat `"unknown"` as a valid, non-fatal value.

pub use ak_build_info::{short_sha, GIT_SHA, VERSION};

#[cfg(ak_test_shard = "services-2")]
#[cfg(test)]
mod tests {
    use super::*;
    use ak_build_info::shorten;

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
