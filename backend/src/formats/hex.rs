use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::error::{AppError, Result};
use crate::formats::FormatHandler;
use crate::models::repository::RepositoryFormat;

/// Information about a Hex.pm path
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HexPathInfo {
    pub path_type: HexPathType,
    pub name: String,
    pub version: Option<String>,
    pub otp_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HexPathType {
    /// Package info: packages/<name>
    PackageInfo,
    /// Package tarball: tarballs/<name>-<version>.tar
    Tarball,
    /// Hex install: installs/<otp_version>/hex-<version>.ez
    Install,
}

/// Hex.pm format handler for Elixir/Erlang packages
pub struct HexHandler;

impl HexHandler {
    pub fn new() -> Self {
        Self
    }

    /// Parse a Hex.pm path
    pub fn parse_path(path: &str) -> Result<HexPathInfo> {
        let parts: Vec<&str> = path.split('/').collect();

        if parts.is_empty() {
            return Err(AppError::Validation(format!("Invalid Hex path: {}", path)));
        }

        match parts[0] {
            "packages" => {
                if parts.len() != 2 {
                    return Err(AppError::Validation(format!(
                        "Invalid package info path: {}",
                        path
                    )));
                }

                Ok(HexPathInfo {
                    path_type: HexPathType::PackageInfo,
                    name: parts[1].to_string(),
                    version: None,
                    otp_version: None,
                })
            }
            "tarballs" => {
                if parts.len() != 2 {
                    return Err(AppError::Validation(format!(
                        "Invalid tarball path: {}",
                        path
                    )));
                }

                // Parse filename: <name>-<version>.tar
                let filename = parts[1];
                if !filename.ends_with(".tar") {
                    return Err(AppError::Validation(format!(
                        "Invalid tarball filename: {}",
                        filename
                    )));
                }

                let basename = &filename[..filename.len() - 4]; // Remove .tar
                let last_dash = basename.rfind('-').ok_or_else(|| {
                    AppError::Validation(format!("Invalid tarball filename format: {}", filename))
                })?;

                let name = basename[..last_dash].to_string();
                let version = basename[last_dash + 1..].to_string();

                Ok(HexPathInfo {
                    path_type: HexPathType::Tarball,
                    name,
                    version: Some(version),
                    otp_version: None,
                })
            }
            "installs" => {
                if parts.len() != 3 {
                    return Err(AppError::Validation(format!(
                        "Invalid install path: {}",
                        path
                    )));
                }

                let otp_version = parts[1].to_string();
                let filename = parts[2];

                // Parse filename: hex-<version>.ez
                if !filename.starts_with("hex-") || !filename.ends_with(".ez") {
                    return Err(AppError::Validation(format!(
                        "Invalid hex install filename: {}",
                        filename
                    )));
                }

                let version_with_ez = &filename[4..]; // Remove "hex-"
                let version = version_with_ez[..version_with_ez.len() - 3].to_string(); // Remove .ez

                Ok(HexPathInfo {
                    path_type: HexPathType::Install,
                    name: "hex".to_string(),
                    version: Some(version),
                    otp_version: Some(otp_version),
                })
            }
            _ => Err(AppError::Validation(format!(
                "Unknown Hex path type: {}",
                parts[0]
            ))),
        }
    }
}

impl Default for HexHandler {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse the package name out of a hex tarball filename.
///
/// Hex tarballs are stored as `<name>-<version>.tar`. The package name itself
/// may contain dashes (`my-package-1.4.0.tar`), so the split is "first `-`
/// followed by an ASCII digit". Returns `None` for any input that does not
/// parse cleanly as a hex tarball filename per the hex.pm package-name spec
/// (lowercase ASCII alphanumeric + underscore, starts with a letter, see
/// <https://hex.pm/docs/publish>).
///
/// Fail-closed contract: this helper is the gate that decides whether the
/// supply-chain shadowing guard fires. Every "maybe" outcome returns `None`
/// rather than a partially-parsed name. Specifically rejected:
/// - filenames not ending in `.tar` (case-insensitive)
/// - filenames with no `-<digit>` version separator
/// - empty package names (e.g. `-1.0.0.tar`)
/// - names containing characters outside `[a-z0-9_]`
/// - names starting with a non-letter (digits, underscore)
///
/// The case-insensitive extension match is load-bearing for the shadowing
/// guard: without it, an attacker requests `phoenix-1.4.0.Tar` and the
/// parser returns `None`, bypassing the guard (#973 / PR #974).
///
/// Lives in the `formats` layer (not `api/handlers`) so the upload path
/// (`HexHandler::validate` and the hex publish handler) can share the same
/// character-set gate as the download path. Moved here as part of the
/// #1217 audit follow-up (ak-niid).
pub(crate) fn package_name_from_tarball_filename(filename: &str) -> Option<String> {
    let lowered = filename.to_ascii_lowercase();
    let without_ext = lowered.strip_suffix(".tar")?;
    for (i, _) in without_ext.match_indices('-') {
        if without_ext
            .get(i + 1..)
            .is_some_and(|s| s.starts_with(|c: char| c.is_ascii_digit()))
        {
            let candidate = &without_ext[..i];
            if is_valid_hex_package_name(candidate) {
                return Some(candidate.to_string());
            }
            return None;
        }
    }
    None
}

/// Validate a candidate hex package name against the registry's accepted
/// shape: `[a-z][a-z0-9_-]*`. Used by `package_name_from_tarball_filename`
/// so the shadowing guard refuses to interpret traversal-shaped or
/// homoglyph-shaped inputs as legitimate package names.
///
/// Allows internal `-` and `_` to match `HexHandler::parse_path`'s behavior
/// (the upload-path side accepts dashed names like `ex-doc`). The first
/// character must be a lowercase ASCII letter to prevent version-looking
/// prefixes (`1.0.0-...`) from being parsed as names.
///
/// Lives in the `formats` layer so the publish handler in
/// `api/handlers/hex.rs` can call this on the extracted tarball
/// `metadata.config` name without crossing layering boundaries.
pub(crate) fn is_valid_hex_package_name(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !first.is_ascii_lowercase() {
        return false;
    }
    chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
}

#[async_trait]
impl FormatHandler for HexHandler {
    fn format(&self) -> RepositoryFormat {
        RepositoryFormat::Hex
    }

    fn format_key(&self) -> &str {
        "hex"
    }

    async fn parse_metadata(&self, path: &str, _content: &Bytes) -> Result<serde_json::Value> {
        let path_info = Self::parse_path(path)?;
        Ok(serde_json::to_value(path_info).unwrap_or(serde_json::json!({})))
    }

    async fn validate(&self, path: &str, _content: &Bytes) -> Result<()> {
        Self::parse_path(path)?;
        Ok(())
    }

    async fn generate_index(&self) -> Result<Option<Vec<(String, Bytes)>>> {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_package_info_path() {
        let path_info = HexHandler::parse_path("packages/phoenix").unwrap();
        assert_eq!(path_info.name, "phoenix");
        assert!(matches!(path_info.path_type, HexPathType::PackageInfo));
        assert_eq!(path_info.version, None);
        assert_eq!(path_info.otp_version, None);
    }

    #[test]
    fn test_parse_tarball_path() {
        let path_info = HexHandler::parse_path("tarballs/phoenix-1.7.0.tar").unwrap();
        assert_eq!(path_info.name, "phoenix");
        assert_eq!(path_info.version, Some("1.7.0".to_string()));
        assert!(matches!(path_info.path_type, HexPathType::Tarball));
        assert_eq!(path_info.otp_version, None);
    }

    #[test]
    fn test_parse_tarball_path_with_dash_in_name() {
        let path_info = HexHandler::parse_path("tarballs/ex-doc-0.30.0.tar").unwrap();
        assert_eq!(path_info.name, "ex-doc");
        assert_eq!(path_info.version, Some("0.30.0".to_string()));
        assert!(matches!(path_info.path_type, HexPathType::Tarball));
    }

    #[test]
    fn test_parse_install_path() {
        let path_info = HexHandler::parse_path("installs/24/hex-1.0.1.ez").unwrap();
        assert_eq!(path_info.name, "hex");
        assert_eq!(path_info.version, Some("1.0.1".to_string()));
        assert_eq!(path_info.otp_version, Some("24".to_string()));
        assert!(matches!(path_info.path_type, HexPathType::Install));
    }

    #[test]
    fn test_parse_invalid_package_path() {
        let result = HexHandler::parse_path("packages/phoenix/invalid");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_invalid_tarball_path() {
        let result = HexHandler::parse_path("tarballs/phoenix.zip");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_invalid_install_path() {
        let result = HexHandler::parse_path("installs/24/invalid.ez");
        assert!(result.is_err());
    }

    #[test]
    fn test_format_handler_format() {
        let handler = HexHandler::new();
        assert_eq!(handler.format_key(), "hex");
    }

    // -----------------------------------------------------------------------
    // package_name_from_tarball_filename (#973 / PR #974 shadowing guard,
    // moved here from api/handlers/hex.rs as part of #1217 audit follow-up
    // ak-niid).
    // -----------------------------------------------------------------------

    #[test]
    fn test_package_name_from_tarball_filename_simple_name() {
        assert_eq!(
            package_name_from_tarball_filename("phoenix-1.4.0.tar"),
            Some("phoenix".to_string())
        );
    }

    #[test]
    fn test_package_name_from_tarball_filename_dashed_name() {
        // The first `-` is followed by `p` (not a digit), so the parser must
        // advance to the second `-` which is followed by `1`. This is the
        // load-bearing case for hex names like `ex-doc-0.30.0` (a real
        // package on hex.pm) and matches `HexHandler::parse_path`.
        assert_eq!(
            package_name_from_tarball_filename("my-package-2.0.0.tar"),
            Some("my-package".to_string())
        );
        assert_eq!(
            package_name_from_tarball_filename("ex-doc-0.30.0.tar"),
            Some("ex-doc".to_string())
        );
    }

    #[test]
    fn test_package_name_from_tarball_filename_no_extension() {
        assert_eq!(package_name_from_tarball_filename("phoenix-1.4.0"), None);
    }

    #[test]
    fn test_package_name_from_tarball_filename_no_version_separator() {
        assert_eq!(package_name_from_tarball_filename("phoenix.tar"), None);
    }

    #[test]
    fn test_package_name_from_tarball_filename_dash_not_followed_by_digit() {
        // `phoenix-html` has a dash, but no digit follows. There is no
        // version, so the filename does not parse as a tarball.
        assert_eq!(package_name_from_tarball_filename("phoenix-html.tar"), None);
    }

    #[test]
    fn test_package_name_from_tarball_filename_version_with_prerelease() {
        // SemVer pre-release (`1.0.0-rc.1`) starts with a digit so the
        // parser picks the right `-`.
        assert_eq!(
            package_name_from_tarball_filename("phoenix-1.0.0-rc.1.tar"),
            Some("phoenix".to_string())
        );
    }

    #[test]
    fn test_package_name_from_tarball_filename_empty_name_rejected() {
        // `-1.0.0.tar` has the version-looking suffix but the name is empty.
        // The shadowing guard must fail closed: empty name returns None.
        assert_eq!(package_name_from_tarball_filename("-1.0.0.tar"), None);
    }

    #[test]
    fn test_package_name_from_tarball_filename_empty_string() {
        assert_eq!(package_name_from_tarball_filename(""), None);
    }

    #[test]
    fn test_package_name_from_tarball_filename_uppercase_extension() {
        // Case-insensitive `.tar` is load-bearing for the shadowing guard;
        // an attacker requesting `.Tar` must not skip the guard.
        assert_eq!(
            package_name_from_tarball_filename("phoenix-1.4.0.Tar"),
            Some("phoenix".to_string())
        );
        assert_eq!(
            package_name_from_tarball_filename("PHOENIX-1.4.0.TAR"),
            Some("phoenix".to_string())
        );
    }

    #[test]
    fn test_package_name_from_tarball_filename_rejects_path_traversal() {
        // Path-traversal-shaped names must be rejected by the hex name
        // validator so an attacker cannot trick the guard into emitting
        // a DB lookup for a forbidden identifier.
        assert_eq!(package_name_from_tarball_filename("..%2f-1.0.0.tar"), None);
        assert_eq!(package_name_from_tarball_filename("../-1.0.0.tar"), None);
        assert_eq!(
            package_name_from_tarball_filename("phoenix/../-1.0.0.tar"),
            None
        );
        // Double-encoded variant: axum percent-decodes once, so `%25`
        // becomes `%` and the validator then rejects the `%` character.
        assert_eq!(
            package_name_from_tarball_filename("..%252f-1.0.0.tar"),
            None
        );
    }

    #[test]
    fn test_package_name_from_tarball_filename_rejects_unicode_homoglyphs() {
        // Non-ASCII characters must be rejected: SQL `LOWER()` is ASCII-only
        // and would otherwise produce a different result than the parser's
        // ASCII lowercase, opening a homoglyph-shadowing attack.
        // (Cyrillic "о" U+043E in place of Latin "o".)
        assert_eq!(
            package_name_from_tarball_filename("ph\u{043e}enix-1.0.0.tar"),
            None
        );
    }

    #[test]
    fn test_package_name_from_tarball_filename_rejects_name_starting_with_digit() {
        // Hex spec: names must start with `[a-z]`. A leading digit would
        // make the parser confuse a version-looking prefix for a name.
        assert_eq!(package_name_from_tarball_filename("1cool-1.0.tar"), None);
        assert_eq!(
            package_name_from_tarball_filename("1.0.0-package-2.0.0.tar"),
            None
        );
    }

    #[test]
    fn test_package_name_from_tarball_filename_rejects_underscore_leading() {
        assert_eq!(package_name_from_tarball_filename("_foo-1.0.0.tar"), None);
    }

    #[test]
    fn test_package_name_from_tarball_filename_accepts_underscore_internal() {
        // Internal underscores are allowed per hex spec `[a-z][a-z0-9_]*`.
        assert_eq!(
            package_name_from_tarball_filename("foo_bar-1.0.0.tar"),
            Some("foo_bar".to_string())
        );
    }

    #[test]
    fn test_package_name_from_tarball_filename_rejects_special_chars() {
        // Spaces, slashes, dots in the name must all be rejected.
        assert_eq!(
            package_name_from_tarball_filename("foo bar-1.0.0.tar"),
            None
        );
        assert_eq!(
            package_name_from_tarball_filename("foo.bar-1.0.0.tar"),
            None
        );
        assert_eq!(
            package_name_from_tarball_filename("foo+bar-1.0.0.tar"),
            None
        );
    }

    #[test]
    fn test_is_valid_hex_package_name_accepts_spec_compliant() {
        assert!(is_valid_hex_package_name("phoenix"));
        assert!(is_valid_hex_package_name("phoenix_live_view"));
        assert!(is_valid_hex_package_name("ex-doc")); // dashes allowed
        assert!(is_valid_hex_package_name("a"));
        assert!(is_valid_hex_package_name("abc123"));
    }

    #[test]
    fn test_is_valid_hex_package_name_rejects_invalid() {
        assert!(!is_valid_hex_package_name("")); // empty
        assert!(!is_valid_hex_package_name("1abc")); // leading digit
        assert!(!is_valid_hex_package_name("_abc")); // leading underscore
        assert!(!is_valid_hex_package_name("-abc")); // leading dash
        assert!(!is_valid_hex_package_name("Phoenix")); // uppercase
        assert!(!is_valid_hex_package_name("abc.def")); // dot
        assert!(!is_valid_hex_package_name("abc def")); // space
        assert!(!is_valid_hex_package_name("abc/def")); // slash (traversal)
    }
}
