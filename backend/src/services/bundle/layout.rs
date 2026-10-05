//! On-media layout of a bundle and the path guards every entry must pass.
//!
//! ```text
//! manifest.json                         first entry; the signed index (P3)
//! repos/<repo-key>/repo.json            repository identity and settings
//! repos/<repo-key>/artifacts.json       per-artifact metadata rows
//! repos/<repo-key>/oci.json             OCI tags/manifests (OCI repos only)
//! blobs/<sha[0..2]>/<sha256><.ext>      content, one file per distinct blob
//! evidence/<sha[0..2]>/<sha256>.json    low-side scan evidence documents
//! signing/<name>.json                   key status list (P3, #2466)
//! ```
//!
//! The layout is deliberately flat and ASCII. Logical artifact paths (Maven
//! coordinates, scoped npm names, OCI references) routinely exceed ISO 9660
//! and UDF name limits, so they never become file names: they live in the
//! manifest, and the content is stored under its SHA-256 with the real
//! extension kept so file-type allowlists and AV engines still see a `.jar`
//! as a `.jar`.
//!
//! Every path read from a tar header or a manifest goes through
//! [`check_bundle_path`], which reuses the migration subsystem's
//! zip-slip guards ([`MigrationService::is_path_safe`] and
//! [`MigrationService::sanitize_path`]) before the layout match.

use super::BundleError;
use crate::api::handlers::repositories::validate_repository_key;
use crate::services::migration_service::MigrationService;

/// Name of the manifest entry. It must be the first entry of the tar stream.
pub const MANIFEST_PATH: &str = "manifest.json";
/// Top-level directory holding content-addressed blobs.
pub const BLOBS_DIR: &str = "blobs";
/// Top-level directory holding per-repository metadata documents.
pub const REPOS_DIR: &str = "repos";
/// Top-level directory holding imported scan evidence documents.
pub const EVIDENCE_DIR: &str = "evidence";
/// Top-level directory reserved for signing material (key status list, P3).
pub const SIGNING_DIR: &str = "signing";

/// Longest bundle-internal path accepted (UDF's path limit).
pub const MAX_BUNDLE_PATH_BYTES: usize = 1023;
/// Longest single path component accepted (UDF / common filesystem limit).
pub const MAX_COMPONENT_BYTES: usize = 255;
/// Longest logical artifact path a manifest may name.
pub const MAX_LOGICAL_PATH_BYTES: usize = 4096;
/// Longest repository key a bundle may carry.
pub const MAX_REPO_KEY_BYTES: usize = 128;
/// Longest blob extension kept (including the dots, e.g. `.tar.gz`).
pub const MAX_EXTENSION_BYTES: usize = 16;

/// Multi-part extensions preserved whole, so a source tarball is stored as
/// `<sha>.tar.gz` rather than `<sha>.gz`.
const COMPOUND_EXTENSIONS: &[&str] = &[".tar.gz", ".tar.bz2", ".tar.xz", ".tar.zst"];

/// One of the per-repository metadata documents under `repos/<key>/`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepoFile {
    Repo,
    Artifacts,
    Oci,
}

impl RepoFile {
    pub fn file_name(self) -> &'static str {
        match self {
            RepoFile::Repo => "repo.json",
            RepoFile::Artifacts => "artifacts.json",
            RepoFile::Oci => "oci.json",
        }
    }

    fn from_file_name(name: &str) -> Option<Self> {
        [RepoFile::Repo, RepoFile::Artifacts, RepoFile::Oci]
            .into_iter()
            .find(|f| f.file_name() == name)
    }
}

/// What a (safe) bundle file path refers to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BundleEntry {
    Manifest,
    RepoFile {
        repository_key: String,
        file: RepoFile,
    },
    Blob {
        sha256: String,
    },
    Evidence {
        sha256: String,
    },
    Signing {
        name: String,
    },
}

fn unsafe_path(path: &str, reason: impl Into<String>) -> BundleError {
    BundleError::UnsafePath {
        path: path.to_string(),
        reason: reason.into(),
    }
}

/// `true` for a lowercase, 64-character hex SHA-256 digest.
pub fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// `true` when `key` is a repository key a bundle may carry: exactly the
/// keys the product lets an operator create
/// ([`validate_repository_key`]: 1-128 ASCII alphanumerics, `-`, `_`, `.`,
/// no leading `.`/`-`, no `..`), each of which is also a safe single path
/// component.
pub fn is_valid_repo_key(key: &str) -> bool {
    key.len() <= MAX_REPO_KEY_BYTES && validate_repository_key(key).is_ok()
}

/// Validate a path that names a file or directory *inside* the bundle.
///
/// Rejects, in order: empty or over-long paths; anything the migration
/// zip-slip guard [`MigrationService::is_path_safe`] rejects (`..`, absolute,
/// drive-letter and UNC paths); anything [`MigrationService::sanitize_path`]
/// would rewrite (control characters, Windows-reserved characters,
/// backslashes, `//`, a leading or trailing `/`); and finally any character
/// outside the layout's ASCII alphabet or a `.`/over-long component.
pub fn check_bundle_path(path: &str) -> Result<(), BundleError> {
    if path.is_empty() {
        return Err(unsafe_path(path, "empty path"));
    }
    if path.len() > MAX_BUNDLE_PATH_BYTES {
        return Err(unsafe_path(
            path,
            format!("longer than {MAX_BUNDLE_PATH_BYTES} bytes"),
        ));
    }
    if !MigrationService::is_path_safe(path) {
        return Err(unsafe_path(
            path,
            "path traversal, absolute, drive-letter or UNC path",
        ));
    }
    if MigrationService::sanitize_path(path) != path {
        return Err(unsafe_path(
            path,
            "contains control, reserved or backslash characters, or empty components",
        ));
    }
    if !path
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'/'))
    {
        return Err(unsafe_path(
            path,
            "only ASCII letters, digits, '.', '_', '-' and '/' are allowed",
        ));
    }
    for component in path.split('/') {
        if component == "." {
            return Err(unsafe_path(path, "'.' path component"));
        }
        if component.len() > MAX_COMPONENT_BYTES {
            return Err(unsafe_path(
                path,
                format!("path component longer than {MAX_COMPONENT_BYTES} bytes"),
            ));
        }
    }
    Ok(())
}

/// Validate a logical artifact path named by the manifest (the path the
/// artifact has inside its repository). Logical paths never become file names
/// in the bundle, so they keep their own alphabet (`@scope/pkg`,
/// `sha256:...`), but they are still refused if they could traverse when the
/// import worker joins them under a repository root.
pub fn check_logical_path(path: &str) -> Result<(), BundleError> {
    if path.is_empty() {
        return Err(unsafe_path(path, "empty logical path"));
    }
    if path.len() > MAX_LOGICAL_PATH_BYTES {
        return Err(unsafe_path(
            path,
            format!("logical path longer than {MAX_LOGICAL_PATH_BYTES} bytes"),
        ));
    }
    if !MigrationService::is_path_safe(path) {
        return Err(unsafe_path(
            path,
            "path traversal, absolute, drive-letter or UNC path",
        ));
    }
    if path.chars().any(|c| c.is_control() || c == '\\') {
        return Err(unsafe_path(path, "control character or backslash"));
    }
    if path.split('/').any(|c| c.is_empty() || c == ".") {
        return Err(unsafe_path(path, "empty or '.' path component"));
    }
    Ok(())
}

/// The extension a blob keeps, derived from its logical path: lowercase,
/// ASCII alphanumeric segments only, compound tarball extensions kept whole,
/// and empty when the file name has no usable extension.
pub fn blob_extension(logical_path: &str) -> String {
    let name = logical_path
        .rsplit('/')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    if let Some(ext) = COMPOUND_EXTENSIONS.iter().find(|e| name.ends_with(*e)) {
        if name.len() > ext.len() {
            return (*ext).to_string();
        }
    }
    match name.rfind('.') {
        Some(idx) if idx > 0 => {
            let ext = &name[idx..];
            let body = &ext[1..];
            if !body.is_empty()
                && ext.len() <= MAX_EXTENSION_BYTES
                && body.bytes().all(|b| b.is_ascii_alphanumeric())
            {
                ext.to_string()
            } else {
                String::new()
            }
        }
        _ => String::new(),
    }
}

/// Canonical blob path for content `sha256` stored for `logical_path`.
pub fn blob_path(sha256: &str, logical_path: &str) -> String {
    format!(
        "{BLOBS_DIR}/{}/{sha256}{}",
        &sha256[..2.min(sha256.len())],
        blob_extension(logical_path)
    )
}

/// Canonical path of a per-repository metadata document.
pub fn repo_file_path(repository_key: &str, file: RepoFile) -> String {
    format!("{REPOS_DIR}/{repository_key}/{}", file.file_name())
}

/// Canonical path of a scan evidence document whose bytes hash to `sha256`.
pub fn evidence_path(sha256: &str) -> String {
    format!(
        "{EVIDENCE_DIR}/{}/{sha256}.json",
        &sha256[..2.min(sha256.len())]
    )
}

/// Split a blob file name into `(sha256, extension)` and check the fan-out
/// directory matches the digest.
fn parse_blob_name(path: &str, fanout: &str, name: &str) -> Result<String, BundleError> {
    let (sha, ext) = name.split_at(64.min(name.len()));
    if !is_sha256_hex(sha) {
        return Err(unsafe_path(path, "blob name is not a SHA-256 digest"));
    }
    if fanout != &sha[..2] {
        return Err(unsafe_path(
            path,
            "blob fan-out directory does not match digest",
        ));
    }
    if !ext.is_empty() && blob_extension(&format!("x{ext}")) != ext {
        return Err(unsafe_path(path, "blob extension is not canonical"));
    }
    Ok(sha.to_string())
}

/// Classify a regular-file path from the tar stream, after
/// [`check_bundle_path`]. Anything outside the layout is refused: a bundle
/// carries nothing that the manifest cannot account for.
pub fn classify_file(path: &str) -> Result<BundleEntry, BundleError> {
    check_bundle_path(path)?;
    let parts: Vec<&str> = path.split('/').collect();
    match parts.as_slice() {
        [MANIFEST_PATH] => Ok(BundleEntry::Manifest),
        [REPOS_DIR, key, file] if is_valid_repo_key(key) => RepoFile::from_file_name(file)
            .map(|file| BundleEntry::RepoFile {
                repository_key: (*key).to_string(),
                file,
            })
            .ok_or_else(|| unsafe_path(path, "unknown repository metadata document")),
        [BLOBS_DIR, fanout, name] => Ok(BundleEntry::Blob {
            sha256: parse_blob_name(path, fanout, name)?,
        }),
        [EVIDENCE_DIR, fanout, name] => {
            let sha = name
                .strip_suffix(".json")
                .filter(|s| is_sha256_hex(s) && &s[..2] == *fanout)
                .ok_or_else(|| unsafe_path(path, "evidence name is not <sha256>.json"))?;
            Ok(BundleEntry::Evidence {
                sha256: sha.to_string(),
            })
        }
        [SIGNING_DIR, name] if name.ends_with(".json") => Ok(BundleEntry::Signing {
            name: (*name).to_string(),
        }),
        _ => Err(unsafe_path(path, "not part of the bundle layout")),
    }
}

/// Validate a directory path from the tar stream. Only the layout's own
/// directories may appear (they are optional; tar writers may omit them).
pub fn check_directory(path: &str) -> Result<(), BundleError> {
    check_bundle_path(path)?;
    let parts: Vec<&str> = path.split('/').collect();
    let ok = match parts.as_slice() {
        [BLOBS_DIR] | [REPOS_DIR] | [EVIDENCE_DIR] | [SIGNING_DIR] => true,
        [BLOBS_DIR, fanout] | [EVIDENCE_DIR, fanout] => {
            fanout.len() == 2
                && fanout
                    .bytes()
                    .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        }
        [REPOS_DIR, key] => is_valid_repo_key(key),
        _ => false,
    };
    if ok {
        Ok(())
    } else {
        Err(unsafe_path(
            path,
            "directory is not part of the bundle layout",
        ))
    }
}

#[cfg(ak_test_shard = "services-1")]
#[cfg(test)]
mod tests {
    use super::*;

    const SHA: &str = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

    #[test]
    fn zip_slip_and_absolute_paths_are_refused() {
        for bad in [
            "../etc/passwd",
            "blobs/../../etc/passwd",
            "repos/x/../../../root/.ssh/authorized_keys",
            "/etc/passwd",
            "\\\\server\\share\\x",
            "C:/Windows/system32",
            "c:evil",
            "blobs\\ab\\x",
            "blobs//ab",
            "blobs/ab/",
            "./manifest.json",
            "repos/./x",
            "manifest.json\0",
            "blobs/ab/\u{1b}x",
            "blobs/ab/caf\u{e9}.jar",
            "blobs/ab/a b.jar",
            "",
        ] {
            assert!(
                check_bundle_path(bad).is_err(),
                "bundle path {bad:?} must be refused"
            );
            assert!(classify_file(bad).is_err(), "{bad:?} must not classify");
        }
    }

    #[test]
    fn over_long_paths_and_components_are_refused() {
        let long_component = "a".repeat(MAX_COMPONENT_BYTES + 1);
        assert!(check_bundle_path(&format!("repos/{long_component}")).is_err());
        let long_path = format!("{}/x", "ab/".repeat(400));
        assert!(check_bundle_path(&long_path).is_err());
        assert!(check_logical_path(&"a".repeat(MAX_LOGICAL_PATH_BYTES + 1)).is_err());
    }

    #[test]
    fn layout_paths_classify() {
        assert_eq!(classify_file("manifest.json"), Ok(BundleEntry::Manifest));
        assert_eq!(
            classify_file("repos/libs-release/repo.json"),
            Ok(BundleEntry::RepoFile {
                repository_key: "libs-release".into(),
                file: RepoFile::Repo
            })
        );
        assert_eq!(
            classify_file("repos/docker-local/oci.json"),
            Ok(BundleEntry::RepoFile {
                repository_key: "docker-local".into(),
                file: RepoFile::Oci
            })
        );
        let jar = blob_path(SHA, "com/acme/lib/1.0/lib-1.0.jar");
        assert_eq!(jar, format!("blobs/ab/{SHA}.jar"));
        assert_eq!(
            classify_file(&jar),
            Ok(BundleEntry::Blob { sha256: SHA.into() })
        );
        assert_eq!(
            classify_file(&blob_path(SHA, "v2/lib/blobs/sha256:abc")),
            Ok(BundleEntry::Blob { sha256: SHA.into() })
        );
        assert_eq!(
            classify_file(&evidence_path(SHA)),
            Ok(BundleEntry::Evidence { sha256: SHA.into() })
        );
        assert_eq!(
            classify_file("signing/key-status.json"),
            Ok(BundleEntry::Signing {
                name: "key-status.json".into()
            })
        );
    }

    #[test]
    fn paths_outside_the_layout_are_refused() {
        for bad in [
            "README.txt",
            "repos/libs/extra.json",
            "repos/-bad-/repo.json",
            "repos/libs/sub/repo.json",
            &format!("blobs/cd/{SHA}.jar"),
            "blobs/ab/notahash.jar",
            &format!("blobs/ab/{SHA}.JAR"),
            &format!("blobs/ab/{SHA}.ja_r"),
            &format!("evidence/ab/{SHA}.txt"),
            &format!("evidence/cd/{SHA}.json"),
            "signing/key.pem",
            "blobs/ab/x/y/z",
        ] {
            assert!(classify_file(bad).is_err(), "{bad:?} must be refused");
        }
    }

    #[test]
    fn directories_are_limited_to_the_layout() {
        for ok in [
            "blobs",
            "blobs/ab",
            "repos",
            "repos/libs",
            "evidence/0f",
            "signing",
        ] {
            assert!(check_directory(ok).is_ok(), "{ok:?} is a layout directory");
        }
        for bad in ["blobs/xyz", "blobs/AB", "tmp", "repos/a b", "../blobs"] {
            assert!(check_directory(bad).is_err(), "{bad:?} must be refused");
        }
    }

    #[test]
    fn blob_extension_keeps_the_real_extension() {
        assert_eq!(blob_extension("a/b/lib-1.0.jar"), ".jar");
        assert_eq!(blob_extension("pkg-1.0.tar.gz"), ".tar.gz");
        assert_eq!(blob_extension("x/Pkg-1.0.WHL"), ".whl");
        assert_eq!(blob_extension("noext"), "");
        assert_eq!(blob_extension(".hidden"), "");
        assert_eq!(blob_extension("x/.tar.gz"), ".gz");
        assert_eq!(blob_extension("weird.ex t"), "");
        assert_eq!(blob_extension("trailing."), "");
        assert_eq!(blob_extension("x.averyveryverylongextension"), "");
        assert_eq!(blob_extension("v2/lib/blobs/sha256:abc"), "");
    }

    #[test]
    fn logical_paths_allow_registry_alphabets_but_not_traversal() {
        for ok in [
            "@scope/pkg/-/pkg-1.0.0.tgz",
            "v2/lib/manifests/sha256:abcd",
            "com/acme/lib/1.0/lib-1.0.jar",
        ] {
            assert!(check_logical_path(ok).is_ok(), "{ok:?} is a logical path");
        }
        for bad in [
            "", "../x", "/abs", "a//b", "a/./b", "a/b/", "a\\b", "a\u{0}b", "C:x",
        ] {
            assert!(check_logical_path(bad).is_err(), "{bad:?} must be refused");
        }
    }

    #[test]
    fn repo_keys_match_the_product_rule() {
        for ok in ["libs-release_1.x", "libs-", "libs.", "Libs"] {
            assert!(is_valid_repo_key(ok), "{ok:?} is a creatable key");
        }
        for bad in ["", "a b", "-lead", ".lead", "a..b", "a/b", "..", "ü"] {
            assert!(!is_valid_repo_key(bad), "{bad:?} must be refused");
        }
        assert!(!is_valid_repo_key(&"a".repeat(MAX_REPO_KEY_BYTES + 1)));
        assert!(is_sha256_hex(SHA));
        assert!(!is_sha256_hex(&SHA.to_uppercase()));
        assert!(!is_sha256_hex("abc"));
    }
}
