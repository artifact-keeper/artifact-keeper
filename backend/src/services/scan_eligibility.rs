//! Shared rules for which artifact filenames are eligible for security
//! scanning / SBOM analysis.
//!
//! Originally lived only inside [`crate::services::grype_scanner::GrypeScanner`]
//! (`is_meaningful_non_oci_target`, fork "limit scanning types of files"). After
//! upstream #2227/#2292 marked every proxy-cache listing row `analyzable:
//! false`, the UI disabled Scan/SBOM for all Remote packages — including real
//! payloads this allowlist already accepted. The same predicate now drives:
//! - Grype applicability for non-OCI targets
//! - `analyzable` on Remote (proxy-cache) listing rows
//! - materializing a hosted `artifacts` row so Scan/SBOM can resolve the object

/// Return true when `file_name` (final path segment) is a package payload or
/// dependency manifest worth scanning.
///
/// Rejects checksum/signature sidecars and common repository index metadata
/// so Cargo/Maven/npm proxies do not flood Grype with non-packages.
pub fn is_scannable_package_name(file_name: &str) -> bool {
    let file_name = file_name.to_lowercase();

    if file_name.is_empty() {
        return false;
    }

    if [
        ".sha1", ".sha256", ".sha512", ".md5", ".asc", ".sig", ".minisig",
    ]
    .iter()
    .any(|ext| file_name.ends_with(ext))
    {
        return false;
    }

    // Repository indexes / metadata (not package payloads).
    if file_name == "maven-metadata.xml"
        || file_name == "config.json"
        || file_name == "index.v1+json"
        || file_name == "index.html"
        || file_name.ends_with(".metadata")
        || file_name == "repomd.xml"
        || file_name == "primary.xml.gz"
        || file_name == "filelists.xml.gz"
        || file_name == "other.xml.gz"
        || file_name == "updateinfo.xml.gz"
        || file_name == "packages.json"
        || file_name == "packument.json"
    {
        return false;
    }

    if [
        ".crate", ".whl", ".jar", ".war", ".ear", ".nupkg", ".gem", ".zip", ".tgz", ".tar.gz",
        ".tar.bz2", ".tar.xz", ".deb", ".rpm", ".apk", ".conda", ".egg", ".pex",
    ]
    .iter()
    .any(|ext| file_name.ends_with(ext))
    {
        return true;
    }

    // npm tarballs often end in `.tgz` (covered above). Bare scoped packages
    // can also be served as `package.tgz` already covered.
    [
        "cargo.lock",
        "cargo.toml",
        "package-lock.json",
        "pnpm-lock.yaml",
        "yarn.lock",
        "requirements.txt",
        "pipfile.lock",
        "poetry.lock",
        "gemfile.lock",
        "go.mod",
        "go.sum",
        "composer.lock",
        "packages.lock.json",
        "pubspec.lock",
        "mix.lock",
        "conan.lock",
        "pom.xml",
    ]
    .contains(&file_name.as_str())
}

/// Cargo sparse/registry download URLs end in `/download` while the real
/// artifact is `{name}-{version}.crate`. Recognize
/// `api/v1/crates/{name}/{version}/download`.
pub fn cargo_crate_filename_from_path(path: &str) -> Option<String> {
    let parts: Vec<&str> = path.split('/').filter(|p| !p.is_empty()).collect();
    if parts.len() == 6
        && parts[0].eq_ignore_ascii_case("api")
        && parts[1].eq_ignore_ascii_case("v1")
        && parts[2].eq_ignore_ascii_case("crates")
        && parts[5].eq_ignore_ascii_case("download")
    {
        let name = parts[3];
        let version = parts[4];
        if !name.is_empty() && !version.is_empty() {
            return Some(format!("{name}-{version}.crate"));
        }
    }
    None
}

/// Display name for a proxy-cache listing row (UI `Artifact.name`).
///
/// Prefer a real package filename when the cache path is a protocol quirk
/// (Cargo `/download`); otherwise the final path segment.
pub fn proxy_listing_display_name(path: &str) -> String {
    if let Some(crate_name) = cargo_crate_filename_from_path(path) {
        return crate_name;
    }
    let name = path.rsplit('/').next().unwrap_or(path);
    if name.is_empty() {
        // Trailing-slash index paths (`simple/pkg/`) have an empty basename.
        path.trim_end_matches('/')
            .rsplit('/')
            .next()
            .unwrap_or(path)
            .to_string()
    } else {
        name.to_string()
    }
}

/// Convenience wrapper over a full logical path.
pub fn is_scannable_package_path(path: &str) -> bool {
    if cargo_crate_filename_from_path(path).is_some() {
        return true;
    }
    let name = proxy_listing_display_name(path);
    is_scannable_package_name(&name)
}

/// Deterministic listing id for a proxy-cached object (same algorithm as
/// `repositories::cached_artifact_id`: first 16 bytes of SHA-256 over
/// `proxy-cache/<repo_key>/<path>`).
pub fn proxy_cache_listing_id(repo_key: &str, path: &str) -> uuid::Uuid {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(format!("proxy-cache/{}/{}", repo_key, path).as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    uuid::Uuid::from_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_payloads_are_scannable() {
        for name in [
            "bytes-3.1.2.tgz",
            "requests-2.32.3-py3-none-any.whl",
            "serde-1.0.0.crate",
            "Newtonsoft.Json.13.0.1.nupkg",
            "which-2.21-1.fc44.x86_64.rpm",
            "curl_8.5.0-2_amd64.deb",
            "foo-1.0.0.jar",
        ] {
            assert!(
                is_scannable_package_name(name),
                "{name} should be scannable"
            );
        }
    }

    #[test]
    fn sidecars_and_indexes_are_not_scannable() {
        for name in [
            "bytes-3.1.2.tgz.sha512",
            "foo.jar.md5",
            "maven-metadata.xml",
            "config.json",
            "repomd.xml",
            "requests-2.32.3-py3-none-any.whl.metadata",
            "packument.json",
            "index.v1+json",
            "index.html",
        ] {
            assert!(
                !is_scannable_package_name(name),
                "{name} should NOT be scannable"
            );
        }
    }

    #[test]
    fn cargo_download_path_is_scannable_with_crate_display_name() {
        let path = "api/v1/crates/serde/1.0.210/download";
        assert_eq!(
            cargo_crate_filename_from_path(path).as_deref(),
            Some("serde-1.0.210.crate")
        );
        assert_eq!(proxy_listing_display_name(path), "serde-1.0.210.crate");
        assert!(is_scannable_package_path(path));
    }

    #[test]
    fn pypi_pep691_index_is_not_scannable() {
        assert!(!is_scannable_package_path("simple/requests/index.v1+json"));
    }

    #[test]
    fn listing_id_is_stable() {
        let a = proxy_cache_listing_id("npm-proxy", "bytes/-/bytes-3.1.2.tgz");
        let b = proxy_cache_listing_id("npm-proxy", "bytes/-/bytes-3.1.2.tgz");
        let c = proxy_cache_listing_id("npm-proxy", "bytes/-/bytes-3.1.3.tgz");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
