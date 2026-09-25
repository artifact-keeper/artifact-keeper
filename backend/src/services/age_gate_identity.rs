//! Parse (package, version) identity from a proxy path for age-gate enforcement.
//!
//! Dedicated npm / PyPI / Go handlers already pass identity they parse
//! themselves. This module covers the other formats so a shared download seam
//! can withhold too-new upstream coordinates. Index and checksum paths return
//! `None` so metadata stays reachable while the versioned artifact is gated.

use crate::formats::maven::MavenHandler;
use crate::models::repository::RepositoryFormat;
use crate::services::age_gate_service::AgeGateService;

/// Formats whose download handlers already call [`super::age_gate_service`]
/// with a parsed identity. The generic path seam must skip them so a single
/// request cannot open two review rows.
pub fn has_dedicated_age_gate_handler(format: &RepositoryFormat) -> bool {
    matches!(
        AgeGateService::normalize_format(format.clone()),
        RepositoryFormat::Npm | RepositoryFormat::Pypi | RepositoryFormat::Go
    )
}

/// Extract the age-gate coordinate from an upstream/cache path, or `None` when
/// the path is metadata/index/checksums (do not start a clock on a listing).
pub fn identity_from_path(format: &RepositoryFormat, path: &str) -> Option<(String, String)> {
    let path = path.trim_start_matches('/');
    if path.is_empty() {
        return None;
    }
    let canonical = AgeGateService::normalize_format(format.clone());
    if has_dedicated_age_gate_handler(&canonical) {
        return None;
    }
    match canonical {
        RepositoryFormat::Maven => maven_identity(path),
        RepositoryFormat::Cargo => cargo_identity(path),
        RepositoryFormat::Nuget => nuget_identity(path),
        RepositoryFormat::Debian => debian_identity(path),
        RepositoryFormat::Rpm => rpm_identity(path),
        RepositoryFormat::Alpine => alpine_identity(path),
        RepositoryFormat::Rubygems => rubygems_identity(path),
        RepositoryFormat::Hex => hex_identity(path),
        RepositoryFormat::Composer => composer_identity(path),
        RepositoryFormat::Terraform => terraform_identity(path),
        RepositoryFormat::Protobuf => protobuf_identity(path),
        RepositoryFormat::Conan => conan_identity(path),
        RepositoryFormat::Helm => helm_identity(path),
        RepositoryFormat::Cran => cran_identity(path),
        RepositoryFormat::Docker => None,
        _ => generic_versioned_file(path),
    }
}

fn filename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

fn is_sidecar(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.ends_with(".sha1")
        || lower.ends_with(".sha256")
        || lower.ends_with(".sha512")
        || lower.ends_with(".md5")
        || lower.ends_with(".asc")
        || lower.ends_with(".sig")
        || lower.ends_with(".module")
}

fn maven_identity(path: &str) -> Option<(String, String)> {
    let name = filename(path);
    if name.to_ascii_lowercase().contains("maven-metadata") || is_sidecar(name) {
        return None;
    }
    let coords = MavenHandler::parse_coordinates(path).ok()?;
    Some((
        format!("{}:{}", coords.group_id, coords.artifact_id),
        coords.version,
    ))
}

fn cargo_identity(path: &str) -> Option<(String, String)> {
    // api/v1/crates/{name}/{version}/download
    let parts: Vec<&str> = path.split('/').collect();
    let crates_idx = parts.iter().position(|p| *p == "crates")?;
    let name = *parts.get(crates_idx + 1)?;
    let version = *parts.get(crates_idx + 2)?;
    if name.is_empty() || version.is_empty() || version == "download" {
        return None;
    }
    Some((name.to_string(), version.to_string()))
}

fn nuget_identity(path: &str) -> Option<(String, String)> {
    let lower = path.to_ascii_lowercase();
    if lower.ends_with("/index.json") || lower.ends_with(".nuspec") {
        return None;
    }
    // v3/flatcontainer/{id}/{version}/{filename}
    if let Some(rest) = path
        .strip_prefix("v3/flatcontainer/")
        .or_else(|| path.strip_prefix("v3-flatcontainer/"))
    {
        let mut parts = rest.split('/');
        let id = parts.next()?;
        let version = parts.next()?;
        if id.is_empty() || version.is_empty() || version == "index.json" {
            return None;
        }
        return Some((id.to_string(), version.to_string()));
    }
    // v2/package/{id}/{version}
    if let Some(rest) = path.strip_prefix("v2/package/") {
        let mut parts = rest.split('/');
        let id = parts.next()?;
        let version = parts.next()?;
        if id.is_empty() || version.is_empty() {
            return None;
        }
        return Some((id.to_string(), version.to_string()));
    }
    None
}

fn debian_identity(path: &str) -> Option<(String, String)> {
    let name = filename(path);
    if !name.ends_with(".deb") && !name.ends_with(".ddeb") && !name.ends_with(".udeb") {
        return None;
    }
    // {package}_{version}_{arch}.deb
    let stem = name.rsplit_once('.')?.0;
    let (package, rest) = stem.split_once('_')?;
    let version = rest.rsplit_once('_').map(|(v, _)| v).unwrap_or(rest);
    if package.is_empty() || version.is_empty() {
        return None;
    }
    Some((package.to_string(), version.to_string()))
}

fn rpm_identity(path: &str) -> Option<(String, String)> {
    let lower = path.to_ascii_lowercase();
    if lower.contains("/repodata/") {
        return None;
    }
    let name = filename(path);
    if !name.ends_with(".rpm") {
        return None;
    }
    // Keep the whole NVR.arch stem as the package name: RPM filenames are the
    // immutable coordinate we observe, and splitting name/version/release is
    // ambiguous without a header.
    let stem = name.strip_suffix(".rpm")?;
    Some((stem.to_string(), "1".to_string()))
}

fn alpine_identity(path: &str) -> Option<(String, String)> {
    let name = filename(path);
    if name.starts_with("APKINDEX") {
        return None;
    }
    if !name.ends_with(".apk") {
        return None;
    }
    parse_nvr_filename(name, ".apk")
}

/// Split `{name}-{version}{suffix}` where version starts at the last `-{digit}`.
fn parse_nvr_filename(filename: &str, suffix: &str) -> Option<(String, String)> {
    let stem = filename.strip_suffix(suffix)?;
    let stem = stem.strip_suffix(".src").unwrap_or(stem);
    let dash = stem.rfind('-')?;
    let (name, version) = stem.split_at(dash);
    let version = version.trim_start_matches('-');
    if name.is_empty() || version.is_empty() {
        return None;
    }
    // Alpine/RPM: name may contain dashes; walk left while the segment after
    // the last dash does not look like a version (starts with a digit).
    if version.starts_with(|c: char| c.is_ascii_digit()) {
        return Some((name.to_string(), version.to_string()));
    }
    let dash = name.rfind('-')?;
    let (pkg, ver_prefix) = name.split_at(dash);
    let version = format!("{}-{}", ver_prefix.trim_start_matches('-'), version);
    if pkg.is_empty() || !version.starts_with(|c: char| c.is_ascii_digit()) {
        return None;
    }
    Some((pkg.to_string(), version))
}

fn rubygems_identity(path: &str) -> Option<(String, String)> {
    let name = filename(path);
    if name.starts_with("specs.")
        || name == "latest_specs.4.8.gz"
        || name == "prerelease_specs.4.8.gz"
    {
        return None;
    }
    if !name.ends_with(".gem") {
        return None;
    }
    parse_nvr_filename(name, ".gem")
}

fn hex_identity(path: &str) -> Option<(String, String)> {
    // tarballs/{name}-{version}.tar
    let name = filename(path);
    if name == "names" || name.starts_with("versions") {
        return None;
    }
    if let Some(stem) = name.strip_suffix(".tar") {
        return parse_nvr_filename(&format!("{stem}.tar"), ".tar");
    }
    None
}

fn composer_identity(path: &str) -> Option<(String, String)> {
    if path.contains("packages.json") || path.contains("/p2/") || path.ends_with(".json") {
        return None;
    }
    generic_versioned_file(path)
}

fn terraform_identity(path: &str) -> Option<(String, String)> {
    // terraform/{ns}/{name}/{version}/...
    let mut parts = path.trim_start_matches("terraform/").split('/');
    let ns = parts.next()?;
    let name = parts.next()?;
    let version = parts.next()?;
    if ns.is_empty() || name.is_empty() || version.is_empty() {
        return None;
    }
    Some((format!("{ns}/{name}"), version.to_string()))
}

fn protobuf_identity(path: &str) -> Option<(String, String)> {
    generic_versioned_file(path)
}

fn conan_identity(path: &str) -> Option<(String, String)> {
    // {name}/{version}/...
    let mut parts = path.split('/');
    let name = parts.next()?;
    let version = parts.next()?;
    if name.is_empty() || version.is_empty() || version.contains("conanfile") {
        return None;
    }
    Some((name.to_string(), version.to_string()))
}

fn helm_identity(path: &str) -> Option<(String, String)> {
    let name = filename(path);
    if name == "index.yaml" {
        return None;
    }
    if name.ends_with(".tgz") {
        return parse_nvr_filename(name, ".tgz");
    }
    None
}

fn cran_identity(path: &str) -> Option<(String, String)> {
    let name = filename(path);
    if name == "PACKAGES" || name == "PACKAGES.gz" {
        return None;
    }
    if name.ends_with(".tar.gz") {
        return parse_nvr_filename(name, ".tar.gz");
    }
    None
}

fn generic_versioned_file(path: &str) -> Option<(String, String)> {
    let name = filename(path);
    if is_sidecar(name) {
        return None;
    }
    let lower = name.to_ascii_lowercase();
    if lower.contains("index")
        || lower.contains("metadata")
        || lower == "packages"
        || lower == "release"
        || lower == "repomd.xml"
    {
        return None;
    }
    // `{name}-{version}.ext` with a version starting with a digit.
    let stem = name.split('.').next().unwrap_or(name);
    parse_nvr_filename(&format!("{stem}.bin"), ".bin")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maven_gav_from_jar_skips_metadata() {
        let id = identity_from_path(
            &RepositoryFormat::Maven,
            "com/example/lib/1.2.3/lib-1.2.3.jar",
        );
        assert_eq!(
            id,
            Some(("com.example:lib".to_string(), "1.2.3".to_string()))
        );
        assert!(identity_from_path(
            &RepositoryFormat::Maven,
            "com/example/lib/maven-metadata.xml"
        )
        .is_none());
        assert!(identity_from_path(
            &RepositoryFormat::Maven,
            "com/example/lib/1.2.3/lib-1.2.3.jar.sha1"
        )
        .is_none());
    }

    #[test]
    fn cargo_download_path() {
        assert_eq!(
            identity_from_path(
                &RepositoryFormat::Cargo,
                "api/v1/crates/serde/1.0.210/download"
            ),
            Some(("serde".to_string(), "1.0.210".to_string()))
        );
    }

    #[test]
    fn nuget_flatcontainer_and_v2() {
        assert_eq!(
            identity_from_path(
                &RepositoryFormat::Nuget,
                "v3/flatcontainer/newtonsoft.json/13.0.1/newtonsoft.json.13.0.1.nupkg"
            ),
            Some(("newtonsoft.json".to_string(), "13.0.1".to_string()))
        );
        assert_eq!(
            identity_from_path(
                &RepositoryFormat::Nuget,
                "v2/package/Newtonsoft.Json/13.0.1"
            ),
            Some(("Newtonsoft.Json".to_string(), "13.0.1".to_string()))
        );
        assert!(identity_from_path(
            &RepositoryFormat::Nuget,
            "v3/flatcontainer/newtonsoft.json/index.json"
        )
        .is_none());
    }

    #[test]
    fn debian_deb_filename() {
        assert_eq!(
            identity_from_path(
                &RepositoryFormat::Debian,
                "pool/main/c/curl/curl_8.5.0-2_amd64.deb"
            ),
            Some(("curl".to_string(), "8.5.0-2".to_string()))
        );
    }

    #[test]
    fn alpine_apk_skips_index() {
        assert_eq!(
            identity_from_path(
                &RepositoryFormat::Alpine,
                "v3.20/main/x86_64/curl-8.5.0-r0.apk"
            ),
            Some(("curl".to_string(), "8.5.0-r0".to_string()))
        );
        assert!(identity_from_path(
            &RepositoryFormat::Alpine,
            "v3.20/main/x86_64/APKINDEX.tar.gz"
        )
        .is_none());
    }

    #[test]
    fn dedicated_handlers_yield_none() {
        assert!(identity_from_path(&RepositoryFormat::Npm, "lodash/-/lodash-4.0.0.tgz").is_none());
        assert!(identity_from_path(
            &RepositoryFormat::Pypi,
            "packages/requests/requests-2.0.whl"
        )
        .is_none());
        assert!(
            identity_from_path(&RepositoryFormat::Go, "github.com/foo/bar/@v/v1.2.3.zip").is_none()
        );
        assert!(
            identity_from_path(&RepositoryFormat::Docker, "library/nginx/manifests/latest")
                .is_none()
        );
    }

    #[test]
    fn gradle_alias_uses_maven_parser() {
        assert_eq!(
            identity_from_path(
                &RepositoryFormat::Gradle,
                "org/junit/junit/4.13.2/junit-4.13.2.jar"
            ),
            Some(("org.junit:junit".to_string(), "4.13.2".to_string()))
        );
    }
}
