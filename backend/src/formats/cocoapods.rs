use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::error::{AppError, Result};
use crate::formats::FormatHandler;
use crate::models::repository::RepositoryFormat;

// ---------------------------------------------------------------------------
// CDN layout
// ---------------------------------------------------------------------------
//
// A CocoaPods client consumes a Spec repo over one of two transports: a git
// Specs repository, or a static CDN. The CDN layout is the modern default and
// is what `pod repo add-cdn` / a `source` line in a Podfile resolves against.
//
// The layout is defined by `cocoapods-core`:
//
//   * `CocoaPods-version.yml` is the entrypoint. The client probes it to decide
//     whether a URL is a CDN source at all, and reads `prefix_lengths` from it
//     to know how the tree is sharded (`Source::Metadata`).
//   * A CDN cannot be listed, so the available pods/versions are published as
//     pre-rendered index files, one per shard:
//     `all_pods_versions_<a>_<b>_<c>.txt`, each line `<pod>/<v1>/<v2>/...`
//     (`CDNSource#ensure_versions_file_loaded`).
//   * Podspecs live under the sharded path
//     `Specs/<a>/<b>/<c>/<pod>/<version>/<pod>.podspec.json`
//     (`Source#pod_path` + `CDNSource#specification_path`).
//
// The shard fragments come from `Source::Metadata#path_fragment`, which slices
// consecutive prefixes off the front of the lowercase hex MD5 of the pod name,
// one per entry in `prefix_lengths`:
//
//     hashed = Digest::MD5.hexdigest(pod_name)
//     prefix_lengths.map { |length| hashed.slice!(0, length) }
//
// With `prefix_lengths: [1, 1, 1]` (what the trunk CDN publishes, and what we
// publish) that is simply the first three hex characters of the MD5, e.g.
// `Alamofire` -> md5 `da208d9c...` -> shard `d/a/2` -> index file
// `all_pods_versions_d_a_2.txt` and podspecs under `Specs/d/a/2/Alamofire/`.

/// The `prefix_lengths` advertised in `CocoaPods-version.yml`.
///
/// Each entry is the number of hex characters of the pod-name MD5 consumed by
/// one level of the shard fan-out. This is the single source of truth for the
/// sharding rule: the index file names, the `Specs/` tree layout and the served
/// manifest are all derived from it.
pub const CDN_PREFIX_LENGTHS: [usize; 3] = [1, 1, 1];

/// The minimum CocoaPods client version advertised in `CocoaPods-version.yml`.
///
/// The client refuses a source whose `min` is above its own version
/// (`Source::Metadata#compatible?`). The layout we serve has been stable since
/// CDN support landed, so we advertise the same floor as the trunk CDN and no
/// `max`.
pub const CDN_MIN_COCOAPODS_VERSION: &str = "1.0.0";

/// The CDN entrypoint file a client probes to identify a CDN source.
pub const CDN_VERSION_FILE: &str = "CocoaPods-version.yml";

/// The CDN's list of deprecated podspec paths.
pub const CDN_DEPRECATED_PODSPECS_FILE: &str = "deprecated_podspecs.txt";

const CDN_INDEX_PREFIX: &str = "all_pods_versions_";
const CDN_INDEX_SUFFIX: &str = ".txt";

/// The contents of `CocoaPods-version.yml`: the CDN capability manifest.
///
/// Mirrors `Pod::Source::Metadata#to_hash`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CdnMetadata {
    /// Minimum compatible CocoaPods client version.
    pub min: String,
    /// Hex-character counts of each level of the MD5 shard fan-out.
    pub prefix_lengths: Vec<usize>,
}

impl Default for CdnMetadata {
    fn default() -> Self {
        Self {
            min: CDN_MIN_COCOAPODS_VERSION.to_string(),
            prefix_lengths: CDN_PREFIX_LENGTHS.to_vec(),
        }
    }
}

/// Compute the CDN shard fragment for a pod name.
///
/// Port of `Pod::Source::Metadata#path_fragment` (minus the trailing
/// name/version elements): consecutive prefixes sliced off the front of the
/// lowercase hex MD5 of the pod name, one per `CDN_PREFIX_LENGTHS` entry.
pub fn cdn_shard_fragment(pod_name: &str) -> Vec<String> {
    use md5::{Digest, Md5};

    let mut hasher = Md5::new();
    Digest::update(&mut hasher, pod_name.as_bytes());
    let hashed = format!("{:x}", Digest::finalize(hasher));

    let mut rest = hashed.as_str();
    CDN_PREFIX_LENGTHS
        .iter()
        .map(|&length| {
            let (head, tail) = rest.split_at(length);
            rest = tail;
            head.to_string()
        })
        .collect()
}

/// The name of the sharded index file that lists a pod's versions.
///
/// Port of `Pod::CDNSource#index_file_name_for_fragment`.
pub fn cdn_index_file_name(pod_name: &str) -> String {
    cdn_index_file_name_for_shard(&cdn_shard_fragment(pod_name))
}

/// The name of the sharded index file for an already-computed shard fragment.
pub fn cdn_index_file_name_for_shard(shard: &[String]) -> String {
    format!(
        "{}{}{}",
        CDN_INDEX_PREFIX,
        shard.join("_"),
        CDN_INDEX_SUFFIX
    )
}

/// Parse a sharded index file name back into its shard fragment.
///
/// Returns `None` unless the name is exactly `all_pods_versions_<a>_<b>_<c>.txt`
/// with each fragment the lowercase-hex width `CDN_PREFIX_LENGTHS` calls for, so
/// that only shards this repo actually publishes are addressable.
pub fn parse_cdn_index_file_name(file_name: &str) -> Option<Vec<String>> {
    let rest = file_name
        .strip_prefix(CDN_INDEX_PREFIX)?
        .strip_suffix(CDN_INDEX_SUFFIX)?;

    let fragments: Vec<&str> = rest.split('_').collect();
    if fragments.len() != CDN_PREFIX_LENGTHS.len() {
        return None;
    }
    for (fragment, &length) in fragments.iter().zip(CDN_PREFIX_LENGTHS.iter()) {
        if fragment.len() != length || !fragment.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        if fragment.bytes().any(|b| b.is_ascii_uppercase()) {
            return None;
        }
    }

    Some(fragments.into_iter().map(String::from).collect())
}

/// The sharded CDN directory holding every version of a pod.
///
/// Port of `Pod::Source#pod_path` relative to the repo root.
pub fn cdn_pod_dir(pod_name: &str) -> String {
    format!(
        "Specs/{}/{}",
        cdn_shard_fragment(pod_name).join("/"),
        pod_name
    )
}

/// The sharded CDN path of a single podspec.
pub fn cdn_podspec_path(pod_name: &str, version: &str) -> String {
    format!(
        "{}/{}/{}.podspec.json",
        cdn_pod_dir(pod_name),
        version,
        pod_name
    )
}

/// Handler for CocoaPods package format
pub struct CocoaPodsHandler;

impl CocoaPodsHandler {
    pub fn new() -> Self {
        Self
    }

    /// Parse a CocoaPods path
    ///
    /// Supports paths like:
    /// - `Specs/<a>/<b>/<c>/<name>/<version>/<name>.podspec.json` (podspec, CDN
    ///   MD5-sharded layout, which is what a real client requests)
    /// - `Specs/<name>/<version>/<name>.podspec.json` (podspec, flat layout)
    /// - `pods/<name>-<version>.tar.gz` (pod archive)
    pub fn parse_path(path: &str) -> Result<CocoaPodsPathInfo> {
        let path = path.trim_start_matches('/');

        // Try to match podspec pattern: Specs/<name>/<version>/<name>.podspec.json
        if path.starts_with("Specs/") {
            let parts: Vec<&str> = path.split('/').collect();

            // CDN layout: Specs/<shard...>/<name>/<version>/<name>.podspec.json.
            // The shard must be the one the pod name hashes to; a CDN only ever
            // serves a pod beneath its own shard, so a mismatched fan-out is not
            // an alias for the pod.
            let cdn_len = 1 + CDN_PREFIX_LENGTHS.len() + 3;
            if parts.len() == cdn_len {
                let shard = &parts[1..1 + CDN_PREFIX_LENGTHS.len()];
                let name = parts[cdn_len - 3];
                let version = parts[cdn_len - 2];
                let expected = cdn_shard_fragment(name);
                let shard_ok = expected.len() == shard.len()
                    && expected.iter().zip(shard).all(|(e, a)| e.as_str() == *a);

                if shard_ok
                    && !version.is_empty()
                    && parts[cdn_len - 1].strip_suffix(".podspec.json") == Some(name)
                {
                    return Ok(CocoaPodsPathInfo {
                        name: name.to_string(),
                        version: version.to_string(),
                        artifact_type: CocoaPodsArtifactType::Podspec,
                    });
                }
            }

            if parts.len() >= 4 && parts[0] == "Specs" && parts[3].ends_with(".podspec.json") {
                let name = parts[1].to_string();
                let version = parts[2].to_string();
                let podspec_name = parts[3].strip_suffix(".podspec.json").unwrap_or("");

                // Validate that the podspec name matches the package name
                if podspec_name == name {
                    return Ok(CocoaPodsPathInfo {
                        name,
                        version,
                        artifact_type: CocoaPodsArtifactType::Podspec,
                    });
                }
            }
        }

        // Try to match pod archive pattern: pods/<name>-<version>.tar.gz
        if path.starts_with("pods/") {
            let filename = path.strip_prefix("pods/").unwrap_or("");
            if filename.ends_with(".tar.gz") {
                let basename = filename.strip_suffix(".tar.gz").unwrap_or("");
                if let Some(last_dash_pos) = basename.rfind('-') {
                    let name = basename[..last_dash_pos].to_string();
                    let version = basename[last_dash_pos + 1..].to_string();

                    if !name.is_empty() && !version.is_empty() {
                        return Ok(CocoaPodsPathInfo {
                            name,
                            version,
                            artifact_type: CocoaPodsArtifactType::Pod,
                        });
                    }
                }
            }
        }

        Err(AppError::Validation(
            "Invalid CocoaPods path format".to_string(),
        ))
    }
}

impl Default for CocoaPodsHandler {
    fn default() -> Self {
        Self::new()
    }
}

/// Information extracted from a CocoaPods path
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CocoaPodsPathInfo {
    /// Package name
    pub name: String,
    /// Package version
    pub version: String,
    /// Type of artifact (Podspec or Pod)
    pub artifact_type: CocoaPodsArtifactType,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CocoaPodsArtifactType {
    /// Podspec file (JSON format)
    Podspec,
    /// Pod archive (tar.gz)
    Pod,
}

/// PodSpec metadata structure.
///
/// Only `name` and `version` are required by Artifact Keeper for indexing and
/// path resolution. Every other field in the original podspec JSON is captured
/// by `extra` so the served `*.podspec.json` is a byte-for-byte preservation of
/// what the publisher uploaded. This matters because the CocoaPods client needs
/// fields like `vendored_frameworks`, `xcconfig`, `preserve_paths`,
/// `requires_arc`, `documentation_url`, `screenshots`, `source_files`,
/// `frameworks`, `swift_version`, `resource_bundles`, etc. to install and link
/// the pod correctly. Hard-coding the schema dropped any field not in the
/// struct (see #1286).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PodSpec {
    /// Package name
    pub name: String,
    /// Package version
    pub version: String,
    /// Short description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    /// Homepage URL
    #[serde(skip_serializing_if = "Option::is_none")]
    pub homepage: Option<String>,
    /// License information
    #[serde(skip_serializing_if = "Option::is_none")]
    pub license: Option<serde_json::Value>,
    /// Authors information
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authors: Option<serde_json::Value>,
    /// Source information
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<serde_json::Value>,
    /// Supported platforms
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platforms: Option<HashMap<String, String>>,
    /// Package dependencies
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dependencies: Option<HashMap<String, serde_json::Value>>,
    /// All other podspec fields the CocoaPods client may rely on
    /// (e.g. `vendored_frameworks`, `xcconfig`, `preserve_paths`,
    /// `requires_arc`, `documentation_url`, `screenshots`, `source_files`,
    /// `frameworks`, `swift_version`, `resource_bundles`, `subspecs`, ...).
    /// Captured as a flattened map so the served podspec JSON is a faithful
    /// round-trip of what was uploaded.
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

#[async_trait]
impl FormatHandler for CocoaPodsHandler {
    fn format(&self) -> RepositoryFormat {
        RepositoryFormat::Cocoapods
    }

    fn format_key(&self) -> &str {
        "cocoapods"
    }

    async fn parse_metadata(&self, path: &str, _content: &Bytes) -> Result<serde_json::Value> {
        let info = Self::parse_path(path)?;
        Ok(serde_json::to_value(info).unwrap_or(serde_json::json!({})))
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
    fn test_parse_podspec_path() {
        let path = "Specs/AFNetworking/4.0.0/AFNetworking.podspec.json";
        let info = CocoaPodsHandler::parse_path(path).unwrap();
        assert_eq!(info.name, "AFNetworking");
        assert_eq!(info.version, "4.0.0");
        assert_eq!(info.artifact_type, CocoaPodsArtifactType::Podspec);
    }

    #[test]
    fn test_parse_podspec_path_with_leading_slash() {
        let path = "/Specs/Alamofire/5.6.0/Alamofire.podspec.json";
        let info = CocoaPodsHandler::parse_path(path).unwrap();
        assert_eq!(info.name, "Alamofire");
        assert_eq!(info.version, "5.6.0");
        assert_eq!(info.artifact_type, CocoaPodsArtifactType::Podspec);
    }

    #[test]
    fn test_parse_pod_archive_path() {
        let path = "pods/AFNetworking-4.0.0.tar.gz";
        let info = CocoaPodsHandler::parse_path(path).unwrap();
        assert_eq!(info.name, "AFNetworking");
        assert_eq!(info.version, "4.0.0");
        assert_eq!(info.artifact_type, CocoaPodsArtifactType::Pod);
    }

    #[test]
    fn test_parse_pod_archive_path_with_leading_slash() {
        let path = "/pods/Alamofire-5.6.0.tar.gz";
        let info = CocoaPodsHandler::parse_path(path).unwrap();
        assert_eq!(info.name, "Alamofire");
        assert_eq!(info.version, "5.6.0");
        assert_eq!(info.artifact_type, CocoaPodsArtifactType::Pod);
    }

    #[test]
    fn test_parse_invalid_podspec_name_mismatch() {
        let path = "Specs/AFNetworking/4.0.0/DifferentName.podspec.json";
        let result = CocoaPodsHandler::parse_path(path);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_invalid_format() {
        let path = "invalid/path/format";
        let result = CocoaPodsHandler::parse_path(path);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_pod_with_hyphen_in_name() {
        let path = "pods/my-package-name-1.2.3.tar.gz";
        let info = CocoaPodsHandler::parse_path(path).unwrap();
        assert_eq!(info.name, "my-package-name");
        assert_eq!(info.version, "1.2.3");
        assert_eq!(info.artifact_type, CocoaPodsArtifactType::Pod);
    }

    #[test]
    fn test_podspec_serialization() {
        let podspec = PodSpec {
            name: "AFNetworking".to_string(),
            version: "4.0.0".to_string(),
            summary: Some("Delightful networking library".to_string()),
            homepage: Some("https://github.com/AFNetworking/AFNetworking".to_string()),
            license: None,
            authors: None,
            source: None,
            platforms: None,
            dependencies: None,
            extra: HashMap::new(),
        };

        let json = serde_json::to_string(&podspec).unwrap();
        assert!(json.contains("AFNetworking"));
        assert!(json.contains("4.0.0"));
    }

    /// Regression test for #1286: the served podspec JSON must preserve every
    /// field the publisher uploaded, not only the ones the struct names. The
    /// CocoaPods client needs fields like `vendored_frameworks`, `xcconfig`,
    /// `preserve_paths`, `requires_arc`, `documentation_url`, and
    /// `screenshots` to successfully link binary frameworks.
    #[test]
    fn test_podspec_preserves_unknown_fields_round_trip() {
        let original = serde_json::json!({
            "name": "MyLibrary",
            "version": "2.8.45",
            "summary": "MyCompany MyLibrary",
            "description": "Library of my company",
            "homepage": "https://github.com/",
            "documentation_url": "https://github.com/",
            "screenshots": "https://github.com/",
            "license": { "type": "Apache 2.0", "file": "LICENSE" },
            "authors": { "My Company": "devteam@my.company" },
            "platforms": { "osx": "10.13", "ios": "11.2" },
            "source": { "http": "https://ak.int.local/cocoapods/repo/pods/MyLibrary-2.8.45.tar.gz" },
            "preserve_paths": ["MyLibrary.xcframework"],
            "vendored_frameworks": "MyLibrary.xcframework",
            "xcconfig": { "LD_RUNPATH_SEARCH_PATHS": "@loader_path/../Frameworks" },
            "requires_arc": true,
        });

        let podspec: PodSpec = serde_json::from_value(original.clone()).unwrap();
        assert_eq!(podspec.name, "MyLibrary");
        assert_eq!(podspec.version, "2.8.45");

        let round_tripped = serde_json::to_value(&podspec).unwrap();

        // Every field present in the uploaded podspec must survive the
        // round-trip into the JSON served at the Specs/<n>/<v>/<n>.podspec.json
        // endpoint. We assert each of the previously-dropped fields explicitly.
        for field in [
            "documentation_url",
            "screenshots",
            "preserve_paths",
            "vendored_frameworks",
            "xcconfig",
            "requires_arc",
            "description",
        ] {
            assert_eq!(
                round_tripped.get(field),
                original.get(field),
                "podspec field {} was lost during round-trip (regression for #1286)",
                field,
            );
        }

        // And the already-supported named fields stay intact too.
        for field in [
            "name",
            "version",
            "summary",
            "homepage",
            "license",
            "authors",
            "platforms",
            "source",
        ] {
            assert_eq!(round_tripped.get(field), original.get(field));
        }
    }

    // -----------------------------------------------------------------------
    // CDN layout: sharding rule
    // -----------------------------------------------------------------------

    /// Golden vectors for the MD5-prefix shard rule.
    ///
    /// These are not hand-computed: each `(pod, shard)` pair was read back from
    /// the live CocoaPods trunk CDN, which is the normative implementation of
    /// `Source::Metadata#path_fragment` with `prefix_lengths: [1, 1, 1]`. Each
    /// pod is listed in `https://cdn.cocoapods.org/all_pods_versions_<shard>.txt`
    /// with the shard joined by `_`, and its podspecs are served under
    /// `https://cdn.cocoapods.org/Specs/<shard joined by />/<pod>/...`.
    const CDN_SHARD_GOLDEN: &[(&str, [&str; 3])] = &[
        ("Alamofire", ["d", "a", "2"]),
        ("SnapKit", ["1", "f", "6"]),
        ("Moya", ["8", "a", "7"]),
        ("AFNetworking", ["a", "7", "5"]),
        ("RxSwift", ["2", "e", "c"]),
    ];

    #[test]
    fn test_cdn_shard_fragment_matches_trunk_cdn() {
        for (pod, expected) in CDN_SHARD_GOLDEN {
            assert_eq!(
                cdn_shard_fragment(pod),
                expected.to_vec(),
                "shard fan-out for {} must match the trunk CDN",
                pod,
            );
        }
    }

    #[test]
    fn test_cdn_shard_fragment_is_md5_prefix() {
        // The rule is literally the first CDN_PREFIX_LENGTHS.sum() hex chars of
        // the MD5 of the pod name, split per prefix length.
        let shard = cdn_shard_fragment("Alamofire");
        assert_eq!(shard.concat(), "da2");
        assert!("da208d9cbd49253cc75271c6c269ebce".starts_with(&shard.concat()));
    }

    #[test]
    fn test_cdn_shard_fragment_widths_follow_prefix_lengths() {
        let shard = cdn_shard_fragment("SomeArbitraryPodName");
        assert_eq!(shard.len(), CDN_PREFIX_LENGTHS.len());
        for (fragment, &length) in shard.iter().zip(CDN_PREFIX_LENGTHS.iter()) {
            assert_eq!(fragment.len(), length);
            assert!(fragment.bytes().all(|b| b.is_ascii_hexdigit()));
        }
    }

    #[test]
    fn test_cdn_shard_fragment_is_case_sensitive() {
        // MD5 is over the pod name verbatim, so a differently-cased name is a
        // different pod and lands in a different shard.
        assert_ne!(
            cdn_shard_fragment("Alamofire"),
            cdn_shard_fragment("alamofire")
        );
    }

    // -----------------------------------------------------------------------
    // CDN layout: index file names
    // -----------------------------------------------------------------------

    #[test]
    fn test_cdn_index_file_name_matches_trunk_cdn() {
        for (pod, shard) in CDN_SHARD_GOLDEN {
            assert_eq!(
                cdn_index_file_name(pod),
                format!("all_pods_versions_{}.txt", shard.join("_")),
            );
        }
        // Spelled out for the canonical example.
        assert_eq!(
            cdn_index_file_name("Alamofire"),
            "all_pods_versions_d_a_2.txt"
        );
    }

    #[test]
    fn test_parse_cdn_index_file_name_round_trips() {
        for (pod, shard) in CDN_SHARD_GOLDEN {
            let file_name = cdn_index_file_name(pod);
            assert_eq!(
                parse_cdn_index_file_name(&file_name).as_deref(),
                Some(shard.map(String::from).as_slice()),
                "{} index file name must parse back to its shard",
                pod,
            );
        }
    }

    #[test]
    fn test_parse_cdn_index_file_name_rejects_non_index_files() {
        for name in [
            "all_specs",
            "CocoaPods-version.yml",
            "all_pods_versions_d_a_2.json",
            "all_pods_versions.txt",
            "all_pods_versions_d_a.txt",
            "all_pods_versions_d_a_2_9.txt",
            "all_pods_versions_dd_a_2.txt",
            "all_pods_versions_z_a_2.txt",
            "all_pods_versions_D_a_2.txt",
            "all_pods_versions___.txt",
            "",
        ] {
            assert!(
                parse_cdn_index_file_name(name).is_none(),
                "{} must not be treated as a shard index file",
                name,
            );
        }
    }

    // -----------------------------------------------------------------------
    // CDN layout: Specs tree paths
    // -----------------------------------------------------------------------

    #[test]
    fn test_cdn_podspec_path_matches_trunk_cdn() {
        // The exact path the client GETs; verified against
        // https://cdn.cocoapods.org/Specs/d/a/2/Alamofire/5.8.0/Alamofire.podspec.json
        assert_eq!(
            cdn_podspec_path("Alamofire", "5.8.0"),
            "Specs/d/a/2/Alamofire/5.8.0/Alamofire.podspec.json",
        );
        assert_eq!(cdn_pod_dir("Alamofire"), "Specs/d/a/2/Alamofire");
    }

    #[test]
    fn test_parse_path_cdn_sharded_podspec() {
        let info = CocoaPodsHandler::parse_path(&cdn_podspec_path("Alamofire", "5.8.0")).unwrap();
        assert_eq!(info.name, "Alamofire");
        assert_eq!(info.version, "5.8.0");
        assert_eq!(info.artifact_type, CocoaPodsArtifactType::Podspec);
    }

    #[test]
    fn test_parse_path_cdn_sharded_podspec_with_leading_slash() {
        let path = format!("/{}", cdn_podspec_path("SnapKit", "5.7.1"));
        let info = CocoaPodsHandler::parse_path(&path).unwrap();
        assert_eq!(info.name, "SnapKit");
        assert_eq!(info.version, "5.7.1");
    }

    #[test]
    fn test_parse_path_cdn_rejects_wrong_shard() {
        // Alamofire hashes to d/a/2; it is not addressable under any other
        // fan-out, exactly as on a real CDN.
        let path = "Specs/0/0/0/Alamofire/5.8.0/Alamofire.podspec.json";
        assert!(CocoaPodsHandler::parse_path(path).is_err());
    }

    #[test]
    fn test_parse_path_cdn_rejects_mismatched_podspec_name() {
        let path = "Specs/d/a/2/Alamofire/5.8.0/Moya.podspec.json";
        assert!(CocoaPodsHandler::parse_path(path).is_err());
    }

    #[test]
    fn test_parse_path_flat_layout_still_supported() {
        // The pre-existing flat layout keeps working alongside the CDN tree.
        let info =
            CocoaPodsHandler::parse_path("Specs/Alamofire/5.8.0/Alamofire.podspec.json").unwrap();
        assert_eq!(info.name, "Alamofire");
        assert_eq!(info.version, "5.8.0");
    }

    // -----------------------------------------------------------------------
    // CDN layout: CocoaPods-version.yml
    // -----------------------------------------------------------------------

    #[test]
    fn test_cdn_metadata_default() {
        let meta = CdnMetadata::default();
        assert_eq!(meta.min, "1.0.0");
        assert_eq!(meta.prefix_lengths, vec![1, 1, 1]);
    }

    #[test]
    fn test_cdn_metadata_yaml_shape_matches_trunk() {
        // The client parses this with YAML and reads `min` + `prefix_lengths`
        // (Source::Metadata#initialize). Keep the emitted document in the shape
        // the trunk CDN publishes.
        let yaml = serde_yaml::to_string(&CdnMetadata::default()).unwrap();
        let parsed: serde_yaml::Value = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(parsed["min"].as_str(), Some("1.0.0"));
        let lengths: Vec<usize> = parsed["prefix_lengths"]
            .as_sequence()
            .unwrap()
            .iter()
            .map(|v| v.as_u64().unwrap() as usize)
            .collect();
        assert_eq!(lengths, CDN_PREFIX_LENGTHS.to_vec());
    }

    #[test]
    fn test_cdn_prefix_lengths_are_consistent_with_md5_width() {
        // Guard against a prefix_lengths change that would over-run the digest.
        let total: usize = CDN_PREFIX_LENGTHS.iter().sum();
        assert!(
            total <= 32,
            "MD5 hex is 32 chars; cannot slice {} of it",
            total
        );
    }
}
