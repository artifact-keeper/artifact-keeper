use async_trait::async_trait;
use bytes::Bytes;
use quick_xml::events::{BytesStart, Event};
use quick_xml::{Reader, XmlVersion};
use serde::{Deserialize, Serialize};

use crate::error::{AppError, Result};
use crate::formats::FormatHandler;
use crate::models::repository::RepositoryFormat;
use crate::util::bounded_archive;

/// Information extracted from VS Code extension paths
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VscodePathInfo {
    /// Extension publisher name (optional)
    pub publisher: Option<String>,
    /// Extension name (optional)
    pub name: Option<String>,
    /// Extension version (optional)
    pub version: Option<String>,
    /// Whether this is a marketplace API query
    pub is_query: bool,
    /// Whether this is a download request
    pub is_download: bool,
}

/// Handler for VS Code extensions format
pub struct VscodeHandler;

impl VscodeHandler {
    pub fn new() -> Self {
        Self
    }

    /// Parse a VS Code extension path
    ///
    /// Supports paths like:
    /// - `/extensions/publisher/name/version` - extension info
    /// - `/extensions/publisher/name/version/download` - VSIX download
    /// - `/extensionquery` - marketplace API query
    pub fn parse_path(path: &str) -> Result<VscodePathInfo> {
        let path = path.trim_start_matches('/');

        // Check for extensionquery API endpoint
        if path == "extensionquery" {
            return Ok(VscodePathInfo {
                is_query: true,
                ..Default::default()
            });
        }

        // Parse extensions paths: extensions/publisher/name/version[/download]
        if path.starts_with("extensions/") {
            let parts: Vec<&str> = path.split('/').collect();

            let is_download = parts.len() > 4 && parts[4] == "download";
            let expected_len = if is_download { 5 } else { 4 };

            if parts.len() < expected_len {
                return Err(AppError::Validation(format!(
                    "Invalid VS Code extension path: {}",
                    path
                )));
            }

            return Ok(VscodePathInfo {
                publisher: Some(parts[1].to_string()),
                name: Some(parts[2].to_string()),
                version: Some(parts[3].to_string()),
                is_download,
                ..Default::default()
            });
        }

        Err(AppError::Validation(format!(
            "Invalid VS Code extension path: {}",
            path
        )))
    }
}

impl Default for VscodeHandler {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// VSIX manifest reader (#3961)
// ---------------------------------------------------------------------------

const VSIX_EXTENSION_MANIFEST: &str = "extension/package.json";
const VSIX_PACKAGE_MANIFEST: &str = "extension.vsixmanifest";
const VSIX_PRERELEASE_PROPERTY: &str = "Microsoft.VisualStudio.Code.PreRelease";

/// Manifest text is persisted and re-serialized into every gallery result, so
/// it is bounded. Identity is rejected rather than truncated below.
const MAX_VSIX_TEXT_CHARS: usize = 2048;
const MAX_VSIX_LIST_ENTRIES: usize = 64;

/// Gallery-relevant metadata read out of a `.vsix`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VsixMetadata {
    pub publisher: String,
    pub name: String,
    pub version: String,
    pub display_name: Option<String>,
    pub description: Option<String>,
    /// `engines.vscode`. `None` only on the header-only publish path.
    pub engine: Option<String>,
    /// `Identity/@TargetPlatform`; `None` means platform-independent.
    pub target_platform: Option<String>,
    pub icon: Option<String>,
    pub categories: Vec<String>,
    pub extension_dependencies: Vec<String>,
    pub extension_pack: Vec<String>,
    pub prerelease: bool,
}

#[derive(Debug, Deserialize)]
struct ExtensionPackageJson {
    publisher: Option<String>,
    name: Option<String>,
    version: Option<String>,
    #[serde(rename = "displayName")]
    display_name: Option<String>,
    description: Option<String>,
    engines: Option<ExtensionEngines>,
    icon: Option<String>,
    categories: Option<Vec<String>>,
    #[serde(rename = "extensionDependencies")]
    extension_dependencies: Option<Vec<String>>,
    #[serde(rename = "extensionPack")]
    extension_pack: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct ExtensionEngines {
    vscode: Option<String>,
}

/// The two per-version facts only `extension.vsixmanifest` carries.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VsixPackageManifest {
    pub target_platform: Option<String>,
    pub prerelease: bool,
}

/// The rule `is_safe_gallery_segment` applies to a coordinate in a request:
/// these become artifact paths, storage keys and URL segments.
fn is_safe_vsix_coordinate(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && value != "."
        && value != ".."
        && !value.contains(['/', '\\', '?', '#'])
        && !value.chars().any(char::is_control)
}

fn invalid_vsix(what: &str) -> AppError {
    AppError::Validation(format!("Invalid VSIX archive: {}", what))
}

fn vsix_text(value: Option<String>) -> Option<String> {
    let trimmed = value?.trim().to_string();
    if trimmed.is_empty() {
        return None;
    }
    Some(trimmed.chars().take(MAX_VSIX_TEXT_CHARS).collect())
}

fn vsix_list(value: Option<Vec<String>>) -> Vec<String> {
    value
        .unwrap_or_default()
        .into_iter()
        .filter_map(|entry| vsix_text(Some(entry)))
        .take(MAX_VSIX_LIST_ENTRIES)
        .collect()
}

/// Parse `extension/package.json`.
pub fn parse_extension_manifest(bytes: &[u8]) -> Result<VsixMetadata> {
    let manifest: ExtensionPackageJson = serde_json::from_slice(bytes).map_err(|e| {
        invalid_vsix(&format!(
            "{} is not valid JSON ({})",
            VSIX_EXTENSION_MANIFEST, e
        ))
    })?;

    let coordinate = |value: Option<String>, field: &str| -> Result<String> {
        let value = vsix_text(value).ok_or_else(|| {
            invalid_vsix(&format!("{} has no \"{}\"", VSIX_EXTENSION_MANIFEST, field))
        })?;
        if !is_safe_vsix_coordinate(&value) {
            return Err(invalid_vsix(&format!(
                "\"{}\" is not usable as a path or URL segment",
                field
            )));
        }
        Ok(value)
    };
    let publisher = coordinate(manifest.publisher, "publisher")?;
    let name = coordinate(manifest.name, "name")?;
    let version = coordinate(manifest.version, "version")?;

    // Mandatory in the packaging format, and what a client reads to decide
    // whether it can run the extension.
    let engine = vsix_text(manifest.engines.and_then(|e| e.vscode)).ok_or_else(|| {
        invalid_vsix(&format!(
            "{} has no \"engines.vscode\" version range",
            VSIX_EXTENSION_MANIFEST
        ))
    })?;

    Ok(VsixMetadata {
        publisher,
        name,
        version,
        display_name: vsix_text(manifest.display_name),
        description: vsix_text(manifest.description),
        engine: Some(engine),
        target_platform: None,
        icon: vsix_text(manifest.icon),
        categories: vsix_list(manifest.categories),
        extension_dependencies: vsix_list(manifest.extension_dependencies),
        extension_pack: vsix_list(manifest.extension_pack),
        prerelease: false,
    })
}

/// Identity for a publish whose archive could not be read. The route accepted
/// opaque bytes plus `x-*` headers before #3961, so those uploads keep working
/// — with no gallery-visible metadata, because there is none to read.
pub fn legacy_vsix_metadata(publisher: &str, name: &str, version: &str) -> Result<VsixMetadata> {
    for (field, value) in [
        ("x-publisher", publisher),
        ("x-extension-name", name),
        ("x-extension-version", version),
    ] {
        if !is_safe_vsix_coordinate(value) {
            return Err(AppError::Validation(format!(
                "{} is not usable as a path or URL segment",
                field
            )));
        }
    }
    Ok(VsixMetadata {
        publisher: publisher.to_string(),
        name: name.to_string(),
        version: version.to_string(),
        ..VsixMetadata::default()
    })
}

/// `normalized_value` resolves only the five predefined XML entities, and an
/// unresolvable reference yields `None`, as in `curation_sync`.
fn vsix_attr(element: &BytesStart<'_>, key: &[u8]) -> Option<String> {
    for attr in element.attributes().flatten() {
        if attr.key.as_ref() == key {
            return attr
                .normalized_value(XmlVersion::Explicit1_0)
                .ok()
                .map(|value| value.into_owned());
        }
    }
    None
}

/// Read `Identity/@TargetPlatform` and the pre-release property. An unreadable
/// document is an error: defaulting it would strip a build's platform.
pub fn parse_vsix_package_manifest(xml: &str) -> Result<VsixPackageManifest> {
    let mut reader = Reader::from_str(xml);
    let mut out = VsixPackageManifest::default();
    let mut saw_identity = false;
    loop {
        match reader.read_event() {
            Err(e) => {
                return Err(invalid_vsix(&format!(
                    "{} is not well-formed XML ({})",
                    VSIX_PACKAGE_MANIFEST, e
                )))
            }
            Ok(Event::Eof) => break,
            Ok(Event::Start(element)) | Ok(Event::Empty(element)) => {
                match element.local_name().as_ref() {
                    b"Identity" => {
                        saw_identity = true;
                        // The gallery compares platforms casefolded.
                        out.target_platform = vsix_text(vsix_attr(&element, b"TargetPlatform"))
                            .map(|platform| platform.to_ascii_lowercase());
                    }
                    b"Property"
                        if vsix_attr(&element, b"Id").as_deref()
                            == Some(VSIX_PRERELEASE_PROPERTY) =>
                    {
                        out.prerelease = vsix_attr(&element, b"Value")
                            .is_some_and(|value| value.trim().eq_ignore_ascii_case("true"));
                    }
                    _ => {}
                }
            }
            Ok(_) => {}
        }
    }
    if !saw_identity {
        return Err(invalid_vsix(&format!(
            "{} has no <Identity> element",
            VSIX_PACKAGE_MANIFEST
        )));
    }
    Ok(out)
}

/// Read both manifests out of an uploaded `.vsix`. Callers hold an
/// ingest-extraction permit ([`bounded_archive::with_ingest_extraction`]).
pub fn extract_vsix_metadata(content: &[u8]) -> Result<VsixMetadata> {
    let extension_manifest =
        bounded_archive::read_metadata_from_zip(std::io::Cursor::new(content), |name| {
            name == VSIX_EXTENSION_MANIFEST
        })?
        .ok_or_else(|| invalid_vsix(&format!("no {}", VSIX_EXTENSION_MANIFEST)))?;
    let mut metadata = parse_extension_manifest(&extension_manifest)?;

    let package_manifest =
        bounded_archive::read_metadata_from_zip(std::io::Cursor::new(content), |name| {
            name == VSIX_PACKAGE_MANIFEST
        })?
        .ok_or_else(|| invalid_vsix(&format!("no {}", VSIX_PACKAGE_MANIFEST)))?;
    let package_manifest = String::from_utf8(package_manifest)
        .map_err(|_| invalid_vsix(&format!("{} is not UTF-8", VSIX_PACKAGE_MANIFEST)))?;
    let package_manifest = parse_vsix_package_manifest(&package_manifest)?;

    metadata.target_platform = package_manifest.target_platform;
    metadata.prerelease = package_manifest.prerelease;
    Ok(metadata)
}

/// Whether `content` is a zip carrying `extension/package.json`, i.e. a VSIX,
/// however broken its manifest. Only a body that is *not* one may fall back to
/// the legacy header identity: a readable manifest that fails validation is a
/// 400, or breaking it would skip the header-vs-archive check (#3961).
pub fn has_extension_manifest(content: &[u8]) -> bool {
    zip::ZipArchive::new(std::io::Cursor::new(content))
        .is_ok_and(|archive| archive.index_for_name(VSIX_EXTENSION_MANIFEST).is_some())
}

#[async_trait]
impl FormatHandler for VscodeHandler {
    fn format(&self) -> RepositoryFormat {
        RepositoryFormat::Vscode
    }

    fn format_key(&self) -> &str {
        "vscode"
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

#[cfg(ak_test_shard = "services-2")]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_extension_info() {
        let path = "/extensions/ms-vscode/cpptools/1.14.0";
        let info = VscodeHandler::parse_path(path).expect("Failed to parse path");

        assert_eq!(info.publisher, Some("ms-vscode".to_string()));
        assert_eq!(info.name, Some("cpptools".to_string()));
        assert_eq!(info.version, Some("1.14.0".to_string()));
        assert!(!info.is_download);
        assert!(!info.is_query);
    }

    #[test]
    fn test_parse_extension_download() {
        let path = "/extensions/ms-vscode/cpptools/1.14.0/download";
        let info = VscodeHandler::parse_path(path).expect("Failed to parse path");

        assert_eq!(info.publisher, Some("ms-vscode".to_string()));
        assert_eq!(info.name, Some("cpptools".to_string()));
        assert_eq!(info.version, Some("1.14.0".to_string()));
        assert!(info.is_download);
        assert!(!info.is_query);
    }

    #[test]
    fn test_parse_extension_query() {
        let path = "/extensionquery";
        let info = VscodeHandler::parse_path(path).expect("Failed to parse path");

        assert!(info.is_query);
        assert!(!info.is_download);
        assert_eq!(info.publisher, None);
        assert_eq!(info.name, None);
        assert_eq!(info.version, None);
    }

    #[test]
    fn test_parse_extension_invalid_path() {
        let path = "/extensions/invalid";
        let result = VscodeHandler::parse_path(path);

        assert!(result.is_err());
    }

    #[test]
    fn test_parse_extension_invalid_root() {
        let path = "/invalid/ms-vscode/cpptools/1.14.0";
        let result = VscodeHandler::parse_path(path);

        assert!(result.is_err());
    }

    #[test]
    fn test_format_key() {
        let handler = VscodeHandler::new();
        assert_eq!(handler.format_key(), "vscode");
    }

    #[test]
    fn test_format() {
        let handler = VscodeHandler::new();
        assert_eq!(handler.format(), RepositoryFormat::Vscode);
    }

    // -----------------------------------------------------------------------
    // VSIX manifest reader (#3961)
    // -----------------------------------------------------------------------

    const PACKAGE_JSON: &str = r#"{
        "publisher": "acme",
        "name": "demo",
        "version": "1.0.0",
        "displayName": "Acme Demo",
        "description": "  Demonstrates things.  ",
        "engines": { "vscode": "^1.75.0" },
        "icon": "images/icon.png",
        "categories": ["Programming Languages", "Linters"],
        "extensionDependencies": ["acme.core"],
        "extensionPack": ["acme.extra"],
        "contributes": { "commands": [] }
    }"#;

    fn vsixmanifest(identity_attrs: &str, properties: &str) -> String {
        format!(
            r#"<?xml version="1.0" encoding="utf-8"?>
            <PackageManifest Version="2.0.0" xmlns="http://schemas.microsoft.com/developer/vsx-schema/2011">
              <Metadata>
                <Identity Language="en-US" Id="demo" Version="1.0.0" Publisher="acme" {identity_attrs}/>
                <DisplayName>Acme Demo</DisplayName>
                <Properties>{properties}</Properties>
              </Metadata>
            </PackageManifest>"#
        )
    }

    fn vsix_bytes(entries: &[(&str, &[u8])]) -> Vec<u8> {
        use std::io::Write;
        let mut cursor = std::io::Cursor::new(Vec::new());
        {
            let mut writer = zip::ZipWriter::new(&mut cursor);
            let options: zip::write::FileOptions<'_, ()> = zip::write::FileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);
            for (name, data) in entries {
                writer.start_file(*name, options).unwrap();
                writer.write_all(data).unwrap();
            }
            writer.finish().unwrap();
        }
        cursor.into_inner()
    }

    /// A `vsce package` output yields every field a gallery response needs.
    #[test]
    fn extension_manifest_yields_gallery_fields() {
        let parsed = parse_extension_manifest(PACKAGE_JSON.as_bytes()).expect("well-formed");
        assert_eq!(parsed.publisher, "acme");
        assert_eq!(parsed.name, "demo");
        assert_eq!(parsed.version, "1.0.0");
        assert_eq!(parsed.display_name.as_deref(), Some("Acme Demo"));
        assert_eq!(parsed.description.as_deref(), Some("Demonstrates things."));
        assert_eq!(parsed.engine.as_deref(), Some("^1.75.0"));
        assert_eq!(parsed.icon.as_deref(), Some("images/icon.png"));
        assert_eq!(parsed.categories, vec!["Programming Languages", "Linters"]);
        assert_eq!(parsed.extension_dependencies, vec!["acme.core"]);
        assert_eq!(parsed.extension_pack, vec!["acme.extra"]);
        // Neither is readable from `package.json`.
        assert_eq!(parsed.target_platform, None);
        assert!(!parsed.prerelease);
    }

    /// The four fields a gallery response cannot be built without are required,
    /// and an identity that cannot become a path segment is refused rather than
    /// interpolated into a storage key.
    #[test]
    fn extension_manifest_requires_identity_and_engine() {
        for missing in ["publisher", "name", "version", "engines"] {
            let mut value: serde_json::Value = serde_json::from_str(PACKAGE_JSON).unwrap();
            value.as_object_mut().unwrap().remove(missing);
            let err = parse_extension_manifest(value.to_string().as_bytes())
                .expect_err("a manifest missing {missing} must not publish");
            assert!(
                matches!(err, AppError::Validation(_)),
                "missing {missing} must be a client error, not a server error"
            );
        }
        for hostile in ["../../etc", "a/b", "..", "", "   ", "we\u{0000}ird"] {
            let mut value: serde_json::Value = serde_json::from_str(PACKAGE_JSON).unwrap();
            value["publisher"] = serde_json::json!(hostile);
            assert!(
                parse_extension_manifest(value.to_string().as_bytes()).is_err(),
                "publisher {hostile:?} must not become a path segment"
            );
        }
    }

    /// Free text is truncated; an over-long identity is refused.
    #[test]
    fn extension_manifest_bounds_free_text_and_identity() {
        let mut value: serde_json::Value = serde_json::from_str(PACKAGE_JSON).unwrap();
        value["description"] = serde_json::json!("x".repeat(MAX_VSIX_TEXT_CHARS * 3));
        value["categories"] = serde_json::json!((0..MAX_VSIX_LIST_ENTRIES * 2)
            .map(|i| i.to_string())
            .collect::<Vec<_>>());
        let parsed = parse_extension_manifest(value.to_string().as_bytes()).expect("well-formed");
        assert_eq!(
            parsed.description.map(|d| d.chars().count()),
            Some(MAX_VSIX_TEXT_CHARS)
        );
        assert_eq!(parsed.categories.len(), MAX_VSIX_LIST_ENTRIES);

        value["publisher"] = serde_json::json!("p".repeat(256));
        assert!(parse_extension_manifest(value.to_string().as_bytes()).is_err());
    }

    /// A wrong-typed field, or garbage, is a validation error — never a panic.
    #[test]
    fn extension_manifest_rejects_wrong_types_and_garbage() {
        let mut value: serde_json::Value = serde_json::from_str(PACKAGE_JSON).unwrap();
        value["categories"] = serde_json::json!("Linters");
        assert!(matches!(
            parse_extension_manifest(value.to_string().as_bytes()),
            Err(AppError::Validation(_))
        ));
        assert!(matches!(
            parse_extension_manifest(b"not json at all"),
            Err(AppError::Validation(_))
        ));
        assert!(matches!(
            parse_extension_manifest(b""),
            Err(AppError::Validation(_))
        ));
    }

    /// The platform is casefolded because the gallery compares it casefolded.
    #[test]
    fn package_manifest_reads_platform_and_prerelease() {
        let parsed = parse_vsix_package_manifest(&vsixmanifest(
            r#"TargetPlatform="Linux-X64" "#,
            r#"<Property Id="Microsoft.VisualStudio.Code.PreRelease" Value="true"/>"#,
        ))
        .expect("well-formed");
        assert_eq!(parsed.target_platform.as_deref(), Some("linux-x64"));
        assert!(parsed.prerelease);

        // A platform-independent, stable build says neither.
        let plain = parse_vsix_package_manifest(&vsixmanifest("", "")).expect("well-formed");
        assert_eq!(plain.target_platform, None);
        assert!(!plain.prerelease);

        // An unrelated property must not be mistaken for the pre-release one,
        // and `Value="false"` is not pre-release.
        let other = parse_vsix_package_manifest(&vsixmanifest(
            "",
            r#"<Property Id="Microsoft.VisualStudio.Code.Engine" Value="true"/>
               <Property Id="Microsoft.VisualStudio.Code.PreRelease" Value="false"/>"#,
        ))
        .expect("well-formed");
        assert!(!other.prerelease);
    }

    /// An unreadable package manifest fails rather than defaulting to
    /// "universal, not pre-release", which would strip a build's platform.
    #[test]
    fn package_manifest_fails_closed_on_unreadable_xml() {
        assert!(parse_vsix_package_manifest("<PackageManifest><Metadata>").is_err());
        assert!(parse_vsix_package_manifest("not xml at all").is_err());
        assert!(
            parse_vsix_package_manifest("<PackageManifest><Metadata/></PackageManifest>").is_err(),
            "no <Identity> means no identity to trust"
        );
    }

    /// The end-to-end archive read: both manifests, merged.
    #[test]
    fn vsix_archive_merges_both_manifests() {
        let archive = vsix_bytes(&[
            ("extension/package.json", PACKAGE_JSON.as_bytes()),
            (
                "extension.vsixmanifest",
                vsixmanifest(r#"TargetPlatform="darwin-arm64" "#, "").as_bytes(),
            ),
            ("extension/README.md", b"# Demo"),
            ("[Content_Types].xml", b"<Types/>"),
        ]);
        let parsed = extract_vsix_metadata(&archive).expect("a vsce package archive");
        assert_eq!(parsed.publisher, "acme");
        assert_eq!(parsed.engine.as_deref(), Some("^1.75.0"));
        assert_eq!(parsed.target_platform.as_deref(), Some("darwin-arm64"));
    }

    /// A corrupt archive, and an archive missing either manifest, are client
    /// errors — never a panic and never a 500.
    #[test]
    fn vsix_archive_rejects_corrupt_and_incomplete_input() {
        for (case, content) in [
            ("not a zip", b"vsix-bytes".to_vec()),
            ("empty", Vec::new()),
            (
                "no extension/package.json",
                vsix_bytes(&[("extension.vsixmanifest", vsixmanifest("", "").as_bytes())]),
            ),
            (
                "no extension.vsixmanifest",
                vsix_bytes(&[("extension/package.json", PACKAGE_JSON.as_bytes())]),
            ),
            (
                "package manifest is not UTF-8",
                vsix_bytes(&[
                    ("extension/package.json", PACKAGE_JSON.as_bytes()),
                    ("extension.vsixmanifest", &[0xff, 0xfe, 0x00]),
                ]),
            ),
        ] {
            assert!(
                matches!(
                    extract_vsix_metadata(&content),
                    Err(AppError::Validation(_))
                ),
                "{case} must be a validation error"
            );
        }
    }

    /// Only a body that is not a VSIX at all may fall back to the legacy
    /// header identity; a VSIX with a broken manifest is still a VSIX.
    #[test]
    fn has_extension_manifest_separates_non_vsix_from_broken_vsix() {
        assert!(!has_extension_manifest(b"vsix-bytes"));
        assert!(!has_extension_manifest(&[]));
        assert!(!has_extension_manifest(&vsix_bytes(&[(
            "extension.vsixmanifest",
            vsixmanifest("", "").as_bytes()
        )])));
        let no_engine = vsix_bytes(&[(
            "extension/package.json",
            br#"{"publisher":"acme","name":"demo","version":"1.0.0"}"#,
        )]);
        assert!(extract_vsix_metadata(&no_engine).is_err());
        assert!(has_extension_manifest(&no_engine));
        assert!(has_extension_manifest(&vsix_bytes(&[(
            "extension/package.json",
            b"not json"
        )])));
    }

    /// The legacy path publishes coordinates and nothing else, and validates
    /// them — they become an artifact path and a storage key.
    #[test]
    fn legacy_identity_is_validated_and_carries_no_metadata() {
        let parsed = legacy_vsix_metadata("acme", "demo", "1.0.0").expect("safe coordinates");
        assert_eq!(parsed.publisher, "acme");
        assert_eq!(parsed.engine, None);
        assert_eq!(parsed.target_platform, None);
        assert!(parsed.categories.is_empty());

        for (publisher, name, version) in [
            ("../../etc", "demo", "1.0.0"),
            ("acme", "de/mo", "1.0.0"),
            ("acme", "demo", ".."),
            ("", "demo", "1.0.0"),
        ] {
            assert!(
                legacy_vsix_metadata(publisher, name, version).is_err(),
                "{publisher}/{name}/{version} must not become a storage key"
            );
        }
    }
}
