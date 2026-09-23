//! Go module proxy format handler.
//!
//! Implements GOPROXY protocol for Go modules.
//! Supports @v/list, @v/version.info, @v/version.mod, @v/version.zip endpoints.

use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::io::Read;

use crate::error::{AppError, Result};
use crate::formats::FormatHandler;
use crate::models::repository::RepositoryFormat;

/// Go module proxy format handler
pub struct GoHandler;

impl GoHandler {
    pub fn new() -> Self {
        Self
    }

    /// Parse Go module proxy path
    /// Formats:
    ///   <module>/@v/list              - List available versions
    ///   <module>/@v/<version>.info    - Version metadata (JSON)
    ///   <module>/@v/<version>.mod     - go.mod file
    ///   <module>/@v/<version>.zip     - Module archive
    ///   <module>/@latest              - Latest version info
    pub fn parse_path(path: &str) -> Result<GoModuleInfo> {
        let path = path.trim_start_matches('/');

        // Handle encoded module paths (capital letters encoded as !lowercase)
        let decoded_path = Self::decode_module_path(path);

        // Find the @v or @latest marker
        if let Some(at_pos) = decoded_path.rfind("/@v/") {
            let module = &decoded_path[..at_pos];
            let rest = &decoded_path[at_pos + 4..];

            if rest == "list" {
                return Ok(GoModuleInfo {
                    module: module.to_string(),
                    version: None,
                    operation: GoOperation::List,
                });
            }

            if let Some(version) = rest.strip_suffix(".info") {
                return Ok(GoModuleInfo {
                    module: module.to_string(),
                    version: Some(version.to_string()),
                    operation: GoOperation::Info,
                });
            }

            if let Some(version) = rest.strip_suffix(".mod") {
                return Ok(GoModuleInfo {
                    module: module.to_string(),
                    version: Some(version.to_string()),
                    operation: GoOperation::Mod,
                });
            }

            if let Some(version) = rest.strip_suffix(".zip") {
                return Ok(GoModuleInfo {
                    module: module.to_string(),
                    version: Some(version.to_string()),
                    operation: GoOperation::Zip,
                });
            }
        }

        // Check for @latest
        if decoded_path.ends_with("/@latest") {
            let module = decoded_path.trim_end_matches("/@latest");
            return Ok(GoModuleInfo {
                module: module.to_string(),
                version: None,
                operation: GoOperation::Latest,
            });
        }

        // Direct zip file path
        if decoded_path.ends_with(".zip") {
            if let Some((module, version)) = Self::parse_zip_path(&decoded_path) {
                return Ok(GoModuleInfo {
                    module,
                    version: Some(version),
                    operation: GoOperation::Zip,
                });
            }
        }

        Err(AppError::Validation(format!(
            "Invalid Go module proxy path: {}",
            path
        )))
    }

    /// Parse a direct zip file path
    fn parse_zip_path(path: &str) -> Option<(String, String)> {
        // Format: module@version.zip or module/@v/version.zip
        let path = path.trim_end_matches(".zip");

        if let Some(at_pos) = path.rfind('@') {
            let module = &path[..at_pos];
            let version = &path[at_pos + 1..];
            return Some((module.to_string(), version.to_string()));
        }

        None
    }

    /// Decode Go module path encoding
    /// In GOPROXY, uppercase letters are encoded as !lowercase
    pub fn decode_module_path(path: &str) -> String {
        let mut result = String::new();
        let mut chars = path.chars().peekable();

        while let Some(c) = chars.next() {
            if c == '!' {
                if let Some(next) = chars.next() {
                    result.push(next.to_ascii_uppercase());
                }
            } else {
                result.push(c);
            }
        }

        result
    }

    /// Encode Go module path for URL
    /// Uppercase letters become !lowercase
    pub fn encode_module_path(path: &str) -> String {
        let mut result = String::new();

        for c in path.chars() {
            if c.is_ascii_uppercase() {
                result.push('!');
                result.push(c.to_ascii_lowercase());
            } else {
                result.push(c);
            }
        }

        result
    }

    /// Parse go.mod file content
    pub fn parse_go_mod(content: &str) -> Result<GoMod> {
        let mut go_mod = GoMod::default();

        for line in content.lines() {
            let line = line.trim();

            // Skip empty lines and comments
            if line.is_empty() || line.starts_with("//") {
                continue;
            }

            // Module declaration
            if let Some(rest) = line.strip_prefix("module ") {
                go_mod.module = rest.trim().to_string();
                continue;
            }

            // Go version
            if let Some(rest) = line.strip_prefix("go ") {
                go_mod.go_version = Some(rest.trim().to_string());
                continue;
            }

            // Require block or single require
            if line.starts_with("require ") {
                let rest = line.strip_prefix("require ").unwrap().trim();
                // Single line require: require module/path v1.2.3
                if !rest.starts_with('(') {
                    if let Some(dep) = Self::parse_dependency_line(rest) {
                        go_mod.require.push(dep);
                    }
                }
                continue;
            }

            // Replace directive
            if line.starts_with("replace ") {
                let rest = line.strip_prefix("replace ").unwrap().trim();
                if let Some(replace) = Self::parse_replace_line(rest) {
                    go_mod.replace.push(replace);
                }
                continue;
            }

            // Exclude directive
            if line.starts_with("exclude ") {
                let rest = line.strip_prefix("exclude ").unwrap().trim();
                if let Some(dep) = Self::parse_dependency_line(rest) {
                    go_mod.exclude.push(dep);
                }
                continue;
            }

            // Retract directive
            if line.starts_with("retract ") {
                let rest = line.strip_prefix("retract ").unwrap().trim();
                go_mod.retract.push(rest.to_string());
                continue;
            }

            // Dependency line in require block
            if !line.starts_with("require")
                && !line.starts_with("replace")
                && !line.starts_with("exclude")
                && !line.starts_with("retract")
                && !line.starts_with(')')
                && !line.starts_with('(')
            {
                if let Some(dep) = Self::parse_dependency_line(line) {
                    go_mod.require.push(dep);
                }
            }
        }

        if go_mod.module.is_empty() {
            return Err(AppError::Validation(
                "go.mod missing module declaration".to_string(),
            ));
        }

        Ok(go_mod)
    }

    /// Parse a dependency line: module/path v1.2.3
    fn parse_dependency_line(line: &str) -> Option<GoDependency> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            // Check for "// indirect" by looking for "//" followed by "indirect"
            let indirect = parts.windows(2).any(|w| w[0] == "//" && w[1] == "indirect");
            Some(GoDependency {
                path: parts[0].to_string(),
                version: parts[1].to_string(),
                indirect,
            })
        } else {
            None
        }
    }

    /// Parse a replace line: old => new v1.2.3 or old v1.0.0 => new v1.2.3
    fn parse_replace_line(line: &str) -> Option<GoReplace> {
        let parts: Vec<&str> = line.split("=>").collect();
        if parts.len() != 2 {
            return None;
        }

        let old_parts: Vec<&str> = parts[0].split_whitespace().collect();
        let new_parts: Vec<&str> = parts[1].split_whitespace().collect();

        let old_path = old_parts.first()?.to_string();
        let old_version = old_parts.get(1).map(|s| s.to_string());
        let new_path = new_parts.first()?.to_string();
        let new_version = new_parts.get(1).map(|s| s.to_string());

        Some(GoReplace {
            old_path,
            old_version,
            new_path,
            new_version,
        })
    }

    /// Extract go.mod from module zip
    pub fn extract_go_mod_from_zip(content: &[u8]) -> Result<GoMod> {
        let cursor = std::io::Cursor::new(content);
        let mut archive = zip::ZipArchive::new(cursor)
            .map_err(|e| AppError::Validation(format!("Invalid module zip: {}", e)))?;

        for i in 0..archive.len() {
            let mut file = archive
                .by_index(i)
                .map_err(|e| AppError::Validation(format!("Failed to read zip entry: {}", e)))?;

            let name = file.name().to_string();

            if name.ends_with("/go.mod") || name == "go.mod" {
                let mut content = String::new();
                file.read_to_string(&mut content)
                    .map_err(|e| AppError::Validation(format!("Failed to read go.mod: {}", e)))?;

                return Self::parse_go_mod(&content);
            }
        }

        Err(AppError::Validation(
            "go.mod not found in module zip".to_string(),
        ))
    }
}

impl Default for GoHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl FormatHandler for GoHandler {
    fn format(&self) -> RepositoryFormat {
        RepositoryFormat::Go
    }

    async fn parse_metadata(&self, path: &str, content: &Bytes) -> Result<serde_json::Value> {
        let info = Self::parse_path(path)?;

        let mut metadata = serde_json::json!({
            "module": info.module,
            "operation": format!("{:?}", info.operation),
        });

        if let Some(version) = &info.version {
            metadata["version"] = serde_json::Value::String(version.clone());
        }

        // Parse content based on operation
        if !content.is_empty() {
            match info.operation {
                GoOperation::Info => {
                    // Parse version info JSON
                    if let Ok(version_info) = serde_json::from_slice::<VersionInfo>(content) {
                        metadata["versionInfo"] = serde_json::to_value(&version_info)?;
                    }
                }
                GoOperation::Mod => {
                    // Parse go.mod
                    if let Ok(content_str) = std::str::from_utf8(content) {
                        if let Ok(go_mod) = Self::parse_go_mod(content_str) {
                            metadata["goMod"] = serde_json::to_value(&go_mod)?;
                        }
                    }
                }
                GoOperation::Zip => {
                    // Extract go.mod from zip
                    if let Ok(go_mod) = Self::extract_go_mod_from_zip(content) {
                        metadata["goMod"] = serde_json::to_value(&go_mod)?;
                    }
                }
                _ => {}
            }
        }

        Ok(metadata)
    }

    async fn validate(&self, path: &str, content: &Bytes) -> Result<()> {
        let info = Self::parse_path(path)?;

        // Validate module path format
        if info.module.is_empty() {
            return Err(AppError::Validation("Empty module path".to_string()));
        }

        // Validate content based on operation
        if !content.is_empty() {
            match info.operation {
                GoOperation::Mod => {
                    let content_str = std::str::from_utf8(content).map_err(|e| {
                        AppError::Validation(format!("Invalid UTF-8 in go.mod: {}", e))
                    })?;
                    let go_mod = Self::parse_go_mod(content_str)?;

                    // Verify module path matches
                    if go_mod.module != info.module {
                        return Err(AppError::Validation(format!(
                            "Module path mismatch: path says '{}' but go.mod says '{}'",
                            info.module, go_mod.module
                        )));
                    }
                }
                GoOperation::Zip => {
                    let go_mod = Self::extract_go_mod_from_zip(content)?;

                    // Verify module path matches
                    if go_mod.module != info.module {
                        return Err(AppError::Validation(format!(
                            "Module path mismatch: path says '{}' but go.mod says '{}'",
                            info.module, go_mod.module
                        )));
                    }
                }
                GoOperation::Info => {
                    // Validate JSON structure
                    let _: VersionInfo = serde_json::from_slice(content).map_err(|e| {
                        AppError::Validation(format!("Invalid version info JSON: {}", e))
                    })?;
                }
                _ => {}
            }
        }

        Ok(())
    }

    async fn generate_index(&self) -> Result<Option<Vec<(String, Bytes)>>> {
        // Go module proxy uses dynamic endpoints
        Ok(None)
    }
}

/// Go module info from path
#[derive(Debug)]
pub struct GoModuleInfo {
    pub module: String,
    pub version: Option<String>,
    pub operation: GoOperation,
}

/// Go module proxy operation
#[derive(Debug)]
pub enum GoOperation {
    List,
    Info,
    Mod,
    Zip,
    Latest,
}

/// Version info response (/@v/<version>.info)
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct VersionInfo {
    pub version: String,
    #[serde(default)]
    pub time: Option<String>,
}

/// Parsed go.mod file
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct GoMod {
    pub module: String,
    #[serde(default)]
    pub go_version: Option<String>,
    #[serde(default)]
    pub require: Vec<GoDependency>,
    #[serde(default)]
    pub replace: Vec<GoReplace>,
    #[serde(default)]
    pub exclude: Vec<GoDependency>,
    #[serde(default)]
    pub retract: Vec<String>,
}

/// Go dependency
#[derive(Debug, Serialize, Deserialize)]
pub struct GoDependency {
    pub path: String,
    pub version: String,
    #[serde(default)]
    pub indirect: bool,
}

/// Go replace directive
#[derive(Debug, Serialize, Deserialize)]
pub struct GoReplace {
    pub old_path: String,
    pub old_version: Option<String>,
    pub new_path: String,
    pub new_version: Option<String>,
}

/// Generate version list response
pub fn generate_version_list(versions: &[String]) -> String {
    versions.join("\n")
}

/// Generate version info JSON
pub fn generate_version_info(version: &str, time: Option<&str>) -> VersionInfo {
    VersionInfo {
        version: version.to_string(),
        time: time.map(|t| t.to_string()),
    }
}

#[cfg(ak_test_shard = "services-2")]
#[cfg(test)]
mod tests {
    use super::*;

    // ---- GoHandler::new / Default ----

    #[test]
    fn test_new_and_default() {
        let _h1 = GoHandler::new();
        let _h2 = GoHandler;
    }

    // ---- parse_path: list ----

    #[test]
    fn test_parse_path_list() {
        let info = GoHandler::parse_path("github.com/user/repo/@v/list").unwrap();
        assert_eq!(info.module, "github.com/user/repo");
        assert!(matches!(info.operation, GoOperation::List));
        assert!(info.version.is_none());
    }

    // ---- parse_path: info ----

    #[test]
    fn test_parse_path_info() {
        let info = GoHandler::parse_path("github.com/user/repo/@v/v1.2.3.info").unwrap();
        assert_eq!(info.module, "github.com/user/repo");
        assert_eq!(info.version, Some("v1.2.3".to_string()));
        assert!(matches!(info.operation, GoOperation::Info));
    }

    // ---- parse_path: mod ----

    #[test]
    fn test_parse_path_mod() {
        let info = GoHandler::parse_path("github.com/user/repo/@v/v1.2.3.mod").unwrap();
        assert_eq!(info.module, "github.com/user/repo");
        assert_eq!(info.version, Some("v1.2.3".to_string()));
        assert!(matches!(info.operation, GoOperation::Mod));
    }

    // ---- parse_path: zip ----

    #[test]
    fn test_parse_path_zip() {
        let info = GoHandler::parse_path("github.com/user/repo/@v/v1.2.3.zip").unwrap();
        assert_eq!(info.module, "github.com/user/repo");
        assert_eq!(info.version, Some("v1.2.3".to_string()));
        assert!(matches!(info.operation, GoOperation::Zip));
    }

    // ---- parse_path: latest ----

    #[test]
    fn test_parse_latest() {
        let info = GoHandler::parse_path("github.com/user/repo/@latest").unwrap();
        assert_eq!(info.module, "github.com/user/repo");
        assert!(matches!(info.operation, GoOperation::Latest));
        assert!(info.version.is_none());
    }

    // ---- parse_path: leading slash ----

    #[test]
    fn test_parse_path_leading_slash() {
        let info = GoHandler::parse_path("/github.com/user/repo/@v/list").unwrap();
        assert_eq!(info.module, "github.com/user/repo");
        assert!(matches!(info.operation, GoOperation::List));
    }

    // ---- parse_path: encoded module path ----

    #[test]
    fn test_parse_path_encoded_module() {
        let info = GoHandler::parse_path("github.com/!my!package/@v/v1.0.0.info").unwrap();
        assert_eq!(info.module, "github.com/MyPackage");
        assert_eq!(info.version, Some("v1.0.0".to_string()));
        assert!(matches!(info.operation, GoOperation::Info));
    }

    // ---- parse_path: subpackages / deeper modules ----

    #[test]
    fn test_parse_path_deep_module() {
        let info = GoHandler::parse_path("github.com/user/repo/v2/subpkg/@v/v2.1.0.mod").unwrap();
        assert_eq!(info.module, "github.com/user/repo/v2/subpkg");
        assert_eq!(info.version, Some("v2.1.0".to_string()));
        assert!(matches!(info.operation, GoOperation::Mod));
    }

    // ---- parse_path: direct zip path (module@version.zip) ----

    #[test]
    fn test_parse_path_direct_zip() {
        let info = GoHandler::parse_path("github.com/user/repo@v1.0.0.zip").unwrap();
        assert_eq!(info.module, "github.com/user/repo");
        assert_eq!(info.version, Some("v1.0.0".to_string()));
        assert!(matches!(info.operation, GoOperation::Zip));
    }

    // ---- parse_path: invalid ----

    #[test]
    fn test_parse_path_invalid() {
        assert!(GoHandler::parse_path("random/path/without/marker").is_err());
    }

    #[test]
    fn test_parse_path_empty() {
        assert!(GoHandler::parse_path("").is_err());
    }

    // ---- decode_module_path ----

    #[test]
    fn test_decode_module_path() {
        assert_eq!(
            GoHandler::decode_module_path("github.com/!my!package"),
            "github.com/MyPackage"
        );
    }

    #[test]
    fn test_decode_module_path_no_encoding() {
        assert_eq!(
            GoHandler::decode_module_path("github.com/user/repo"),
            "github.com/user/repo"
        );
    }

    #[test]
    fn test_decode_module_path_empty() {
        assert_eq!(GoHandler::decode_module_path(""), "");
    }

    #[test]
    fn test_decode_module_path_trailing_exclamation() {
        // '!' at the end with no following char - the next() returns None
        assert_eq!(GoHandler::decode_module_path("test!"), "test");
    }

    #[test]
    fn test_decode_module_path_multiple_encoded() {
        assert_eq!(
            GoHandler::decode_module_path("!azure!storage"),
            "AzureStorage"
        );
    }

    // ---- encode_module_path ----

    #[test]
    fn test_encode_module_path() {
        assert_eq!(
            GoHandler::encode_module_path("github.com/MyPackage"),
            "github.com/!my!package"
        );
    }

    #[test]
    fn test_encode_module_path_no_uppercase() {
        assert_eq!(
            GoHandler::encode_module_path("github.com/user/repo"),
            "github.com/user/repo"
        );
    }

    #[test]
    fn test_encode_module_path_empty() {
        assert_eq!(GoHandler::encode_module_path(""), "");
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        let original = "github.com/Azure/go-autorest/v14";
        let encoded = GoHandler::encode_module_path(original);
        let decoded = GoHandler::decode_module_path(&encoded);
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_encode_decode_roundtrip_all_lower() {
        let original = "golang.org/x/text";
        let encoded = GoHandler::encode_module_path(original);
        assert_eq!(encoded, original); // no uppercase, no encoding
        let decoded = GoHandler::decode_module_path(&encoded);
        assert_eq!(decoded, original);
    }

    // ---- parse_go_mod ----

    #[test]
    fn test_parse_go_mod() {
        let content = r#"
module github.com/user/repo

go 1.21

require (
    github.com/pkg/errors v0.9.1
    golang.org/x/text v0.3.7 // indirect
)

replace github.com/old/pkg => github.com/new/pkg v1.0.0
"#;
        let go_mod = GoHandler::parse_go_mod(content).unwrap();
        assert_eq!(go_mod.module, "github.com/user/repo");
        assert_eq!(go_mod.go_version, Some("1.21".to_string()));
        assert_eq!(go_mod.require.len(), 2);
        assert_eq!(go_mod.require[0].path, "github.com/pkg/errors");
        assert_eq!(go_mod.require[0].version, "v0.9.1");
        assert!(!go_mod.require[0].indirect);
        assert_eq!(go_mod.require[1].path, "golang.org/x/text");
        assert_eq!(go_mod.require[1].version, "v0.3.7");
        assert_eq!(go_mod.replace.len(), 1);
        assert_eq!(go_mod.replace[0].old_path, "github.com/old/pkg");
        assert!(go_mod.replace[0].old_version.is_none());
        assert_eq!(go_mod.replace[0].new_path, "github.com/new/pkg");
        assert_eq!(go_mod.replace[0].new_version, Some("v1.0.0".to_string()));
    }

    #[test]
    fn test_parse_go_mod_single_require() {
        let content = r#"
module github.com/user/repo

go 1.21

require github.com/pkg/errors v0.9.1
"#;
        let go_mod = GoHandler::parse_go_mod(content).unwrap();
        assert_eq!(go_mod.module, "github.com/user/repo");
        assert_eq!(go_mod.require.len(), 1);
        assert_eq!(go_mod.require[0].path, "github.com/pkg/errors");
        assert_eq!(go_mod.require[0].version, "v0.9.1");
    }

    #[test]
    fn test_parse_go_mod_with_exclude() {
        let content = r#"
module github.com/user/repo

go 1.21

exclude github.com/bad/pkg v0.1.0
"#;
        let go_mod = GoHandler::parse_go_mod(content).unwrap();
        assert_eq!(go_mod.exclude.len(), 1);
        assert_eq!(go_mod.exclude[0].path, "github.com/bad/pkg");
        assert_eq!(go_mod.exclude[0].version, "v0.1.0");
    }

    #[test]
    fn test_parse_go_mod_with_retract() {
        let content = r#"
module github.com/user/repo

go 1.21

retract v1.0.0
retract [v1.1.0, v1.2.0]
"#;
        let go_mod = GoHandler::parse_go_mod(content).unwrap();
        assert_eq!(go_mod.retract.len(), 2);
        assert_eq!(go_mod.retract[0], "v1.0.0");
        assert_eq!(go_mod.retract[1], "[v1.1.0, v1.2.0]");
    }

    #[test]
    fn test_parse_go_mod_replace_with_version() {
        let content = r#"
module github.com/user/repo

go 1.21

replace github.com/old/pkg v1.0.0 => github.com/new/pkg v2.0.0
"#;
        let go_mod = GoHandler::parse_go_mod(content).unwrap();
        assert_eq!(go_mod.replace.len(), 1);
        assert_eq!(go_mod.replace[0].old_path, "github.com/old/pkg");
        assert_eq!(go_mod.replace[0].old_version, Some("v1.0.0".to_string()));
        assert_eq!(go_mod.replace[0].new_path, "github.com/new/pkg");
        assert_eq!(go_mod.replace[0].new_version, Some("v2.0.0".to_string()));
    }

    #[test]
    fn test_parse_go_mod_replace_local_path() {
        let content = r#"
module github.com/user/repo

go 1.21

replace github.com/old/pkg => ../local-pkg
"#;
        let go_mod = GoHandler::parse_go_mod(content).unwrap();
        assert_eq!(go_mod.replace.len(), 1);
        assert_eq!(go_mod.replace[0].new_path, "../local-pkg");
        assert!(go_mod.replace[0].new_version.is_none());
    }

    #[test]
    fn test_parse_go_mod_missing_module() {
        let content = r#"
go 1.21

require github.com/pkg/errors v0.9.1
"#;
        let result = GoHandler::parse_go_mod(content);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_go_mod_empty() {
        let result = GoHandler::parse_go_mod("");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_go_mod_comments_and_blank_lines() {
        let content = r#"
// This is a comment
module github.com/user/repo

// Another comment
go 1.22

// Dependencies
require github.com/pkg/errors v0.9.1
"#;
        let go_mod = GoHandler::parse_go_mod(content).unwrap();
        assert_eq!(go_mod.module, "github.com/user/repo");
        assert_eq!(go_mod.go_version, Some("1.22".to_string()));
        assert_eq!(go_mod.require.len(), 1);
    }

    #[test]
    fn test_parse_go_mod_minimal() {
        let content = "module github.com/user/repo\n";
        let go_mod = GoHandler::parse_go_mod(content).unwrap();
        assert_eq!(go_mod.module, "github.com/user/repo");
        assert!(go_mod.go_version.is_none());
        assert!(go_mod.require.is_empty());
        assert!(go_mod.replace.is_empty());
        assert!(go_mod.exclude.is_empty());
        assert!(go_mod.retract.is_empty());
    }

    // ---- parse_dependency_line ----

    #[test]
    fn test_parse_dependency_line_normal() {
        let dep = GoHandler::parse_dependency_line("github.com/user/repo v1.0.0").unwrap();
        assert_eq!(dep.path, "github.com/user/repo");
        assert_eq!(dep.version, "v1.0.0");
        assert!(!dep.indirect);
    }

    #[test]
    fn test_parse_dependency_line_indirect() {
        // "// indirect" is correctly detected by looking for "//" followed by "indirect"
        // as adjacent tokens in the split_whitespace output.
        let dep =
            GoHandler::parse_dependency_line("github.com/user/repo v1.0.0 // indirect").unwrap();
        assert_eq!(dep.path, "github.com/user/repo");
        assert_eq!(dep.version, "v1.0.0");
        assert!(dep.indirect);
    }

    #[test]
    fn test_parse_dependency_line_single_token() {
        // Only one token - no version
        let result = GoHandler::parse_dependency_line("github.com/user/repo");
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_dependency_line_empty() {
        let result = GoHandler::parse_dependency_line("");
        assert!(result.is_none());
    }

    // ---- parse_replace_line ----

    #[test]
    fn test_parse_replace_line_simple() {
        let replace =
            GoHandler::parse_replace_line("github.com/old/pkg => github.com/new/pkg v1.0.0")
                .unwrap();
        assert_eq!(replace.old_path, "github.com/old/pkg");
        assert!(replace.old_version.is_none());
        assert_eq!(replace.new_path, "github.com/new/pkg");
        assert_eq!(replace.new_version, Some("v1.0.0".to_string()));
    }

    #[test]
    fn test_parse_replace_line_with_old_version() {
        let replace =
            GoHandler::parse_replace_line("github.com/old/pkg v1.0.0 => github.com/new/pkg v2.0.0")
                .unwrap();
        assert_eq!(replace.old_path, "github.com/old/pkg");
        assert_eq!(replace.old_version, Some("v1.0.0".to_string()));
        assert_eq!(replace.new_path, "github.com/new/pkg");
        assert_eq!(replace.new_version, Some("v2.0.0".to_string()));
    }

    #[test]
    fn test_parse_replace_line_no_arrow() {
        let result = GoHandler::parse_replace_line("github.com/old/pkg v1.0.0");
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_replace_line_multiple_arrows() {
        // Two "=>" - split gives 3 parts, which != 2
        let result = GoHandler::parse_replace_line("a => b => c");
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_replace_line_empty_sides() {
        // " => " with empty sides
        let result = GoHandler::parse_replace_line(" =>  ");
        // split_whitespace on "" gives empty vec, .first() returns None
        assert!(result.is_none());
    }

    // ---- generate_version_list ----

    #[test]
    fn test_generate_version_list() {
        let versions = vec![
            "v1.0.0".to_string(),
            "v1.1.0".to_string(),
            "v2.0.0".to_string(),
        ];
        let list = generate_version_list(&versions);
        assert_eq!(list, "v1.0.0\nv1.1.0\nv2.0.0");
    }

    #[test]
    fn test_generate_version_list_empty() {
        let list = generate_version_list(&[]);
        assert_eq!(list, "");
    }

    #[test]
    fn test_generate_version_list_single() {
        let list = generate_version_list(&["v1.0.0".to_string()]);
        assert_eq!(list, "v1.0.0");
    }

    // ---- generate_version_info ----

    #[test]
    fn test_generate_version_info_with_time() {
        let info = generate_version_info("v1.0.0", Some("2024-01-01T00:00:00Z"));
        assert_eq!(info.version, "v1.0.0");
        assert_eq!(info.time, Some("2024-01-01T00:00:00Z".to_string()));
    }

    #[test]
    fn test_generate_version_info_no_time() {
        let info = generate_version_info("v1.0.0", None);
        assert_eq!(info.version, "v1.0.0");
        assert!(info.time.is_none());
    }

    // ---- VersionInfo serde ----

    #[test]
    fn test_version_info_serde_roundtrip() {
        let info = VersionInfo {
            version: "v1.0.0".to_string(),
            time: Some("2024-01-01T00:00:00Z".to_string()),
        };
        let json = serde_json::to_string(&info).unwrap();
        // PascalCase: {"Version":"v1.0.0","Time":"2024-01-01T00:00:00Z"}
        assert!(json.contains("\"Version\""));
        assert!(json.contains("\"Time\""));
        let parsed: VersionInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.version, "v1.0.0");
        assert_eq!(parsed.time, Some("2024-01-01T00:00:00Z".to_string()));
    }

    #[test]
    fn test_version_info_serde_no_time() {
        let info = VersionInfo {
            version: "v1.0.0".to_string(),
            time: None,
        };
        let json = serde_json::to_string(&info).unwrap();
        let parsed: VersionInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.version, "v1.0.0");
        assert!(parsed.time.is_none());
    }

    // ---- GoMod serde ----

    #[test]
    fn test_go_mod_serde_roundtrip() {
        let go_mod = GoMod {
            module: "github.com/user/repo".to_string(),
            go_version: Some("1.21".to_string()),
            require: vec![GoDependency {
                path: "github.com/pkg/errors".to_string(),
                version: "v0.9.1".to_string(),
                indirect: false,
            }],
            replace: vec![GoReplace {
                old_path: "github.com/old".to_string(),
                old_version: None,
                new_path: "github.com/new".to_string(),
                new_version: Some("v1.0.0".to_string()),
            }],
            exclude: vec![],
            retract: vec![],
        };
        let json = serde_json::to_string(&go_mod).unwrap();
        let parsed: GoMod = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.module, "github.com/user/repo");
        assert_eq!(parsed.require.len(), 1);
        assert_eq!(parsed.replace.len(), 1);
    }

    // ---- parse_zip_path ----

    #[test]
    fn test_parse_zip_path_with_at() {
        // module@version.zip -> trimmed to module@version
        let result = GoHandler::parse_zip_path("github.com/user/repo@v1.0.0.zip");
        assert!(result.is_some());
        let (module, version) = result.unwrap();
        assert_eq!(module, "github.com/user/repo");
        assert_eq!(version, "v1.0.0");
    }

    #[test]
    fn test_parse_zip_path_no_at() {
        let result = GoHandler::parse_zip_path("github.com/user/repo/v1.0.0.zip");
        assert!(result.is_none());
    }

    // ---- extract_go_mod_from_zip: error cases ----

    #[test]
    fn test_extract_go_mod_from_zip_invalid() {
        let result = GoHandler::extract_go_mod_from_zip(b"not a zip");
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_go_mod_from_zip_empty() {
        let result = GoHandler::extract_go_mod_from_zip(b"");
        assert!(result.is_err());
    }

    // ---- parse_go_mod: require block with opening paren on separate line ----

    #[test]
    fn test_parse_go_mod_require_with_paren() {
        // The "require (" line has a rest of "(", which starts_with('(')
        // so it's skipped. Then the dep lines are parsed as standalone lines.
        let content = r#"
module github.com/user/repo

go 1.21

require (
    github.com/pkg/errors v0.9.1
    github.com/sirupsen/logrus v1.9.0
)
"#;
        let go_mod = GoHandler::parse_go_mod(content).unwrap();
        assert_eq!(go_mod.require.len(), 2);
    }

    // ---- parse_go_mod: multiple replace directives ----

    #[test]
    fn test_parse_go_mod_multiple_replaces() {
        let content = r#"
module github.com/user/repo

go 1.21

replace github.com/a => github.com/b v1.0.0
replace github.com/c v2.0.0 => github.com/d v3.0.0
"#;
        let go_mod = GoHandler::parse_go_mod(content).unwrap();
        assert_eq!(go_mod.replace.len(), 2);
    }
}
