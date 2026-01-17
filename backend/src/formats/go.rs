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
            Some(GoDependency {
                path: parts[0].to_string(),
                version: parts[1].to_string(),
                indirect: parts.iter().any(|&p| p == "//indirect" || p == "// indirect"),
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

        let old_parts: Vec<&str> = parts[0].trim().split_whitespace().collect();
        let new_parts: Vec<&str> = parts[1].trim().split_whitespace().collect();

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
                    let content_str = std::str::from_utf8(content)
                        .map_err(|e| AppError::Validation(format!("Invalid UTF-8 in go.mod: {}", e)))?;
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
                    let _: VersionInfo = serde_json::from_slice(content)
                        .map_err(|e| AppError::Validation(format!("Invalid version info JSON: {}", e)))?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_path_list() {
        let info = GoHandler::parse_path("github.com/user/repo/@v/list").unwrap();
        assert_eq!(info.module, "github.com/user/repo");
        assert!(matches!(info.operation, GoOperation::List));
    }

    #[test]
    fn test_parse_path_info() {
        let info = GoHandler::parse_path("github.com/user/repo/@v/v1.2.3.info").unwrap();
        assert_eq!(info.module, "github.com/user/repo");
        assert_eq!(info.version, Some("v1.2.3".to_string()));
        assert!(matches!(info.operation, GoOperation::Info));
    }

    #[test]
    fn test_parse_path_mod() {
        let info = GoHandler::parse_path("github.com/user/repo/@v/v1.2.3.mod").unwrap();
        assert_eq!(info.module, "github.com/user/repo");
        assert_eq!(info.version, Some("v1.2.3".to_string()));
        assert!(matches!(info.operation, GoOperation::Mod));
    }

    #[test]
    fn test_parse_path_zip() {
        let info = GoHandler::parse_path("github.com/user/repo/@v/v1.2.3.zip").unwrap();
        assert_eq!(info.module, "github.com/user/repo");
        assert_eq!(info.version, Some("v1.2.3".to_string()));
        assert!(matches!(info.operation, GoOperation::Zip));
    }

    #[test]
    fn test_decode_module_path() {
        // GitHub uses lowercase in module paths, but other hosts might not
        assert_eq!(GoHandler::decode_module_path("github.com/!my!package"), "github.com/MyPackage");
    }

    #[test]
    fn test_encode_module_path() {
        assert_eq!(GoHandler::encode_module_path("github.com/MyPackage"), "github.com/!my!package");
    }

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
        assert_eq!(go_mod.replace.len(), 1);
    }

    #[test]
    fn test_parse_latest() {
        let info = GoHandler::parse_path("github.com/user/repo/@latest").unwrap();
        assert_eq!(info.module, "github.com/user/repo");
        assert!(matches!(info.operation, GoOperation::Latest));
    }
}
