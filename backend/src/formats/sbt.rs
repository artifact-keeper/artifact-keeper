use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::error::{AppError, Result};
use crate::formats::FormatHandler;
use crate::models::repository::RepositoryFormat;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SbtPathInfo {
    pub org: String,
    pub module: String,
    pub revision: Option<String>,
    pub artifact: Option<String>,
    pub ext: Option<String>,
    pub is_ivy_descriptor: bool,
}

pub struct SbtHandler;

impl SbtHandler {
    pub fn new() -> Self {
        Self
    }

    pub fn parse_path(path: &str) -> Result<SbtPathInfo> {
        let path = path.trim_start_matches('/');

        // Try parsing as ivy descriptor: <org>/<module>/<revision>/ivy-<revision>.xml
        if let Some(ivy_match) = Self::try_parse_ivy_descriptor(path) {
            return Ok(ivy_match);
        }

        // Try parsing as artifact: <org>/<module>/<revision>/<type>s/<artifact>-<revision>.<ext>
        Self::try_parse_artifact(path)
    }

    fn try_parse_ivy_descriptor(path: &str) -> Option<SbtPathInfo> {
        let parts: Vec<&str> = path.split('/').collect();

        // Need at least: org/module/revision/ivy-revision.xml
        if parts.len() < 4 {
            return None;
        }

        // Last part should be ivy-*.xml
        let filename = parts[parts.len() - 1];
        if !filename.starts_with("ivy-") || !filename.ends_with(".xml") {
            return None;
        }

        let org = parts[0].to_string();
        let module = parts[1].to_string();
        let revision = parts[2].to_string();

        Some(SbtPathInfo {
            org,
            module,
            revision: Some(revision),
            artifact: None,
            ext: Some("xml".to_string()),
            is_ivy_descriptor: true,
        })
    }

    fn try_parse_artifact(path: &str) -> Result<SbtPathInfo> {
        let parts: Vec<&str> = path.split('/').collect();

        // Need at least: org/module/revision/<type>s/artifact.ext
        if parts.len() < 5 {
            return Err(AppError::Validation(format!("Invalid SBT path: {}", path)));
        }

        let org = parts[0].to_string();
        let module = parts[1].to_string();
        let revision = parts[2].to_string();

        // Fourth part should be <type>s (e.g., jars, sources, docs)
        let type_part = parts[3];
        if !type_part.ends_with('s') {
            return Err(AppError::Validation(format!("Invalid SBT path: {}", path)));
        }

        // Last part is the filename: artifact-revision.ext
        let filename = parts[4];

        // Parse filename
        let (artifact, ext) = if let Some(dot_pos) = filename.rfind('.') {
            let name = &filename[..dot_pos];
            let extension = &filename[dot_pos + 1..];
            (name.to_string(), extension.to_string())
        } else {
            return Err(AppError::Validation(format!("Invalid SBT path: {}", path)));
        };

        Ok(SbtPathInfo {
            org,
            module,
            revision: Some(revision),
            artifact: Some(artifact),
            ext: Some(ext),
            is_ivy_descriptor: false,
        })
    }
}

impl Default for SbtHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl FormatHandler for SbtHandler {
    fn format(&self) -> RepositoryFormat {
        RepositoryFormat::Sbt
    }

    fn format_key(&self) -> &str {
        "sbt"
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
    fn test_parse_ivy_descriptor() {
        let result = SbtHandler::parse_path("org.example/module/1.0.0/ivy-1.0.0.xml");
        assert!(result.is_ok());
        let info = result.unwrap();
        assert_eq!(info.org, "org.example");
        assert_eq!(info.module, "module");
        assert_eq!(info.revision, Some("1.0.0".to_string()));
        assert_eq!(info.ext, Some("xml".to_string()));
        assert!(info.is_ivy_descriptor);
    }

    #[test]
    fn test_parse_jar_artifact() {
        let result = SbtHandler::parse_path("org/example/1.0.0/jars/module-1.0.0.jar");
        assert!(result.is_ok());
        let info = result.unwrap();
        assert_eq!(info.org, "org");
        assert_eq!(info.module, "example");
        assert_eq!(info.revision, Some("1.0.0".to_string()));
        assert_eq!(info.artifact, Some("module-1.0.0".to_string()));
        assert_eq!(info.ext, Some("jar".to_string()));
        assert!(!info.is_ivy_descriptor);
    }

    #[test]
    fn test_parse_sources_artifact() {
        let result = SbtHandler::parse_path("com/example/2.0.0/sources/mylib-2.0.0-sources.jar");
        assert!(result.is_ok());
        let info = result.unwrap();
        assert_eq!(info.org, "com");
        assert_eq!(info.module, "example");
        assert_eq!(info.revision, Some("2.0.0".to_string()));
        assert_eq!(info.artifact, Some("mylib-2.0.0-sources".to_string()));
        assert_eq!(info.ext, Some("jar".to_string()));
        assert!(!info.is_ivy_descriptor);
    }

    #[test]
    fn test_parse_invalid_path_short() {
        let result = SbtHandler::parse_path("org/module");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_invalid_type_part() {
        let result = SbtHandler::parse_path("org/module/1.0.0/jar/module-1.0.0.jar");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_no_extension() {
        let result = SbtHandler::parse_path("org/module/1.0.0/jars/noext");
        assert!(result.is_err());
    }

    #[test]
    fn test_format() {
        let handler = SbtHandler::new();
        assert_eq!(handler.format(), RepositoryFormat::Sbt);
    }

    #[test]
    fn test_format_key() {
        let handler = SbtHandler::new();
        assert_eq!(handler.format_key(), "sbt");
    }
}
