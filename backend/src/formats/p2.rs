use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::error::{AppError, Result};
use crate::formats::FormatHandler;
use crate::models::repository::RepositoryFormat;

/// P2 (Eclipse package repository) format handler
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum P2Kind {
    Content,
    Artifacts,
    Plugin,
    Feature,
}

/// P2 repository format handler
pub struct P2Handler;

/// Information extracted from a P2 repository path
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct P2PathInfo {
    pub kind: P2Kind,
    pub id: Option<String>,
    pub version: Option<String>,
}

impl P2Handler {
    pub fn new() -> Self {
        Self
    }

    /// Parse a P2 repository path and extract metadata
    pub fn parse_path(path: &str) -> Result<P2PathInfo> {
        let path = path.trim_start_matches('/');

        // Repository metadata files
        if path == "content.xml" {
            return Ok(P2PathInfo {
                kind: P2Kind::Content,
                id: None,
                version: None,
            });
        }

        if path == "artifacts.xml" {
            return Ok(P2PathInfo {
                kind: P2Kind::Artifacts,
                id: None,
                version: None,
            });
        }

        // Plugin JAR: plugins/<id>_<version>.jar
        if path.starts_with("plugins/") && path.ends_with(".jar") {
            let filename = path.strip_prefix("plugins/").unwrap();
            let basename = filename.strip_suffix(".jar").unwrap();

            if let Some((id, version)) = basename.rsplit_once('_') {
                return Ok(P2PathInfo {
                    kind: P2Kind::Plugin,
                    id: Some(id.to_string()),
                    version: Some(version.to_string()),
                });
            }
        }

        // Feature JAR: features/<id>_<version>.jar
        if path.starts_with("features/") && path.ends_with(".jar") {
            let filename = path.strip_prefix("features/").unwrap();
            let basename = filename.strip_suffix(".jar").unwrap();

            if let Some((id, version)) = basename.rsplit_once('_') {
                return Ok(P2PathInfo {
                    kind: P2Kind::Feature,
                    id: Some(id.to_string()),
                    version: Some(version.to_string()),
                });
            }
        }

        Err(AppError::Validation(format!(
            "Invalid P2 path format: {}",
            path
        )))
    }
}

impl Default for P2Handler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl FormatHandler for P2Handler {
    fn format(&self) -> RepositoryFormat {
        RepositoryFormat::P2
    }

    fn format_key(&self) -> &str {
        "p2"
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
    fn test_parse_content_xml() {
        let result = P2Handler::parse_path("content.xml").unwrap();
        match result.kind {
            P2Kind::Content => (),
            _ => panic!("Expected Content kind"),
        }
        assert_eq!(result.id, None);
        assert_eq!(result.version, None);
    }

    #[test]
    fn test_parse_artifacts_xml() {
        let result = P2Handler::parse_path("artifacts.xml").unwrap();
        match result.kind {
            P2Kind::Artifacts => (),
            _ => panic!("Expected Artifacts kind"),
        }
        assert_eq!(result.id, None);
        assert_eq!(result.version, None);
    }

    #[test]
    fn test_parse_plugin_jar() {
        let result = P2Handler::parse_path("plugins/org.eclipse.core.runtime_3.20.0.jar").unwrap();
        match result.kind {
            P2Kind::Plugin => (),
            _ => panic!("Expected Plugin kind"),
        }
        assert_eq!(result.id, Some("org.eclipse.core.runtime".to_string()));
        assert_eq!(result.version, Some("3.20.0".to_string()));
    }

    #[test]
    fn test_parse_feature_jar() {
        let result = P2Handler::parse_path("features/org.eclipse.rcp_4.18.0.jar").unwrap();
        match result.kind {
            P2Kind::Feature => (),
            _ => panic!("Expected Feature kind"),
        }
        assert_eq!(result.id, Some("org.eclipse.rcp".to_string()));
        assert_eq!(result.version, Some("4.18.0".to_string()));
    }

    #[test]
    fn test_parse_complex_plugin_id() {
        let result =
            P2Handler::parse_path("plugins/com.example.my.plugin_2.5.1.20210101.jar").unwrap();
        match result.kind {
            P2Kind::Plugin => (),
            _ => panic!("Expected Plugin kind"),
        }
        assert_eq!(result.id, Some("com.example.my.plugin".to_string()));
        assert_eq!(result.version, Some("2.5.1.20210101".to_string()));
    }

    #[test]
    fn test_invalid_plugin_without_jar() {
        assert!(P2Handler::parse_path("plugins/org.eclipse.core.runtime_3.20.0").is_err());
    }

    #[test]
    fn test_invalid_path() {
        assert!(P2Handler::parse_path("invalid/path").is_err());
    }

    #[test]
    fn test_format_handler() {
        let handler = P2Handler::new();
        assert_eq!(handler.format_key(), "p2");
        assert_eq!(handler.format(), RepositoryFormat::P2);
    }
}
