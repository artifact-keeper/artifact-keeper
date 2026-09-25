use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::error::{AppError, Result};
use crate::formats::FormatHandler;
use crate::models::repository::RepositoryFormat;

/// Represents different types of HuggingFace resources
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HuggingFaceKind {
    /// Model information endpoint
    Model,
    /// Dataset information endpoint
    Dataset,
    /// File download/content
    File,
}

/// Parsed information from a HuggingFace path
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HuggingFacePathInfo {
    /// Type of resource (Model, Dataset, or File)
    pub kind: String,
    /// Organization/owner name
    pub org: String,
    /// Repository/model/dataset name
    pub name: String,
    /// Optional revision (branch, tag, or commit hash)
    pub revision: Option<String>,
    /// Optional file path (for file downloads)
    pub file_path: Option<String>,
}

/// Handler for HuggingFace Hub repositories
pub struct HuggingFaceHandler;

impl HuggingFaceHandler {
    pub fn new() -> Self {
        Self
    }

    /// Parse a HuggingFace repository path
    ///
    /// Supports patterns:
    /// - `api/models/<org>/<name>` - model info
    /// - `api/models/<org>/<name>/revision/<rev>` - specific revision
    /// - `<org>/<name>/resolve/<rev>/<path..>` - file download
    /// - `api/datasets/<org>/<name>` - dataset info
    pub fn parse_path(path: &str) -> Result<HuggingFacePathInfo> {
        let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();

        // Pattern: api/models/<org>/<name>
        if parts.len() >= 4 && parts[0] == "api" && parts[1] == "models" {
            let org = parts[2].to_string();
            let name = parts[3].to_string();

            // Check for revision: api/models/<org>/<name>/revision/<rev>
            if parts.len() >= 6 && parts[4] == "revision" {
                let revision = Some(parts[5].to_string());
                return Ok(HuggingFacePathInfo {
                    kind: "model".to_string(),
                    org,
                    name,
                    revision,
                    file_path: None,
                });
            }

            return Ok(HuggingFacePathInfo {
                kind: "model".to_string(),
                org,
                name,
                revision: None,
                file_path: None,
            });
        }

        // Pattern: api/datasets/<org>/<name>
        if parts.len() >= 4 && parts[0] == "api" && parts[1] == "datasets" {
            let org = parts[2].to_string();
            let name = parts[3].to_string();

            return Ok(HuggingFacePathInfo {
                kind: "dataset".to_string(),
                org,
                name,
                revision: None,
                file_path: None,
            });
        }

        // Pattern: <org>/<name>/resolve/<rev>/<path..>
        if parts.len() >= 4 && parts[2] == "resolve" {
            let org = parts[0].to_string();
            let name = parts[1].to_string();
            let revision = Some(parts[3].to_string());
            let file_path = if parts.len() > 4 {
                Some(parts[4..].join("/"))
            } else {
                None
            };

            return Ok(HuggingFacePathInfo {
                kind: "file".to_string(),
                org,
                name,
                revision,
                file_path,
            });
        }

        Err(AppError::Validation(format!(
            "Invalid HuggingFace path format: {}",
            path
        )))
    }
}

impl Default for HuggingFaceHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl FormatHandler for HuggingFaceHandler {
    fn format(&self) -> RepositoryFormat {
        RepositoryFormat::Huggingface
    }

    fn format_key(&self) -> &str {
        "huggingface"
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
    fn test_parse_model_info() {
        let path = "api/models/gpt2-org/gpt2";
        let info = HuggingFaceHandler::parse_path(path).unwrap();
        assert_eq!(info.kind, "model");
        assert_eq!(info.org, "gpt2-org");
        assert_eq!(info.name, "gpt2");
        assert_eq!(info.revision, None);
        assert_eq!(info.file_path, None);
    }

    #[test]
    fn test_parse_model_with_revision() {
        let path = "api/models/gpt2-org/gpt2/revision/main";
        let info = HuggingFaceHandler::parse_path(path).unwrap();
        assert_eq!(info.kind, "model");
        assert_eq!(info.org, "gpt2-org");
        assert_eq!(info.name, "gpt2");
        assert_eq!(info.revision, Some("main".to_string()));
        assert_eq!(info.file_path, None);
    }

    #[test]
    fn test_parse_file_download() {
        let path = "gpt2-org/gpt2/resolve/main/pytorch_model.bin";
        let info = HuggingFaceHandler::parse_path(path).unwrap();
        assert_eq!(info.kind, "file");
        assert_eq!(info.org, "gpt2-org");
        assert_eq!(info.name, "gpt2");
        assert_eq!(info.revision, Some("main".to_string()));
        assert_eq!(info.file_path, Some("pytorch_model.bin".to_string()));
    }

    #[test]
    fn test_parse_file_download_nested() {
        let path = "gpt2-org/gpt2/resolve/main/models/sub/file.bin";
        let info = HuggingFaceHandler::parse_path(path).unwrap();
        assert_eq!(info.kind, "file");
        assert_eq!(info.org, "gpt2-org");
        assert_eq!(info.name, "gpt2");
        assert_eq!(info.revision, Some("main".to_string()));
        assert_eq!(info.file_path, Some("models/sub/file.bin".to_string()));
    }

    #[test]
    fn test_parse_dataset_info() {
        let path = "api/datasets/datasets-org/dataset-name";
        let info = HuggingFaceHandler::parse_path(path).unwrap();
        assert_eq!(info.kind, "dataset");
        assert_eq!(info.org, "datasets-org");
        assert_eq!(info.name, "dataset-name");
        assert_eq!(info.revision, None);
        assert_eq!(info.file_path, None);
    }

    #[test]
    fn test_parse_invalid_path() {
        let path = "invalid/path/format";
        let result = HuggingFaceHandler::parse_path(path);
        assert!(result.is_err());
    }

    #[test]
    fn test_handler_format() {
        let handler = HuggingFaceHandler::new();
        assert_eq!(handler.format(), RepositoryFormat::Huggingface);
    }

    #[test]
    fn test_handler_format_key() {
        let handler = HuggingFaceHandler::new();
        assert_eq!(handler.format_key(), "huggingface");
    }
}
