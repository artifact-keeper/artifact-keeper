use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::error::{AppError, Result};
use crate::formats::FormatHandler;
use crate::models::repository::RepositoryFormat;

/// Parsed information from an MLModel path
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MlModelPathInfo {
    /// Model name
    pub name: String,
    /// Optional version identifier
    pub version: Option<String>,
    /// Optional artifact file path
    pub artifact_path: Option<String>,
}

/// Handler for MLModel repositories
pub struct MlModelHandler;

impl MlModelHandler {
    pub fn new() -> Self {
        Self
    }

    /// Parse an MLModel repository path
    ///
    /// Supports patterns:
    /// - `models/<name>` - model info
    /// - `models/<name>/versions/<version>` - model version
    /// - `models/<name>/versions/<version>/artifacts/<path..>` - artifact file
    pub fn parse_path(path: &str) -> Result<MlModelPathInfo> {
        let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();

        // Must start with "models"
        if parts.is_empty() || parts[0] != "models" {
            return Err(AppError::Validation(format!(
                "Invalid MLModel path format: {}",
                path
            )));
        }

        if parts.len() < 2 {
            return Err(AppError::Validation(format!(
                "Invalid MLModel path format: {}",
                path
            )));
        }

        let name = parts[1].to_string();

        // Pattern: models/<name>
        if parts.len() == 2 {
            return Ok(MlModelPathInfo {
                name,
                version: None,
                artifact_path: None,
            });
        }

        // Pattern: models/<name>/versions/<version>
        // Pattern: models/<name>/versions/<version>/artifacts/<path..>
        if parts.len() >= 4 && parts[2] == "versions" {
            let version = Some(parts[3].to_string());

            // Check for artifacts: models/<name>/versions/<version>/artifacts/<path..>
            if parts.len() >= 6 && parts[4] == "artifacts" {
                let artifact_path = if parts.len() > 5 {
                    Some(parts[5..].join("/"))
                } else {
                    None
                };

                return Ok(MlModelPathInfo {
                    name,
                    version,
                    artifact_path,
                });
            }

            // Just version without artifacts
            return Ok(MlModelPathInfo {
                name,
                version,
                artifact_path: None,
            });
        }

        Err(AppError::Validation(format!(
            "Invalid MLModel path format: {}",
            path
        )))
    }
}

impl Default for MlModelHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl FormatHandler for MlModelHandler {
    fn format(&self) -> RepositoryFormat {
        RepositoryFormat::Mlmodel
    }

    fn format_key(&self) -> &str {
        "mlmodel"
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
        let path = "models/my-model";
        let info = MlModelHandler::parse_path(path).unwrap();
        assert_eq!(info.name, "my-model");
        assert_eq!(info.version, None);
        assert_eq!(info.artifact_path, None);
    }

    #[test]
    fn test_parse_model_with_version() {
        let path = "models/my-model/versions/v1.0.0";
        let info = MlModelHandler::parse_path(path).unwrap();
        assert_eq!(info.name, "my-model");
        assert_eq!(info.version, Some("v1.0.0".to_string()));
        assert_eq!(info.artifact_path, None);
    }

    #[test]
    fn test_parse_artifact_file() {
        let path = "models/my-model/versions/v1.0.0/artifacts/model.pkl";
        let info = MlModelHandler::parse_path(path).unwrap();
        assert_eq!(info.name, "my-model");
        assert_eq!(info.version, Some("v1.0.0".to_string()));
        assert_eq!(info.artifact_path, Some("model.pkl".to_string()));
    }

    #[test]
    fn test_parse_artifact_nested() {
        let path = "models/my-model/versions/v1.0.0/artifacts/weights/model.pkl";
        let info = MlModelHandler::parse_path(path).unwrap();
        assert_eq!(info.name, "my-model");
        assert_eq!(info.version, Some("v1.0.0".to_string()));
        assert_eq!(info.artifact_path, Some("weights/model.pkl".to_string()));
    }

    #[test]
    fn test_parse_artifact_deeply_nested() {
        let path = "models/my-model/versions/v1.0.0/artifacts/dir1/dir2/dir3/file.bin";
        let info = MlModelHandler::parse_path(path).unwrap();
        assert_eq!(info.name, "my-model");
        assert_eq!(info.version, Some("v1.0.0".to_string()));
        assert_eq!(
            info.artifact_path,
            Some("dir1/dir2/dir3/file.bin".to_string())
        );
    }

    #[test]
    fn test_parse_invalid_no_models_prefix() {
        let path = "invalid/my-model";
        let result = MlModelHandler::parse_path(path);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_models_only() {
        // "models/" splits to ["models", ""] which has len 2,
        // so it parses as model with empty name
        let path = "models/";
        let result = MlModelHandler::parse_path(path);
        assert!(result.is_ok());
        let info = result.unwrap();
        assert_eq!(info.name, "");
    }

    #[test]
    fn test_parse_invalid_empty() {
        let path = "";
        let result = MlModelHandler::parse_path(path);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_model_with_special_chars() {
        let path = "models/my-model-v2_3/versions/v1.0.0-alpha";
        let info = MlModelHandler::parse_path(path).unwrap();
        assert_eq!(info.name, "my-model-v2_3");
        assert_eq!(info.version, Some("v1.0.0-alpha".to_string()));
    }

    #[test]
    fn test_handler_format() {
        let handler = MlModelHandler::new();
        assert_eq!(handler.format(), RepositoryFormat::Mlmodel);
    }

    #[test]
    fn test_handler_format_key() {
        let handler = MlModelHandler::new();
        assert_eq!(handler.format_key(), "mlmodel");
    }
}
