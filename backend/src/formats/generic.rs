//! Generic binary format handler.

use async_trait::async_trait;
use bytes::Bytes;

use super::FormatHandler;
use crate::error::Result;
use crate::models::repository::RepositoryFormat;

pub struct GenericHandler;

impl GenericHandler {
    pub fn new() -> Self {
        Self
    }
}

impl Default for GenericHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl FormatHandler for GenericHandler {
    fn format(&self) -> RepositoryFormat {
        RepositoryFormat::Generic
    }

    async fn parse_metadata(&self, path: &str, _content: &Bytes) -> Result<serde_json::Value> {
        // Generic format has minimal metadata
        Ok(serde_json::json!({
            "path": path,
        }))
    }

    async fn validate(&self, _path: &str, _content: &Bytes) -> Result<()> {
        // Generic format accepts any content
        Ok(())
    }

    async fn generate_index(&self) -> Result<Option<Vec<(String, Bytes)>>> {
        // No index for generic format
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generic_handler_new() {
        let handler = GenericHandler::new();
        assert_eq!(handler.format(), RepositoryFormat::Generic);
    }

    #[test]
    fn test_generic_handler_default() {
        let handler = GenericHandler;
        assert_eq!(handler.format(), RepositoryFormat::Generic);
    }

    #[test]
    fn test_generic_handler_format_key() {
        let handler = GenericHandler::new();
        assert_eq!(handler.format_key(), "generic");
    }

    #[test]
    fn test_generic_handler_is_not_wasm_plugin() {
        let handler = GenericHandler::new();
        assert!(!handler.is_wasm_plugin());
    }

    #[tokio::test]
    async fn test_parse_metadata_returns_path() {
        let handler = GenericHandler::new();
        let content = Bytes::from_static(b"some binary data");
        let metadata = handler
            .parse_metadata("/path/to/file.bin", &content)
            .await
            .unwrap();
        assert_eq!(metadata["path"], "/path/to/file.bin");
    }

    #[tokio::test]
    async fn test_parse_metadata_different_paths() {
        let handler = GenericHandler::new();
        let content = Bytes::from_static(b"data");

        let m1 = handler.parse_metadata("file.txt", &content).await.unwrap();
        assert_eq!(m1["path"], "file.txt");

        let m2 = handler
            .parse_metadata("/a/b/c/d.tar.gz", &content)
            .await
            .unwrap();
        assert_eq!(m2["path"], "/a/b/c/d.tar.gz");
    }

    #[tokio::test]
    async fn test_parse_metadata_empty_path() {
        let handler = GenericHandler::new();
        let content = Bytes::from_static(b"data");
        let metadata = handler.parse_metadata("", &content).await.unwrap();
        assert_eq!(metadata["path"], "");
    }

    #[tokio::test]
    async fn test_parse_metadata_ignores_content() {
        let handler = GenericHandler::new();
        let content1 = Bytes::from_static(b"content A");
        let content2 = Bytes::from_static(b"content B");
        let m1 = handler.parse_metadata("file.bin", &content1).await.unwrap();
        let m2 = handler.parse_metadata("file.bin", &content2).await.unwrap();
        // Metadata should be the same regardless of content
        assert_eq!(m1, m2);
    }

    #[tokio::test]
    async fn test_validate_accepts_anything() {
        let handler = GenericHandler::new();
        // Generic format should accept any content
        assert!(handler
            .validate("file.bin", &Bytes::from_static(b""))
            .await
            .is_ok());
        assert!(handler
            .validate("file.bin", &Bytes::from_static(b"data"))
            .await
            .is_ok());
        assert!(handler.validate("", &Bytes::new()).await.is_ok());
    }

    #[tokio::test]
    async fn test_validate_binary_content() {
        let handler = GenericHandler::new();
        let binary = Bytes::from(vec![0u8, 1, 2, 255, 254, 253]);
        assert!(handler.validate("binary.bin", &binary).await.is_ok());
    }

    #[tokio::test]
    async fn test_generate_index_returns_none() {
        let handler = GenericHandler::new();
        let result = handler.generate_index().await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_parse_metadata_with_unicode_path() {
        let handler = GenericHandler::new();
        let content = Bytes::from_static(b"data");
        let metadata = handler
            .parse_metadata("/path/to/file-\u{00e9}\u{00e8}.bin", &content)
            .await
            .unwrap();
        assert_eq!(metadata["path"], "/path/to/file-\u{00e9}\u{00e8}.bin");
    }

    #[tokio::test]
    async fn test_parse_metadata_with_large_content() {
        let handler = GenericHandler::new();
        let large_content = Bytes::from(vec![0u8; 10_000]);
        let metadata = handler
            .parse_metadata("large.bin", &large_content)
            .await
            .unwrap();
        assert_eq!(metadata["path"], "large.bin");
    }
}
