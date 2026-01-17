//! Plugin Template for Artifact Keeper Format Handler
//!
//! This template provides a starting point for creating custom format handler plugins.
//! Implement the required functions to handle your artifact format.

// Generate bindings from the WIT interface
wit_bindgen::generate!({
    world: "format-plugin",
    path: "wit/format-plugin.wit",
});

use exports::artifact_keeper::format::handler::{Guest, Metadata, ValidationError};

/// The format handler implementation.
struct MyFormatHandler;

impl Guest for MyFormatHandler {
    /// Returns the format key this handler supports.
    /// This must match the `format.key` value in plugin.toml.
    fn format_key() -> String {
        "my-format".to_string()
    }

    /// Parse metadata from artifact content.
    ///
    /// This function is called when an artifact is uploaded to extract
    /// format-specific metadata.
    ///
    /// # Arguments
    /// * `path` - The artifact path within the repository (e.g., "com/example/lib/1.0.0/lib-1.0.0.myf")
    /// * `data` - The raw artifact content bytes
    ///
    /// # Returns
    /// * `Ok(Metadata)` - Successfully parsed metadata
    /// * `Err(String)` - Parse failed with error description
    fn parse_metadata(path: String, data: Vec<u8>) -> Result<Metadata, String> {
        // TODO: Implement your metadata parsing logic here
        //
        // Example: Parse version from filename
        let version = extract_version_from_path(&path);

        // Example: Detect content type
        let content_type = detect_content_type(&path, &data);

        Ok(Metadata {
            path,
            version,
            content_type,
            size_bytes: data.len() as u64,
            checksum_sha256: None, // Host will calculate if not provided
        })
    }

    /// Validate artifact before storage.
    ///
    /// This function is called to verify the artifact is valid for this format.
    /// Return an error if the artifact should be rejected.
    ///
    /// # Arguments
    /// * `path` - The artifact path within the repository
    /// * `data` - The raw artifact content bytes
    ///
    /// # Returns
    /// * `Ok(())` - Artifact is valid
    /// * `Err(String)` - Artifact is invalid with error description
    fn validate(path: String, data: Vec<u8>) -> Result<(), String> {
        // TODO: Implement your validation logic here
        //
        // Example validations:
        // - Check file extension matches expected format
        // - Verify file header/magic bytes
        // - Parse and validate content structure
        // - Check required fields are present

        // Basic validation: check that data is not empty
        if data.is_empty() {
            return Err("Artifact cannot be empty".to_string());
        }

        // Check file extension
        if !path.ends_with(".myf") && !path.ends_with(".myformat") {
            return Err(format!(
                "Invalid file extension for my-format: {}",
                path
            ));
        }

        Ok(())
    }

    /// Generate index files for repository.
    ///
    /// This function is called to generate format-specific index/metadata files.
    /// For example, Maven uses maven-metadata.xml, npm uses package.json index.
    ///
    /// # Arguments
    /// * `artifacts` - List of artifact metadata in the repository
    ///
    /// # Returns
    /// * `Ok(Some(files))` - List of (path, content) tuples for index files
    /// * `Ok(None)` - No index files needed for this format
    /// * `Err(String)` - Index generation failed
    fn generate_index(
        artifacts: Vec<Metadata>,
    ) -> Result<Option<Vec<(String, Vec<u8>)>>, String> {
        // TODO: Implement index generation if your format needs it
        //
        // Example: Generate a simple JSON index
        // let index = serde_json::to_vec(&artifacts).map_err(|e| e.to_string())?;
        // Ok(Some(vec![("index.json".to_string(), index)]))

        // Return None if no index files are needed
        Ok(None)
    }
}

// Export the handler implementation
export!(MyFormatHandler);

// Helper functions

/// Extract version from artifact path.
/// Override this for your format's versioning scheme.
fn extract_version_from_path(path: &str) -> Option<String> {
    // Example: Extract version from path like "group/artifact/1.0.0/file.ext"
    let parts: Vec<&str> = path.split('/').collect();
    if parts.len() >= 3 {
        // Assume version is the second-to-last directory component
        let potential_version = parts[parts.len() - 2];
        // Basic version pattern check
        if potential_version.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false) {
            return Some(potential_version.to_string());
        }
    }
    None
}

/// Detect content type from path and data.
/// Override this for your format's content types.
fn detect_content_type(path: &str, _data: &[u8]) -> String {
    if path.ends_with(".myf") || path.ends_with(".myformat") {
        "application/x-my-format".to_string()
    } else {
        "application/octet-stream".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_key() {
        assert_eq!(MyFormatHandler::format_key(), "my-format");
    }

    #[test]
    fn test_parse_metadata() {
        let path = "com/example/lib/1.0.0/lib-1.0.0.myf".to_string();
        let data = b"test content".to_vec();

        let result = MyFormatHandler::parse_metadata(path.clone(), data.clone());
        assert!(result.is_ok());

        let metadata = result.unwrap();
        assert_eq!(metadata.path, path);
        assert_eq!(metadata.version, Some("1.0.0".to_string()));
        assert_eq!(metadata.size_bytes, data.len() as u64);
    }

    #[test]
    fn test_validate_empty_data() {
        let result = MyFormatHandler::validate("test.myf".to_string(), vec![]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("empty"));
    }

    #[test]
    fn test_validate_valid_file() {
        let result = MyFormatHandler::validate("test.myf".to_string(), b"content".to_vec());
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_wrong_extension() {
        let result = MyFormatHandler::validate("test.txt".to_string(), b"content".to_vec());
        assert!(result.is_err());
    }
}
