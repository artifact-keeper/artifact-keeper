//! Echo Format Plugin for Artifact Keeper
//!
//! This is a sample plugin that demonstrates the format handler interface.
//! It accepts any file and echoes back its metadata, serving as a reference
//! implementation for plugin developers.

// Generate bindings from the WIT interface
wit_bindgen::generate!({
    world: "format-plugin",
    path: "wit/format-plugin.wit",
});

use exports::artifact_keeper::format::handler::{Guest, Metadata};

/// The echo format handler implementation.
/// This plugin accepts any artifact and returns basic metadata.
struct EchoFormatHandler;

impl Guest for EchoFormatHandler {
    /// Returns the format key: "echo"
    fn format_key() -> String {
        "echo".to_string()
    }

    /// Parse metadata from artifact content.
    /// For the echo format, we extract what we can from the path and data.
    fn parse_metadata(path: String, data: Vec<u8>) -> Result<Metadata, String> {
        // Try to extract version from path
        let version = extract_version_from_path(&path);

        // Detect content type from extension
        let content_type = detect_content_type(&path);

        // Calculate a simple checksum (optional - host will calculate SHA-256 if needed)
        let checksum = calculate_simple_checksum(&data);

        Ok(Metadata {
            path,
            version,
            content_type,
            size_bytes: data.len() as u64,
            checksum_sha256: Some(checksum),
        })
    }

    /// Validate artifact before storage.
    /// The echo format accepts any non-empty artifact.
    fn validate(path: String, data: Vec<u8>) -> Result<(), String> {
        // Accept any non-empty file
        if data.is_empty() {
            return Err("Echo format requires non-empty content".to_string());
        }

        // Validate path is not empty
        if path.is_empty() {
            return Err("Artifact path cannot be empty".to_string());
        }

        // All other content is valid
        Ok(())
    }

    /// Generate index files for repository.
    /// Creates a simple JSON index of all artifacts.
    fn generate_index(
        artifacts: Vec<Metadata>,
    ) -> Result<Option<Vec<(String, Vec<u8>)>>, String> {
        if artifacts.is_empty() {
            return Ok(None);
        }

        // Build a simple JSON index
        let mut index = String::from("{\n  \"artifacts\": [\n");

        for (i, artifact) in artifacts.iter().enumerate() {
            index.push_str("    {\n");
            index.push_str(&format!("      \"path\": \"{}\",\n", escape_json(&artifact.path)));

            if let Some(ref version) = artifact.version {
                index.push_str(&format!("      \"version\": \"{}\",\n", escape_json(version)));
            }

            index.push_str(&format!("      \"content_type\": \"{}\",\n", escape_json(&artifact.content_type)));
            index.push_str(&format!("      \"size_bytes\": {}\n", artifact.size_bytes));
            index.push_str("    }");

            if i < artifacts.len() - 1 {
                index.push(',');
            }
            index.push('\n');
        }

        index.push_str("  ],\n");
        index.push_str(&format!("  \"total_count\": {},\n", artifacts.len()));
        index.push_str(&format!("  \"total_size_bytes\": {}\n",
            artifacts.iter().map(|a| a.size_bytes).sum::<u64>()));
        index.push_str("}\n");

        Ok(Some(vec![
            ("echo-index.json".to_string(), index.into_bytes())
        ]))
    }
}

// Export the handler implementation
export!(EchoFormatHandler);

// Helper functions

/// Extract version from artifact path.
/// Looks for semantic version patterns in path components.
fn extract_version_from_path(path: &str) -> Option<String> {
    let parts: Vec<&str> = path.split('/').collect();

    // Look for version-like patterns in path components
    for part in parts.iter().rev() {
        // Check if this looks like a version (starts with digit or 'v')
        if is_version_like(part) {
            return Some(part.to_string());
        }
    }

    // Try to extract from filename (e.g., "lib-1.0.0.jar")
    if let Some(filename) = parts.last() {
        if let Some(version) = extract_version_from_filename(filename) {
            return Some(version);
        }
    }

    None
}

/// Check if a string looks like a version number.
fn is_version_like(s: &str) -> bool {
    let s = s.strip_prefix('v').unwrap_or(s);

    // Must start with a digit
    if !s.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false) {
        return false;
    }

    // Must contain at least one dot (e.g., 1.0)
    if !s.contains('.') {
        return false;
    }

    // All characters should be digits, dots, or common version suffixes
    s.chars().all(|c| c.is_ascii_digit() || c == '.' || c == '-' || c.is_ascii_alphabetic())
}

/// Extract version from filename like "artifact-1.0.0.ext"
fn extract_version_from_filename(filename: &str) -> Option<String> {
    // Remove extension
    let name = filename.rsplit_once('.').map(|(n, _)| n).unwrap_or(filename);

    // Look for version pattern after last hyphen
    if let Some(idx) = name.rfind('-') {
        let potential_version = &name[idx + 1..];
        if is_version_like(potential_version) {
            return Some(potential_version.to_string());
        }
    }

    None
}

/// Detect content type from file extension.
fn detect_content_type(path: &str) -> String {
    let ext = path.rsplit_once('.').map(|(_, e)| e.to_lowercase());

    match ext.as_deref() {
        Some("json") => "application/json",
        Some("xml") => "application/xml",
        Some("txt") => "text/plain",
        Some("html") | Some("htm") => "text/html",
        Some("css") => "text/css",
        Some("js") => "application/javascript",
        Some("jar") => "application/java-archive",
        Some("war") => "application/java-archive",
        Some("zip") => "application/zip",
        Some("gz") | Some("gzip") => "application/gzip",
        Some("tar") => "application/x-tar",
        Some("tgz") => "application/gzip",
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("pdf") => "application/pdf",
        Some("wasm") => "application/wasm",
        _ => "application/octet-stream",
    }.to_string()
}

/// Calculate a simple checksum for the data.
/// This is a placeholder - the host typically calculates SHA-256.
fn calculate_simple_checksum(data: &[u8]) -> String {
    // Simple FNV-1a hash for demonstration
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in data {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{:016x}", hash)
}

/// Escape special characters for JSON strings.
fn escape_json(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => result.push_str("\\\""),
            '\\' => result.push_str("\\\\"),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            c if c.is_control() => {
                result.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => result.push(c),
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_key() {
        assert_eq!(EchoFormatHandler::format_key(), "echo");
    }

    #[test]
    fn test_parse_metadata_simple() {
        let path = "test.txt".to_string();
        let data = b"Hello, World!".to_vec();

        let result = EchoFormatHandler::parse_metadata(path.clone(), data.clone());
        assert!(result.is_ok());

        let metadata = result.unwrap();
        assert_eq!(metadata.path, path);
        assert_eq!(metadata.content_type, "text/plain");
        assert_eq!(metadata.size_bytes, 13);
    }

    #[test]
    fn test_parse_metadata_with_version() {
        let path = "com/example/lib/1.2.3/lib-1.2.3.jar".to_string();
        let data = b"jar content".to_vec();

        let result = EchoFormatHandler::parse_metadata(path, data);
        assert!(result.is_ok());

        let metadata = result.unwrap();
        assert_eq!(metadata.version, Some("1.2.3".to_string()));
        assert_eq!(metadata.content_type, "application/java-archive");
    }

    #[test]
    fn test_validate_empty() {
        let result = EchoFormatHandler::validate("test.txt".to_string(), vec![]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("non-empty"));
    }

    #[test]
    fn test_validate_empty_path() {
        let result = EchoFormatHandler::validate("".to_string(), b"content".to_vec());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("path"));
    }

    #[test]
    fn test_validate_success() {
        let result = EchoFormatHandler::validate("test.txt".to_string(), b"content".to_vec());
        assert!(result.is_ok());
    }

    #[test]
    fn test_generate_index_empty() {
        let result = EchoFormatHandler::generate_index(vec![]);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_generate_index() {
        let artifacts = vec![
            Metadata {
                path: "test.txt".to_string(),
                version: Some("1.0.0".to_string()),
                content_type: "text/plain".to_string(),
                size_bytes: 100,
                checksum_sha256: None,
            },
        ];

        let result = EchoFormatHandler::generate_index(artifacts);
        assert!(result.is_ok());

        let files = result.unwrap();
        assert!(files.is_some());

        let files = files.unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].0, "echo-index.json");

        let content = String::from_utf8_lossy(&files[0].1);
        assert!(content.contains("\"path\": \"test.txt\""));
        assert!(content.contains("\"total_count\": 1"));
    }

    #[test]
    fn test_is_version_like() {
        assert!(is_version_like("1.0.0"));
        assert!(is_version_like("v1.2.3"));
        assert!(is_version_like("1.0.0-beta"));
        assert!(is_version_like("2.0.0-rc1"));
        assert!(!is_version_like("src"));
        assert!(!is_version_like("main"));
        assert!(!is_version_like("123")); // No dot
    }

    #[test]
    fn test_extract_version_from_filename() {
        assert_eq!(extract_version_from_filename("lib-1.0.0.jar"), Some("1.0.0".to_string()));
        assert_eq!(extract_version_from_filename("my-artifact-2.3.4-SNAPSHOT.war"), Some("2.3.4-SNAPSHOT".to_string()));
        assert_eq!(extract_version_from_filename("noversion.txt"), None);
    }

    #[test]
    fn test_detect_content_type() {
        assert_eq!(detect_content_type("test.json"), "application/json");
        assert_eq!(detect_content_type("test.jar"), "application/java-archive");
        assert_eq!(detect_content_type("test.unknown"), "application/octet-stream");
        assert_eq!(detect_content_type("path/to/file.wasm"), "application/wasm");
    }
}
