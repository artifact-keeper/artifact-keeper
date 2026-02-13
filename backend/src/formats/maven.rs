//! Maven format handler.
//!
//! Implements Maven 2 repository layout and metadata parsing.

use async_trait::async_trait;
use bytes::Bytes;
use quick_xml::de::from_str;
use serde::{Deserialize, Serialize};

use crate::error::{AppError, Result};
use crate::formats::FormatHandler;
use crate::models::repository::RepositoryFormat;

/// Maven format handler
pub struct MavenHandler;

impl MavenHandler {
    pub fn new() -> Self {
        Self
    }

    /// Parse Maven coordinates from path
    /// Path format: groupId/artifactId/version/artifactId-version[-classifier].extension
    pub fn parse_coordinates(path: &str) -> Result<MavenCoordinates> {
        let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();

        if parts.len() < 4 {
            return Err(AppError::Validation(
                "Invalid Maven path: expected groupId/artifactId/version/filename".to_string(),
            ));
        }

        let filename = parts[parts.len() - 1];
        let version = parts[parts.len() - 2];
        let artifact_id = parts[parts.len() - 3];
        let group_id = parts[..parts.len() - 3].join(".");

        // Parse filename to extract classifier and extension
        let (classifier, extension) = Self::parse_filename(filename, artifact_id, version)?;

        Ok(MavenCoordinates {
            group_id,
            artifact_id: artifact_id.to_string(),
            version: version.to_string(),
            classifier,
            extension,
        })
    }

    /// Parse filename to extract classifier and extension
    fn parse_filename(
        filename: &str,
        artifact_id: &str,
        version: &str,
    ) -> Result<(Option<String>, String)> {
        let expected_prefix = format!("{}-{}", artifact_id, version);

        // For SNAPSHOT versions, Maven resolves the filename to a timestamp like:
        // artifact-1.0.0-20260211.124623-1.jar instead of artifact-1.0.0-SNAPSHOT.jar
        // Accept either the exact version or the timestamp-resolved form.
        let snapshot_prefix = version
            .strip_suffix("-SNAPSHOT")
            .map(|base_version| format!("{}-{}", artifact_id, base_version));

        let remainder = if filename.starts_with(&expected_prefix) {
            &filename[expected_prefix.len()..]
        } else if let Some(ref snap) = snapshot_prefix {
            if filename.starts_with(snap) {
                &filename[snap.len()..]
            } else {
                // Could be metadata file
                if filename == "maven-metadata.xml"
                    || filename.ends_with(".md5")
                    || filename.ends_with(".sha1")
                    || filename.ends_with(".sha256")
                {
                    return Ok((None, filename.to_string()));
                }
                return Err(AppError::Validation(format!(
                    "Invalid Maven filename: expected to start with {}",
                    expected_prefix
                )));
            }
        } else {
            // Could be metadata file
            if filename == "maven-metadata.xml"
                || filename.ends_with(".md5")
                || filename.ends_with(".sha1")
                || filename.ends_with(".sha256")
            {
                return Ok((None, filename.to_string()));
            }
            return Err(AppError::Validation(format!(
                "Invalid Maven filename: expected to start with {}",
                expected_prefix
            )));
        };

        if remainder.is_empty() {
            return Err(AppError::Validation(
                "Invalid Maven filename: missing extension".to_string(),
            ));
        }

        // Check for classifier: -classifier.ext
        if let Some(rest) = remainder.strip_prefix('-') {
            if let Some(dot_pos) = rest.rfind('.') {
                let classifier = &rest[..dot_pos];
                let extension = &rest[dot_pos + 1..];
                return Ok((Some(classifier.to_string()), extension.to_string()));
            }
        }

        // No classifier: .ext
        if let Some(ext) = remainder.strip_prefix('.') {
            return Ok((None, ext.to_string()));
        }

        Err(AppError::Validation(
            "Invalid Maven filename format".to_string(),
        ))
    }

    /// Check if this is a POM file
    pub fn is_pom(path: &str) -> bool {
        path.ends_with(".pom") || path.ends_with("/pom.xml")
    }

    /// Check if this is a metadata file
    pub fn is_metadata(path: &str) -> bool {
        path.ends_with("maven-metadata.xml")
    }

    /// Parse POM file
    pub fn parse_pom(content: &[u8]) -> Result<PomProject> {
        let content_str = std::str::from_utf8(content)
            .map_err(|e| AppError::Validation(format!("Invalid UTF-8 in POM: {}", e)))?;

        from_str(content_str).map_err(|e| AppError::Validation(format!("Invalid POM XML: {}", e)))
    }
}

impl Default for MavenHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl FormatHandler for MavenHandler {
    fn format(&self) -> RepositoryFormat {
        RepositoryFormat::Maven
    }

    async fn parse_metadata(&self, path: &str, content: &Bytes) -> Result<serde_json::Value> {
        let coords = Self::parse_coordinates(path)?;

        let mut metadata = serde_json::json!({
            "groupId": coords.group_id,
            "artifactId": coords.artifact_id,
            "version": coords.version,
            "extension": coords.extension,
        });

        if let Some(classifier) = &coords.classifier {
            metadata["classifier"] = serde_json::Value::String(classifier.clone());
        }

        // If it's a POM, parse additional metadata
        if Self::is_pom(path) {
            if let Ok(pom) = Self::parse_pom(content) {
                if let Some(name) = pom.name {
                    metadata["name"] = serde_json::Value::String(name);
                }
                if let Some(description) = pom.description {
                    metadata["description"] = serde_json::Value::String(description);
                }
                if let Some(url) = pom.url {
                    metadata["url"] = serde_json::Value::String(url);
                }
                if let Some(deps) = pom.dependencies {
                    metadata["dependencies"] = serde_json::to_value(deps.dependency)
                        .unwrap_or(serde_json::Value::Array(vec![]));
                }
            }
        }

        Ok(metadata)
    }

    async fn validate(&self, path: &str, content: &Bytes) -> Result<()> {
        // Validate coordinates can be parsed
        let _coords = Self::parse_coordinates(path)?;

        // Validate POM if applicable
        if Self::is_pom(path) {
            let _pom = Self::parse_pom(content)?;
        }

        Ok(())
    }

    async fn generate_index(&self) -> Result<Option<Vec<(String, Bytes)>>> {
        // Maven uses maven-metadata.xml which is generated per artifact
        // This would typically be generated on demand based on DB state
        Ok(None)
    }
}

/// Maven coordinates (GAV)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MavenCoordinates {
    pub group_id: String,
    pub artifact_id: String,
    pub version: String,
    pub classifier: Option<String>,
    pub extension: String,
}

impl MavenCoordinates {
    /// Get the repository path for these coordinates
    pub fn to_path(&self, filename: &str) -> String {
        format!(
            "{}/{}/{}/{}",
            self.group_id.replace('.', "/"),
            self.artifact_id,
            self.version,
            filename
        )
    }

    /// Get the standard filename for these coordinates
    pub fn filename(&self) -> String {
        match &self.classifier {
            Some(c) => format!(
                "{}-{}-{}.{}",
                self.artifact_id, self.version, c, self.extension
            ),
            None => format!("{}-{}.{}", self.artifact_id, self.version, self.extension),
        }
    }
}

/// POM project model (simplified)
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PomProject {
    pub model_version: Option<String>,
    pub group_id: Option<String>,
    pub artifact_id: Option<String>,
    pub version: Option<String>,
    pub packaging: Option<String>,
    pub name: Option<String>,
    pub description: Option<String>,
    pub url: Option<String>,
    pub parent: Option<PomParent>,
    pub dependencies: Option<PomDependencies>,
    pub properties: Option<PomProperties>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PomParent {
    pub group_id: Option<String>,
    pub artifact_id: Option<String>,
    pub version: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PomDependencies {
    #[serde(default)]
    pub dependency: Vec<PomDependency>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PomDependency {
    pub group_id: String,
    pub artifact_id: String,
    pub version: Option<String>,
    pub scope: Option<String>,
    #[serde(rename = "type")]
    pub dep_type: Option<String>,
    pub classifier: Option<String>,
    pub optional: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct PomProperties {
    #[serde(flatten)]
    pub properties: std::collections::HashMap<String, String>,
}

/// Generate maven-metadata.xml content
pub fn generate_metadata_xml(
    group_id: &str,
    artifact_id: &str,
    versions: &[String],
    latest: &str,
    release: Option<&str>,
) -> String {
    let mut versions_xml = String::new();
    for v in versions {
        versions_xml.push_str(&format!("      <version>{}</version>\n", v));
    }

    let release_line = match release {
        Some(r) => format!("    <release>{}</release>\n", r),
        None => String::new(),
    };

    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<metadata>
  <groupId>{}</groupId>
  <artifactId>{}</artifactId>
  <versioning>
    <latest>{}</latest>
{}    <versions>
{}    </versions>
    <lastUpdated>{}</lastUpdated>
  </versioning>
</metadata>
"#,
        group_id,
        artifact_id,
        latest,
        release_line,
        versions_xml,
        chrono::Utc::now().format("%Y%m%d%H%M%S")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_coordinates() {
        let coords = MavenHandler::parse_coordinates(
            "org/apache/maven/maven-core/3.8.1/maven-core-3.8.1.jar",
        )
        .unwrap();
        assert_eq!(coords.group_id, "org.apache.maven");
        assert_eq!(coords.artifact_id, "maven-core");
        assert_eq!(coords.version, "3.8.1");
        assert_eq!(coords.classifier, None);
        assert_eq!(coords.extension, "jar");
    }

    #[test]
    fn test_parse_coordinates_with_classifier() {
        let coords = MavenHandler::parse_coordinates(
            "org/apache/maven/maven-core/3.8.1/maven-core-3.8.1-sources.jar",
        )
        .unwrap();
        assert_eq!(coords.group_id, "org.apache.maven");
        assert_eq!(coords.artifact_id, "maven-core");
        assert_eq!(coords.version, "3.8.1");
        assert_eq!(coords.classifier, Some("sources".to_string()));
        assert_eq!(coords.extension, "jar");
    }

    #[test]
    fn test_parse_pom_coordinates() {
        let coords =
            MavenHandler::parse_coordinates("com/example/mylib/1.0.0/mylib-1.0.0.pom").unwrap();
        assert_eq!(coords.group_id, "com.example");
        assert_eq!(coords.artifact_id, "mylib");
        assert_eq!(coords.version, "1.0.0");
        assert_eq!(coords.extension, "pom");
    }

    #[test]
    fn test_coordinates_to_path() {
        let coords = MavenCoordinates {
            group_id: "com.example".to_string(),
            artifact_id: "mylib".to_string(),
            version: "1.0.0".to_string(),
            classifier: None,
            extension: "jar".to_string(),
        };
        assert_eq!(
            coords.to_path("mylib-1.0.0.jar"),
            "com/example/mylib/1.0.0/mylib-1.0.0.jar"
        );
    }

    #[test]
    fn test_parse_snapshot_coordinates() {
        // SNAPSHOT version with exact -SNAPSHOT filename
        let coords = MavenHandler::parse_coordinates(
            "com/example/test/1.0.0-SNAPSHOT/test-1.0.0-SNAPSHOT.jar",
        )
        .unwrap();
        assert_eq!(coords.group_id, "com.example");
        assert_eq!(coords.artifact_id, "test");
        assert_eq!(coords.version, "1.0.0-SNAPSHOT");
        assert_eq!(coords.classifier, None);
        assert_eq!(coords.extension, "jar");
    }

    #[test]
    fn test_parse_snapshot_timestamp_coordinates() {
        // SNAPSHOT version with timestamp-resolved filename (Maven deploy format)
        let coords = MavenHandler::parse_coordinates(
            "com/example/test/1.0.0-SNAPSHOT/test-1.0.0-20260211.124623-1.jar",
        )
        .unwrap();
        assert_eq!(coords.group_id, "com.example");
        assert_eq!(coords.artifact_id, "test");
        assert_eq!(coords.version, "1.0.0-SNAPSHOT");
        assert_eq!(coords.extension, "jar");
    }

    #[test]
    fn test_parse_snapshot_timestamp_with_classifier() {
        let coords = MavenHandler::parse_coordinates(
            "com/example/test/1.2.3-SNAPSHOT/test-1.2.3-20260211.124623-1-sources.jar",
        )
        .unwrap();
        assert_eq!(coords.artifact_id, "test");
        assert_eq!(coords.version, "1.2.3-SNAPSHOT");
        assert_eq!(coords.extension, "jar");
    }

    #[test]
    fn test_parse_snapshot_pom() {
        let coords = MavenHandler::parse_coordinates(
            "com/example/test/1.0.0-SNAPSHOT/test-1.0.0-20260211.124623-1.pom",
        )
        .unwrap();
        assert_eq!(coords.artifact_id, "test");
        assert_eq!(coords.version, "1.0.0-SNAPSHOT");
        assert_eq!(coords.extension, "pom");
    }

    #[test]
    fn test_parse_snapshot_metadata() {
        // maven-metadata.xml in a SNAPSHOT version directory should still work
        let coords =
            MavenHandler::parse_coordinates("com/example/test/1.0.0-SNAPSHOT/maven-metadata.xml")
                .unwrap();
        assert_eq!(coords.artifact_id, "test");
        assert_eq!(coords.version, "1.0.0-SNAPSHOT");
        assert_eq!(coords.extension, "maven-metadata.xml");
    }

    #[test]
    fn test_generate_metadata() {
        let xml = generate_metadata_xml(
            "com.example",
            "mylib",
            &["1.0.0".to_string(), "1.1.0".to_string()],
            "1.1.0",
            Some("1.1.0"),
        );
        assert!(xml.contains("<groupId>com.example</groupId>"));
        assert!(xml.contains("<artifactId>mylib</artifactId>"));
        assert!(xml.contains("<latest>1.1.0</latest>"));
        assert!(xml.contains("<release>1.1.0</release>"));
    }
}
