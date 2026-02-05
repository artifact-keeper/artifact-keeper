//! Sonatype Nexus Repository REST API client for migration.
//!
//! Supports Nexus 3.x Community/Pro editions. Handles the Nexus REST API
//! for listing repositories, components, assets, and downloading artifacts.

use reqwest::Client;
use serde::Deserialize;
use std::time::Duration;

use crate::services::artifactory_client::{
    AqlRange, AqlResponse, AqlResult, ArtifactoryError, PropertiesResponse, RepositoryListItem,
    SystemVersionResponse,
};

/// Nexus authentication credentials
#[derive(Debug, Clone)]
pub struct NexusAuth {
    pub username: String,
    pub password: String,
}

/// Nexus client configuration
#[derive(Debug, Clone)]
pub struct NexusClientConfig {
    pub base_url: String,
    pub auth: NexusAuth,
    pub timeout_secs: u64,
    pub throttle_delay_ms: u64,
}

impl Default for NexusClientConfig {
    fn default() -> Self {
        Self {
            base_url: String::new(),
            auth: NexusAuth {
                username: String::new(),
                password: String::new(),
            },
            timeout_secs: 30,
            throttle_delay_ms: 100,
        }
    }
}

/// Nexus REST API client
pub struct NexusClient {
    client: Client,
    config: NexusClientConfig,
}

// --- Nexus API response types ---

#[derive(Debug, Deserialize)]
pub struct NexusStatusResponse {
    pub edition: Option<String>,
    pub version: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct NexusRepository {
    pub name: String,
    pub format: String,
    #[serde(rename = "type")]
    pub repo_type: String,
    pub url: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct NexusComponentsResponse {
    pub items: Vec<NexusComponent>,
    #[serde(rename = "continuationToken")]
    pub continuation_token: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct NexusComponent {
    pub id: String,
    pub repository: String,
    pub format: String,
    pub group: Option<String>,
    pub name: String,
    pub version: Option<String>,
    pub assets: Vec<NexusAsset>,
}

#[derive(Debug, Deserialize)]
pub struct NexusAsset {
    pub id: String,
    pub path: Option<String>,
    #[serde(rename = "downloadUrl")]
    pub download_url: Option<String>,
    pub checksum: Option<NexusChecksum>,
    #[serde(rename = "contentType")]
    pub content_type: Option<String>,
    #[serde(rename = "fileSize")]
    pub file_size: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct NexusChecksum {
    pub sha256: Option<String>,
    pub sha1: Option<String>,
    pub md5: Option<String>,
}

impl NexusClient {
    /// Create a new Nexus client
    pub fn new(config: NexusClientConfig) -> Result<Self, ArtifactoryError> {
        let client = Client::builder()
            .timeout(Duration::from_secs(config.timeout_secs))
            .build()?;

        Ok(Self { client, config })
    }

    /// Build an authenticated GET request
    async fn get<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T, ArtifactoryError> {
        if self.config.throttle_delay_ms > 0 {
            tokio::time::sleep(Duration::from_millis(self.config.throttle_delay_ms)).await;
        }

        let url = format!("{}{}", self.config.base_url, path);
        let response = self
            .client
            .get(&url)
            .basic_auth(&self.config.auth.username, Some(&self.config.auth.password))
            .send()
            .await?;

        let status = response.status();
        if status.is_success() {
            Ok(response.json::<T>().await?)
        } else if status.as_u16() == 401 || status.as_u16() == 403 {
            Err(ArtifactoryError::AuthError(format!(
                "Nexus authentication failed: {}",
                status
            )))
        } else if status.as_u16() == 404 {
            Err(ArtifactoryError::NotFound("Resource not found".into()))
        } else {
            let message = response.text().await.unwrap_or_default();
            Err(ArtifactoryError::ApiError {
                status: status.as_u16(),
                message,
            })
        }
    }

    /// Check if Nexus is reachable
    pub async fn ping(&self) -> Result<bool, ArtifactoryError> {
        let url = format!("{}/service/rest/v1/status/writable", self.config.base_url);
        let response = self
            .client
            .get(&url)
            .basic_auth(&self.config.auth.username, Some(&self.config.auth.password))
            .send()
            .await?;
        Ok(response.status().is_success())
    }

    /// Get Nexus version — returns in the same format as Artifactory for compatibility
    pub async fn get_version(&self) -> Result<SystemVersionResponse, ArtifactoryError> {
        let status: NexusStatusResponse =
            self.get("/service/rest/v1/status")
                .await
                .unwrap_or(NexusStatusResponse {
                    edition: Some("Unknown".into()),
                    version: Some("Unknown".into()),
                });

        Ok(SystemVersionResponse {
            version: status.version.unwrap_or_else(|| "unknown".into()),
            revision: None,
            addons: None,
            license: status.edition,
        })
    }

    /// List all repositories — returns in the same format as Artifactory for compatibility
    pub async fn list_repositories(&self) -> Result<Vec<RepositoryListItem>, ArtifactoryError> {
        let repos: Vec<NexusRepository> = self.get("/service/rest/v1/repositories").await?;

        Ok(repos
            .into_iter()
            .map(|r| RepositoryListItem {
                key: r.name,
                repo_type: r.repo_type,
                package_type: r.format,
                url: r.url,
                description: None,
            })
            .collect())
    }

    /// List artifacts (components + assets) with pagination.
    /// Returns data in the same AqlResponse format as the Artifactory client
    /// so the migration worker can process either source.
    pub async fn list_artifacts(
        &self,
        repo_name: &str,
        offset: i64,
        limit: i64,
    ) -> Result<AqlResponse, ArtifactoryError> {
        // Nexus uses continuation tokens, not offset/limit.
        // We'll accumulate results up to the offset + limit.
        let mut all_results = Vec::new();
        let mut token: Option<String> = None;
        let target_end = (offset + limit) as usize;

        loop {
            let path = match &token {
                Some(t) => format!(
                    "/service/rest/v1/components?repository={}&continuationToken={}",
                    repo_name, t
                ),
                None => format!("/service/rest/v1/components?repository={}", repo_name),
            };

            let page: NexusComponentsResponse = self.get(&path).await?;

            for component in &page.items {
                for asset in &component.assets {
                    let path_str = asset.path.clone().unwrap_or_else(|| {
                        format!(
                            "{}/{}",
                            component.name,
                            component.version.as_deref().unwrap_or("0")
                        )
                    });
                    let (dir, name) = match path_str.rsplit_once('/') {
                        Some((d, n)) => (d.to_string(), n.to_string()),
                        None => (".".to_string(), path_str),
                    };

                    all_results.push(AqlResult {
                        repo: repo_name.to_string(),
                        path: dir,
                        name,
                        size: asset.file_size,
                        created: None,
                        modified: None,
                        sha256: asset.checksum.as_ref().and_then(|c| c.sha256.clone()),
                        actual_sha1: asset.checksum.as_ref().and_then(|c| c.sha1.clone()),
                    });
                }
            }

            // Stop if we have enough or no more pages
            if all_results.len() >= target_end || page.continuation_token.is_none() {
                break;
            }
            token = page.continuation_token;
        }

        let total = all_results.len() as i64;
        let start = offset as usize;
        let end = std::cmp::min(target_end, all_results.len());
        let page_results = if start < all_results.len() {
            all_results[start..end].to_vec()
        } else {
            vec![]
        };

        Ok(AqlResponse {
            results: page_results,
            range: AqlRange {
                start_pos: offset,
                end_pos: offset + limit,
                total,
            },
        })
    }

    /// Download an artifact by repository name and path
    pub async fn download_artifact(
        &self,
        repo_name: &str,
        path: &str,
    ) -> Result<bytes::Bytes, ArtifactoryError> {
        let url = format!("{}/repository/{}/{}", self.config.base_url, repo_name, path);
        let response = self
            .client
            .get(&url)
            .basic_auth(&self.config.auth.username, Some(&self.config.auth.password))
            .send()
            .await?;

        let status = response.status();
        if status.is_success() {
            Ok(response.bytes().await?)
        } else if status.as_u16() == 404 {
            Err(ArtifactoryError::NotFound(format!(
                "Artifact not found: {}/{}",
                repo_name, path
            )))
        } else {
            Err(ArtifactoryError::ApiError {
                status: status.as_u16(),
                message: "Failed to download artifact".into(),
            })
        }
    }
}

// Implement SourceRegistry trait for migration compatibility
#[async_trait::async_trait]
impl crate::services::source_registry::SourceRegistry for NexusClient {
    async fn ping(&self) -> Result<bool, ArtifactoryError> {
        self.ping().await
    }

    async fn get_version(&self) -> Result<SystemVersionResponse, ArtifactoryError> {
        self.get_version().await
    }

    async fn list_repositories(&self) -> Result<Vec<RepositoryListItem>, ArtifactoryError> {
        self.list_repositories().await
    }

    async fn list_artifacts(
        &self,
        repo_key: &str,
        offset: i64,
        limit: i64,
    ) -> Result<AqlResponse, ArtifactoryError> {
        self.list_artifacts(repo_key, offset, limit).await
    }

    async fn download_artifact(
        &self,
        repo_key: &str,
        path: &str,
    ) -> Result<bytes::Bytes, ArtifactoryError> {
        self.download_artifact(repo_key, path).await
    }

    async fn get_properties(
        &self,
        _repo_key: &str,
        _path: &str,
    ) -> Result<PropertiesResponse, ArtifactoryError> {
        // Nexus doesn't have the same properties API as Artifactory
        Ok(PropertiesResponse {
            properties: None,
            uri: None,
        })
    }

    fn source_type(&self) -> &'static str {
        "nexus"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nexus_config_default() {
        let config = NexusClientConfig::default();
        assert_eq!(config.timeout_secs, 30);
        assert_eq!(config.throttle_delay_ms, 100);
    }
}
