//! Integration tests for artifact registry backend.
//!
//! These tests require a running backend HTTP server.
//! Set the TEST_BASE_URL environment variable to specify the server URL.
//!
//! Example:
//! ```sh
//! export TEST_BASE_URL="http://127.0.0.1:9080"
//! cargo test --test integration_tests -- --ignored
//! ```
//!
//! Note: These tests are marked with #[ignore] because they require
//! a running HTTP server. In CI, run them separately with a service container.

#![allow(dead_code)]

use std::env;
use std::sync::Once;

use base64::Engine;
use reqwest::Client;
use serde_json::{json, Value};

static INIT: Once = Once::new();
static mut BASE_URL: String = String::new();
static mut ACCESS_TOKEN: String = String::new();

/// Test server configuration
struct TestServer {
    base_url: String,
    access_token: String,
}

impl TestServer {
    fn new() -> Self {
        let base_url = env::var("TEST_BASE_URL").unwrap_or_else(|_| "http://127.0.0.1:9080".into());
        let access_token = String::new();
        Self {
            base_url,
            access_token,
        }
    }

    async fn login(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::new();
        let resp = client
            .post(format!("{}/api/v1/auth/login", self.base_url))
            .json(&json!({
                "username": "admin",
                "password": "admin123"
            }))
            .send()
            .await?;

        let body: Value = resp.json().await?;
        self.access_token = body["access_token"]
            .as_str()
            .ok_or("No access token")?
            .to_string();
        Ok(())
    }

    fn auth_header(&self) -> String {
        format!("Bearer {}", self.access_token)
    }

    async fn create_repository(
        &self,
        key: &str,
        name: &str,
        format: &str,
    ) -> Result<Value, Box<dyn std::error::Error>> {
        let client = Client::new();
        let resp = client
            .post(format!("{}/api/v1/repositories", self.base_url))
            .header("Authorization", self.auth_header())
            .json(&json!({
                "key": key,
                "name": name,
                "format": format,
                "repo_type": "local",
                "is_public": true
            }))
            .send()
            .await?;

        if resp.status().is_success() {
            Ok(resp.json().await?)
        } else {
            let status = resp.status();
            let text = resp.text().await?;
            Err(format!("Failed to create repository: {} - {}", status, text).into())
        }
    }

    async fn create_private_repository(
        &self,
        key: &str,
        name: &str,
        format: &str,
    ) -> std::result::Result<Value, Box<dyn std::error::Error>> {
        let client = Client::new();
        let resp = client
            .post(format!("{}/api/v1/repositories", self.base_url))
            .header("Authorization", self.auth_header())
            .json(&json!({
                "key": key,
                "name": name,
                "format": format,
                "repo_type": "local",
                "is_public": false
            }))
            .send()
            .await?;

        if resp.status().is_success() {
            Ok(resp.json().await?)
        } else {
            let status = resp.status();
            let text = resp.text().await?;
            Err(format!("Failed to create repository: {} - {}", status, text).into())
        }
    }

    async fn create_user(
        &self,
        username: &str,
        email: &str,
        password: &str,
        is_admin: bool,
    ) -> Result<Value, Box<dyn std::error::Error>> {
        let client = Client::new();
        let resp = client
            .post(format!("{}/api/v1/users", self.base_url))
            .header("Authorization", self.auth_header())
            .json(&json!({
                "username": username,
                "email": email,
                "password": password,
                "display_name": username,
                "is_admin": is_admin
            }))
            .send()
            .await?;

        if resp.status().is_success() {
            Ok(resp.json().await?)
        } else {
            let status = resp.status();
            let text = resp.text().await?;
            Err(format!("Failed to create user: {} - {}", status, text).into())
        }
    }

    async fn get_oci_token(
        &self,
        username: &str,
        password: &str,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let client = Client::new();
        let token_resp: Value = client
            .get(format!("{}/v2/token", self.base_url))
            .basic_auth(username, Some(password))
            .send()
            .await?
            .json()
            .await?;

        token_resp["token"]
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| "No OCI token in response".into())
    }

    async fn upload_artifact(
        &self,
        repo_key: &str,
        path: &str,
        content: &[u8],
        content_type: &str,
    ) -> Result<Value, Box<dyn std::error::Error>> {
        let client = Client::new();
        let resp = client
            .put(format!(
                "{}/api/v1/repositories/{}/artifacts/{}",
                self.base_url, repo_key, path
            ))
            .header("Authorization", self.auth_header())
            .header("Content-Type", content_type)
            .body(content.to_vec())
            .send()
            .await?;

        if resp.status().is_success() {
            Ok(resp.json().await?)
        } else {
            let status = resp.status();
            let text = resp.text().await?;
            Err(format!("Failed to upload artifact: {} - {}", status, text).into())
        }
    }

    async fn download_artifact(
        &self,
        repo_key: &str,
        path: &str,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let client = Client::new();
        let resp = client
            .get(format!(
                "{}/api/v1/repositories/{}/download/{}",
                self.base_url, repo_key, path
            ))
            .header("Authorization", self.auth_header())
            .send()
            .await?;

        if resp.status().is_success() {
            Ok(resp.bytes().await?.to_vec())
        } else {
            let status = resp.status();
            let text = resp.text().await?;
            Err(format!("Failed to download artifact: {} - {}", status, text).into())
        }
    }

    async fn get_artifact_metadata(
        &self,
        repo_key: &str,
        path: &str,
    ) -> Result<Value, Box<dyn std::error::Error>> {
        let client = Client::new();
        let resp = client
            .get(format!(
                "{}/api/v1/repositories/{}/artifacts/{}",
                self.base_url, repo_key, path
            ))
            .header("Authorization", self.auth_header())
            .send()
            .await?;

        if resp.status().is_success() {
            Ok(resp.json().await?)
        } else {
            let status = resp.status();
            let text = resp.text().await?;
            Err(format!("Failed to get artifact metadata: {} - {}", status, text).into())
        }
    }

    async fn delete_artifact(
        &self,
        repo_key: &str,
        path: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let client = Client::new();
        let resp = client
            .delete(format!(
                "{}/api/v1/repositories/{}/artifacts/{}",
                self.base_url, repo_key, path
            ))
            .header("Authorization", self.auth_header())
            .send()
            .await?;

        if resp.status().is_success() {
            Ok(())
        } else {
            let status = resp.status();
            let text = resp.text().await?;
            Err(format!("Failed to delete artifact: {} - {}", status, text).into())
        }
    }
}

/// Sample artifact content for each format
mod samples {
    /// Sample Maven POM file
    pub fn maven_pom() -> &'static [u8] {
        br#"<?xml version="1.0" encoding="UTF-8"?>
<project>
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>test-artifact</artifactId>
    <version>1.0.0</version>
    <packaging>jar</packaging>
</project>"#
    }

    /// Sample Maven JAR file (just a placeholder)
    pub fn maven_jar() -> Vec<u8> {
        // Simple ZIP/JAR header with minimal content
        vec![
            0x50, 0x4B, 0x03, 0x04, // Local file header signature
            0x14, 0x00, // Version needed
            0x00, 0x00, // General purpose bit flag
            0x00, 0x00, // Compression method (stored)
            0x00, 0x00, // File last modification time
            0x00, 0x00, // File last modification date
            0x00, 0x00, 0x00, 0x00, // CRC-32
            0x00, 0x00, 0x00, 0x00, // Compressed size
            0x00, 0x00, 0x00, 0x00, // Uncompressed size
            0x08, 0x00, // File name length
            0x00, 0x00, // Extra field length
            // File name: META-INF
            0x4D, 0x45, 0x54, 0x41, 0x2D, 0x49, 0x4E, 0x46,
        ]
    }

    /// Sample PyPI wheel metadata
    pub fn pypi_wheel() -> Vec<u8> {
        // Minimal wheel file
        let content = b"test-package content";
        content.to_vec()
    }

    /// Sample NPM package.json
    pub fn npm_package_json() -> &'static [u8] {
        br#"{
    "name": "test-package",
    "version": "1.0.0",
    "description": "Test package",
    "main": "index.js"
}"#
    }

    /// Sample Docker manifest
    pub fn docker_manifest() -> &'static [u8] {
        br#"{
    "schemaVersion": 2,
    "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
    "config": {
        "mediaType": "application/vnd.docker.container.image.v1+json",
        "size": 7023,
        "digest": "sha256:b5b2b2c507a0944348e0303114d8d93aaaa081732b86451d9bce1f432a537bc7"
    },
    "layers": []
}"#
    }

    /// Sample Helm chart
    pub fn helm_chart_yaml() -> &'static [u8] {
        br#"apiVersion: v2
name: test-chart
description: A test Helm chart
type: application
version: 1.0.0
appVersion: "1.0.0"
"#
    }

    /// Sample RPM spec content (placeholder)
    pub fn rpm_package() -> Vec<u8> {
        // RPM magic number followed by placeholder content
        let mut content = vec![0xED, 0xAB, 0xEE, 0xDB];
        content.extend_from_slice(b"placeholder rpm content");
        content
    }

    /// Sample Debian package content (placeholder)
    pub fn deb_package() -> Vec<u8> {
        // Debian package magic
        let mut content = b"!<arch>\n".to_vec();
        content.extend_from_slice(b"debian-binary   ");
        content.extend_from_slice(b"2.0\n");
        content
    }

    /// Sample Go module
    pub fn go_mod() -> &'static [u8] {
        br#"module example.com/test
go 1.21
require (
    github.com/some/dependency v1.0.0
)"#
    }

    /// Sample NuGet package (nupkg is a zip)
    pub fn nuget_package() -> Vec<u8> {
        maven_jar() // Similar structure to JAR
    }

    /// Sample RubyGems gemspec
    pub fn rubygems_spec() -> &'static [u8] {
        br#"Gem::Specification.new do |s|
  s.name        = 'test-gem'
  s.version     = '1.0.0'
  s.summary     = 'Test gem'
  s.authors     = ['Test Author']
end"#
    }

    /// Sample Conan conanfile
    pub fn conan_file() -> &'static [u8] {
        br#"from conans import ConanFile

class TestConan(ConanFile):
    name = "test"
    version = "1.0.0"
"#
    }

    /// Sample Cargo crate (tarball placeholder)
    pub fn cargo_crate() -> Vec<u8> {
        // Gzip magic + tar content
        vec![0x1F, 0x8B, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00]
    }

    /// Generic binary file
    pub fn generic_binary() -> Vec<u8> {
        b"Generic binary content for testing".to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to get an authenticated test server
    async fn get_server() -> TestServer {
        let mut server = TestServer::new();
        server.login().await.expect("Login failed");
        server
    }

    // ============= Health Check Tests =============

    #[tokio::test]
    #[ignore = "requires running HTTP server"]
    async fn test_health_check() {
        let server = TestServer::new();
        let client = Client::new();
        let resp = client
            .get(format!("{}/health", server.base_url))
            .send()
            .await
            .expect("Health check request failed");

        assert!(resp.status().is_success());
        let body: Value = resp.json().await.expect("Failed to parse health response");
        assert_eq!(body["status"], "healthy");
    }

    // ============= Authentication Tests =============

    #[tokio::test]
    #[ignore = "requires running HTTP server"]
    async fn test_login() {
        let mut server = TestServer::new();
        let result = server.login().await;
        assert!(result.is_ok(), "Login should succeed");
        assert!(
            !server.access_token.is_empty(),
            "Should receive access token"
        );
    }

    #[tokio::test]
    #[ignore = "requires running HTTP server"]
    async fn test_login_invalid_credentials() {
        let server = TestServer::new();
        let client = Client::new();
        let resp = client
            .post(format!("{}/api/v1/auth/login", server.base_url))
            .json(&json!({
                "username": "admin",
                "password": "wrong_password"
            }))
            .send()
            .await
            .expect("Request failed");

        assert_eq!(resp.status(), 401);
    }

    // ============= Maven Repository Tests =============

    #[tokio::test]
    #[ignore = "requires running HTTP server"]
    async fn test_maven_artifact_lifecycle() {
        let server = get_server().await;
        let repo_key = "maven-test";
        let artifact_path = "com/example/test-artifact/1.0.0/test-artifact-1.0.0.pom";

        // Create repository
        let _ = server
            .create_repository(repo_key, "Maven Test Repo", "maven")
            .await;

        // Upload POM
        let upload_result = server
            .upload_artifact(
                repo_key,
                artifact_path,
                samples::maven_pom(),
                "application/xml",
            )
            .await;
        assert!(
            upload_result.is_ok(),
            "Maven POM upload failed: {:?}",
            upload_result
        );

        // Get metadata
        let metadata = server
            .get_artifact_metadata(repo_key, artifact_path)
            .await
            .expect("Get metadata failed");
        assert!(metadata["name"].as_str().is_some());

        // Download and verify
        let downloaded = server
            .download_artifact(repo_key, artifact_path)
            .await
            .expect("Download failed");
        assert_eq!(downloaded, samples::maven_pom());
    }

    // ============= PyPI Repository Tests =============

    #[tokio::test]
    #[ignore = "requires running HTTP server"]
    async fn test_pypi_artifact_lifecycle() {
        let server = get_server().await;
        let repo_key = "pypi-test";
        let artifact_path = "packages/test-package/1.0.0/test_package-1.0.0-py3-none-any.whl";

        // Create repository
        let _ = server
            .create_repository(repo_key, "PyPI Test Repo", "pypi")
            .await;

        // Upload wheel
        let upload_result = server
            .upload_artifact(
                repo_key,
                artifact_path,
                &samples::pypi_wheel(),
                "application/zip",
            )
            .await;
        assert!(
            upload_result.is_ok(),
            "PyPI wheel upload failed: {:?}",
            upload_result
        );

        // Download and verify
        let downloaded = server
            .download_artifact(repo_key, artifact_path)
            .await
            .expect("Download failed");
        assert_eq!(downloaded, samples::pypi_wheel());
    }

    // ============= NPM Repository Tests =============

    #[tokio::test]
    #[ignore = "requires running HTTP server"]
    async fn test_npm_artifact_lifecycle() {
        let server = get_server().await;
        let repo_key = "npm-test";
        let artifact_path = "test-package/-/test-package-1.0.0.tgz";

        // Create repository
        let _ = server
            .create_repository(repo_key, "NPM Test Repo", "npm")
            .await;

        // Upload package tarball
        let tarball = samples::cargo_crate(); // Reuse tarball structure
        let upload_result = server
            .upload_artifact(repo_key, artifact_path, &tarball, "application/gzip")
            .await;
        assert!(
            upload_result.is_ok(),
            "NPM package upload failed: {:?}",
            upload_result
        );

        // Download and verify
        let downloaded = server
            .download_artifact(repo_key, artifact_path)
            .await
            .expect("Download failed");
        assert_eq!(downloaded, tarball);
    }

    // ============= Docker Repository Tests =============

    #[tokio::test]
    #[ignore = "requires running HTTP server"]
    async fn test_docker_manifest_lifecycle() {
        let server = get_server().await;
        let repo_key = "docker-test";
        let manifest_path = "v2/test-image/manifests/latest";

        // Create repository
        let _ = server
            .create_repository(repo_key, "Docker Test Repo", "docker")
            .await;

        // Upload manifest
        let upload_result = server
            .upload_artifact(
                repo_key,
                manifest_path,
                samples::docker_manifest(),
                "application/vnd.docker.distribution.manifest.v2+json",
            )
            .await;
        assert!(
            upload_result.is_ok(),
            "Docker manifest upload failed: {:?}",
            upload_result
        );

        // Download and verify
        let downloaded = server
            .download_artifact(repo_key, manifest_path)
            .await
            .expect("Download failed");
        assert_eq!(downloaded, samples::docker_manifest());
    }

    // ============= Docker Tags/List and Catalog Tests =============

    #[tokio::test]
    #[ignore = "requires running HTTP server"]
    async fn test_oci_tags_list_after_manifest_push() {
        let server = get_server().await;
        let repo_key = "docker-tags-test";

        // Create repository
        let _ = server
            .create_repository(repo_key, "Docker Tags Test", "docker")
            .await;

        // Push a manifest with a tag (via the generic artifact API)
        let manifest_path = "v2/myimage/manifests/v1.0";
        let _ = server
            .upload_artifact(
                repo_key,
                manifest_path,
                samples::docker_manifest(),
                "application/vnd.docker.distribution.manifest.v2+json",
            )
            .await;

        // Query tags/list via OCI V2 API
        let client = Client::new();
        let token = server.get_oci_token("admin", "admin123").await.unwrap();

        let resp = client
            .get(format!(
                "{}/v2/{}/myimage/tags/list",
                server.base_url, repo_key
            ))
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "Tags list should return 200");
        let body: Value = resp.json().await.unwrap();
        assert_eq!(body["name"], "myimage");
        let tags = body["tags"].as_array().expect("tags should be an array");
        assert!(
            tags.iter().any(|t| t.as_str() == Some("v1.0")),
            "Tags should contain v1.0, got: {:?}",
            tags
        );
    }

    #[tokio::test]
    #[ignore = "requires running HTTP server"]
    async fn test_oci_tags_list_pagination() {
        let server = get_server().await;
        let repo_key = "docker-tags-page-test";

        let _ = server
            .create_repository(repo_key, "Docker Tags Page Test", "docker")
            .await;

        // Push two manifests with different tags
        for tag in &["alpha", "beta"] {
            let path = format!("v2/paged/manifests/{}", tag);
            let _ = server
                .upload_artifact(
                    repo_key,
                    &path,
                    samples::docker_manifest(),
                    "application/vnd.docker.distribution.manifest.v2+json",
                )
                .await;
        }

        let client = Client::new();
        let token = server.get_oci_token("admin", "admin123").await.unwrap();

        // Request n=1 — should get one tag and a Link header
        let resp = client
            .get(format!(
                "{}/v2/{}/paged/tags/list?n=1",
                server.base_url, repo_key
            ))
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let link = resp
            .headers()
            .get("link")
            .map(|v| v.to_str().unwrap_or("").to_string());
        let body: Value = resp.json().await.unwrap();
        let tags = body["tags"].as_array().unwrap();
        assert_eq!(tags.len(), 1, "Should return exactly 1 tag");
        assert!(link.is_some(), "Should have Link header for next page");
    }

    #[tokio::test]
    #[ignore = "requires running HTTP server"]
    async fn test_oci_tags_list_n_zero() {
        let server = get_server().await;
        let repo_key = "docker-tags-zero-test";

        let _ = server
            .create_repository(repo_key, "Docker Tags Zero Test", "docker")
            .await;
        let _ = server
            .upload_artifact(
                repo_key,
                "v2/img/manifests/latest",
                samples::docker_manifest(),
                "application/vnd.docker.distribution.manifest.v2+json",
            )
            .await;

        let client = Client::new();
        let token = server.get_oci_token("admin", "admin123").await.unwrap();

        let resp = client
            .get(format!(
                "{}/v2/{}/img/tags/list?n=0",
                server.base_url, repo_key
            ))
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let link = resp.headers().get("link");
        assert!(link.is_none(), "n=0 should not have Link header");
        let body: Value = resp.json().await.unwrap();
        assert_eq!(
            body["tags"],
            serde_json::json!([]),
            "n=0 should return empty tags"
        );
    }

    #[tokio::test]
    #[ignore = "requires running HTTP server"]
    async fn test_oci_catalog() {
        let server = get_server().await;
        let repo_key = "docker-catalog-test";

        let _ = server
            .create_repository(repo_key, "Docker Catalog Test", "docker")
            .await;
        let _ = server
            .upload_artifact(
                repo_key,
                "v2/catalogimg/manifests/v1",
                samples::docker_manifest(),
                "application/vnd.docker.distribution.manifest.v2+json",
            )
            .await;

        let client = Client::new();
        let token = server.get_oci_token("admin", "admin123").await.unwrap();

        let resp = client
            .get(format!("{}/v2/_catalog", server.base_url))
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "Catalog should return 200");
        let body: Value = resp.json().await.unwrap();
        let repos = body["repositories"]
            .as_array()
            .expect("repositories should be an array");
        assert!(
            repos
                .iter()
                .any(|r| r.as_str().is_some_and(|s| s.contains("catalogimg"))),
            "Catalog should contain catalogimg, got: {:?}",
            repos
        );
    }

    #[tokio::test]
    #[ignore = "requires running HTTP server"]
    async fn test_oci_catalog_includes_private_repos_for_authenticated_non_admin_user() {
        let server = get_server().await;
        let repo_key = "docker-private-catalog-test";
        let username = "catalog-reader";
        let password = "CatalogPass123!";

        let _ = server
            .create_private_repository(repo_key, "Docker Private Catalog Test", "docker")
            .await;
        let _ = server
            .upload_artifact(
                repo_key,
                "v2/privateimg/manifests/v1",
                samples::docker_manifest(),
                "application/vnd.docker.distribution.manifest.v2+json",
            )
            .await;
        let _ = server
            .create_user(username, "catalog-reader@example.test", password, false)
            .await;

        let token = server
            .get_oci_token(username, password)
            .await
            .expect("Failed to issue OCI token for non-admin user");

        let client = Client::new();
        let resp = client
            .get(format!("{}/v2/_catalog", server.base_url))
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "Catalog should return 200");
        let body: Value = resp.json().await.unwrap();
        let repos = body["repositories"]
            .as_array()
            .expect("repositories should be an array");
        assert!(
            repos
                .iter()
                .any(|r| r.as_str().is_some_and(|s| s.contains("privateimg"))),
            "Catalog should contain privateimg for authenticated non-admin users, got: {:?}",
            repos
        );
    }

    #[tokio::test]
    #[ignore = "requires running HTTP server"]
    async fn test_oci_tags_list_nonexistent_returns_404() {
        let server = get_server().await;

        let client = Client::new();
        let token = server.get_oci_token("admin", "admin123").await.unwrap();

        let resp = client
            .get(format!(
                "{}/v2/nonexistent-repo/someimage/tags/list",
                server.base_url
            ))
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            404,
            "Tags list for unknown repo should return 404"
        );
    }

    // ============= Helm Repository Tests =============

    #[tokio::test]
    #[ignore = "requires running HTTP server"]
    async fn test_helm_chart_lifecycle() {
        let server = get_server().await;
        let repo_key = "helm-test";
        let chart_path = "charts/test-chart-1.0.0.tgz";

        // Create repository
        let _ = server
            .create_repository(repo_key, "Helm Test Repo", "helm")
            .await;

        // Upload chart
        let chart = samples::cargo_crate(); // Helm charts are tarballs
        let upload_result = server
            .upload_artifact(repo_key, chart_path, &chart, "application/gzip")
            .await;
        assert!(
            upload_result.is_ok(),
            "Helm chart upload failed: {:?}",
            upload_result
        );

        // Download and verify
        let downloaded = server
            .download_artifact(repo_key, chart_path)
            .await
            .expect("Download failed");
        assert_eq!(downloaded, chart);
    }

    // ============= RPM Repository Tests =============

    #[tokio::test]
    #[ignore = "requires running HTTP server"]
    async fn test_rpm_package_lifecycle() {
        let server = get_server().await;
        let repo_key = "rpm-test";
        let package_path = "packages/test-package-1.0.0-1.x86_64.rpm";

        // Create repository
        let _ = server
            .create_repository(repo_key, "RPM Test Repo", "rpm")
            .await;

        // Upload RPM
        let upload_result = server
            .upload_artifact(
                repo_key,
                package_path,
                &samples::rpm_package(),
                "application/x-rpm",
            )
            .await;
        assert!(
            upload_result.is_ok(),
            "RPM package upload failed: {:?}",
            upload_result
        );

        // Download and verify
        let downloaded = server
            .download_artifact(repo_key, package_path)
            .await
            .expect("Download failed");
        assert_eq!(downloaded, samples::rpm_package());
    }

    // ============= Debian Repository Tests =============

    #[tokio::test]
    #[ignore = "requires running HTTP server"]
    async fn test_deb_package_lifecycle() {
        let server = get_server().await;
        let repo_key = "deb-test";
        let package_path = "pool/main/t/test-package/test-package_1.0.0_amd64.deb";

        // Create repository
        let _ = server
            .create_repository(repo_key, "Debian Test Repo", "debian")
            .await;

        // Upload DEB
        let upload_result = server
            .upload_artifact(
                repo_key,
                package_path,
                &samples::deb_package(),
                "application/vnd.debian.binary-package",
            )
            .await;
        assert!(
            upload_result.is_ok(),
            "Debian package upload failed: {:?}",
            upload_result
        );

        // Download and verify
        let downloaded = server
            .download_artifact(repo_key, package_path)
            .await
            .expect("Download failed");
        assert_eq!(downloaded, samples::deb_package());
    }

    // ============= Go Module Repository Tests =============

    #[tokio::test]
    #[ignore = "requires running HTTP server"]
    async fn test_go_module_lifecycle() {
        let server = get_server().await;
        let repo_key = "go-test";
        let module_path = "example.com/test/@v/v1.0.0.mod";

        // Create repository
        let _ = server
            .create_repository(repo_key, "Go Module Test Repo", "go")
            .await;

        // Upload go.mod
        let upload_result = server
            .upload_artifact(repo_key, module_path, samples::go_mod(), "text/plain")
            .await;
        assert!(
            upload_result.is_ok(),
            "Go module upload failed: {:?}",
            upload_result
        );

        // Download and verify
        let downloaded = server
            .download_artifact(repo_key, module_path)
            .await
            .expect("Download failed");
        assert_eq!(downloaded, samples::go_mod());
    }

    // ============= NuGet Repository Tests =============

    #[tokio::test]
    #[ignore = "requires running HTTP server"]
    async fn test_nuget_package_lifecycle() {
        let server = get_server().await;
        let repo_key = "nuget-test";
        let package_path = "packages/TestPackage/1.0.0/testpackage.1.0.0.nupkg";

        // Create repository
        let _ = server
            .create_repository(repo_key, "NuGet Test Repo", "nuget")
            .await;

        // Upload nupkg
        let upload_result = server
            .upload_artifact(
                repo_key,
                package_path,
                &samples::nuget_package(),
                "application/octet-stream",
            )
            .await;
        assert!(
            upload_result.is_ok(),
            "NuGet package upload failed: {:?}",
            upload_result
        );

        // Download and verify
        let downloaded = server
            .download_artifact(repo_key, package_path)
            .await
            .expect("Download failed");
        assert_eq!(downloaded, samples::nuget_package());
    }

    // ============= RubyGems Repository Tests =============

    #[tokio::test]
    #[ignore = "requires running HTTP server"]
    async fn test_rubygems_lifecycle() {
        let server = get_server().await;
        let repo_key = "rubygems-test";
        let gem_path = "gems/test-gem-1.0.0.gem";

        // Create repository
        let _ = server
            .create_repository(repo_key, "RubyGems Test Repo", "rubygems")
            .await;

        // Upload gem
        let gem = samples::generic_binary();
        let upload_result = server
            .upload_artifact(repo_key, gem_path, &gem, "application/octet-stream")
            .await;
        assert!(
            upload_result.is_ok(),
            "RubyGems upload failed: {:?}",
            upload_result
        );

        // Download and verify
        let downloaded = server
            .download_artifact(repo_key, gem_path)
            .await
            .expect("Download failed");
        assert_eq!(downloaded, gem);
    }

    // ============= Conan Repository Tests =============

    #[tokio::test]
    #[ignore = "requires running HTTP server"]
    async fn test_conan_package_lifecycle() {
        let server = get_server().await;
        let repo_key = "conan-test";
        let package_path = "test/1.0.0/_/_/conanfile.py";

        // Create repository
        let _ = server
            .create_repository(repo_key, "Conan Test Repo", "conan")
            .await;

        // Upload conanfile
        let upload_result = server
            .upload_artifact(repo_key, package_path, samples::conan_file(), "text/plain")
            .await;
        assert!(
            upload_result.is_ok(),
            "Conan package upload failed: {:?}",
            upload_result
        );

        // Download and verify
        let downloaded = server
            .download_artifact(repo_key, package_path)
            .await
            .expect("Download failed");
        assert_eq!(downloaded, samples::conan_file());
    }

    // ============= Cargo Repository Tests =============

    #[tokio::test]
    #[ignore = "requires running HTTP server"]
    async fn test_cargo_crate_lifecycle() {
        let server = get_server().await;
        let repo_key = "cargo-test";
        let crate_path = "crates/test-crate/1.0.0/download";

        // Create repository
        let _ = server
            .create_repository(repo_key, "Cargo Test Repo", "cargo")
            .await;

        // Upload crate
        let upload_result = server
            .upload_artifact(
                repo_key,
                crate_path,
                &samples::cargo_crate(),
                "application/gzip",
            )
            .await;
        assert!(
            upload_result.is_ok(),
            "Cargo crate upload failed: {:?}",
            upload_result
        );

        // Download and verify
        let downloaded = server
            .download_artifact(repo_key, crate_path)
            .await
            .expect("Download failed");
        assert_eq!(downloaded, samples::cargo_crate());
    }

    // ============= Generic Repository Tests =============

    #[tokio::test]
    #[ignore = "requires running HTTP server"]
    async fn test_generic_artifact_lifecycle() {
        let server = get_server().await;
        let repo_key = "generic-test";
        let artifact_path = "releases/v1.0.0/binary.tar.gz";

        // Create repository
        let _ = server
            .create_repository(repo_key, "Generic Test Repo", "generic")
            .await;

        // Upload generic artifact
        let upload_result = server
            .upload_artifact(
                repo_key,
                artifact_path,
                &samples::generic_binary(),
                "application/octet-stream",
            )
            .await;
        assert!(
            upload_result.is_ok(),
            "Generic artifact upload failed: {:?}",
            upload_result
        );

        // Download and verify
        let downloaded = server
            .download_artifact(repo_key, artifact_path)
            .await
            .expect("Download failed");
        assert_eq!(downloaded, samples::generic_binary());

        // Test deletion
        let delete_result = server.delete_artifact(repo_key, artifact_path).await;
        assert!(
            delete_result.is_ok(),
            "Delete artifact failed: {:?}",
            delete_result
        );
    }

    // ============= Search Tests =============

    #[tokio::test]
    #[ignore = "requires running HTTP server"]
    async fn test_search_artifacts() {
        let server = get_server().await;
        let client = Client::new();

        // Search all artifacts
        let resp = client
            .get(format!("{}/api/v1/search/artifacts", server.base_url))
            .header("Authorization", server.auth_header())
            .send()
            .await
            .expect("Search request failed");

        assert!(resp.status().is_success());
        let body: Value = resp.json().await.expect("Failed to parse search response");
        assert!(body["items"].is_array());
    }

    // ============= Repository List Tests =============

    #[tokio::test]
    #[ignore = "requires running HTTP server"]
    async fn test_list_repositories() {
        let server = get_server().await;
        let client = Client::new();

        let resp = client
            .get(format!("{}/api/v1/repositories", server.base_url))
            .header("Authorization", server.auth_header())
            .send()
            .await
            .expect("List repos request failed");

        assert!(resp.status().is_success());
        let body: Value = resp.json().await.expect("Failed to parse repos response");
        assert!(body["items"].is_array());
    }

    // ============= Private Repository Visibility Tests =============

    /// Test that private repos are excluded from the repo list for anonymous users.
    #[tokio::test]
    #[ignore = "requires running HTTP server"]
    async fn test_private_repo_hidden_from_anonymous_list() {
        let mut server = TestServer::new();
        server.login().await.unwrap();
        let client = Client::new();

        // Create a private repo (authenticated)
        server
            .create_private_repository("integ-private-repo", "Private Test Repo", "generic")
            .await
            .unwrap();

        // List repos without auth - should NOT include the private repo
        let resp = client
            .get(format!("{}/api/v1/repositories", server.base_url))
            .send()
            .await
            .unwrap();
        assert!(resp.status().is_success());
        let body: Value = resp.json().await.unwrap();
        let items = body["items"].as_array().unwrap();
        let keys: Vec<&str> = items.iter().filter_map(|r| r["key"].as_str()).collect();
        assert!(
            !keys.contains(&"integ-private-repo"),
            "Private repo should not appear in anonymous listing, got: {:?}",
            keys
        );

        // List repos with auth - SHOULD include the private repo
        let resp = client
            .get(format!("{}/api/v1/repositories", server.base_url))
            .header("Authorization", server.auth_header())
            .send()
            .await
            .unwrap();
        assert!(resp.status().is_success());
        let body: Value = resp.json().await.unwrap();
        let items = body["items"].as_array().unwrap();
        let keys: Vec<&str> = items.iter().filter_map(|r| r["key"].as_str()).collect();
        assert!(
            keys.contains(&"integ-private-repo"),
            "Private repo should appear in authenticated listing, got: {:?}",
            keys
        );
    }

    /// Test that Maven upload to a private repo works with Basic auth.
    #[tokio::test]
    #[ignore = "requires running HTTP server"]
    async fn test_private_repo_maven_upload_with_basic_auth() {
        let mut server = TestServer::new();
        server.login().await.unwrap();
        let client = Client::new();

        // Create a private Maven repo
        server
            .create_private_repository("integ-private-maven", "Private Maven", "maven")
            .await
            .unwrap();

        // Upload with Basic auth should succeed
        let basic_creds = base64::engine::general_purpose::STANDARD.encode("admin:admin123");
        let resp = client
            .put(format!(
                "{}/maven/integ-private-maven/com/example/test/1.0/test-1.0.jar",
                server.base_url
            ))
            .header("Authorization", format!("Basic {}", basic_creds))
            .header("Content-Type", "application/java-archive")
            .body(b"fake-jar-content".to_vec())
            .send()
            .await
            .unwrap();
        assert!(
            resp.status().is_success(),
            "Basic auth upload to private repo should succeed, got {}",
            resp.status()
        );
    }

    /// Test that anonymous download from a private repo returns 404.
    #[tokio::test]
    #[ignore = "requires running HTTP server"]
    async fn test_private_repo_anonymous_download_blocked() {
        let server = TestServer::new();
        let client = Client::new();

        // Attempt anonymous download from the private Maven repo created in previous test
        let resp = client
            .get(format!(
                "{}/maven/integ-private-maven/com/example/test/1.0/test-1.0.jar",
                server.base_url
            ))
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            404,
            "Anonymous access to private repo should return 404, got {}",
            resp.status()
        );
    }

    /// Test that packages list filters private repo packages for anonymous users.
    #[tokio::test]
    #[ignore = "requires running HTTP server"]
    async fn test_private_repo_packages_hidden_from_anonymous() {
        let server = TestServer::new();
        let client = Client::new();

        // List packages without auth
        let resp = client
            .get(format!("{}/api/v1/packages", server.base_url))
            .send()
            .await
            .unwrap();
        assert!(resp.status().is_success());
        let body: Value = resp.json().await.unwrap();
        let empty = vec![];
        let items = body["items"].as_array().unwrap_or(&empty);
        // Verify no packages from private repos appear
        let private_repo_packages: Vec<&Value> = items
            .iter()
            .filter(|p| p["repository_key"].as_str() == Some("integ-private-maven"))
            .collect();
        assert!(
            private_repo_packages.is_empty(),
            "Private repo packages should not appear in anonymous listing"
        );
    }
}
