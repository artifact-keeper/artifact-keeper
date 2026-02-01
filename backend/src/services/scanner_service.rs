//! Core scanner orchestration service.
//!
//! Provides a trait-based scanner interface and an orchestrator that runs
//! applicable scanners against artifacts, persists results, and triggers
//! security score recalculation.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::Bytes;
use reqwest::Client;
use serde::Deserialize;
use sqlx::PgPool;
use tokio::sync::RwLock;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::error::{AppError, Result};
use crate::models::artifact::{Artifact, ArtifactMetadata};
use crate::models::security::{RawFinding, Severity};
use crate::services::grype_scanner::GrypeScanner;
use crate::services::image_scanner::ImageScanner;
use crate::services::scan_config_service::ScanConfigService;
use crate::services::scan_result_service::ScanResultService;
use crate::services::trivy_fs_scanner::TrivyFsScanner;
use crate::storage::filesystem::FilesystemStorage;
use crate::storage::StorageBackend;

// ---------------------------------------------------------------------------
// Scanner trait
// ---------------------------------------------------------------------------

/// A pluggable vulnerability scanner.
#[async_trait]
pub trait Scanner: Send + Sync {
    /// Human-readable name for logging.
    fn name(&self) -> &str;

    /// The scan_type value stored in scan_results.
    fn scan_type(&self) -> &str;

    /// Run the scan against artifact content and metadata.
    async fn scan(
        &self,
        artifact: &Artifact,
        metadata: Option<&ArtifactMetadata>,
        content: &Bytes,
    ) -> Result<Vec<RawFinding>>;
}

// ---------------------------------------------------------------------------
// Advisory client (OSV.dev + GitHub Advisory)
// ---------------------------------------------------------------------------

/// Cached advisory lookup shared across scanner invocations.
pub struct AdvisoryClient {
    http: Client,
    cache: RwLock<HashMap<String, CachedAdvisory>>,
    github_token: Option<String>,
}

struct CachedAdvisory {
    findings: Vec<AdvisoryMatch>,
    fetched_at: Instant,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AdvisoryMatch {
    pub id: String,
    pub summary: Option<String>,
    pub details: Option<String>,
    pub severity: String,
    pub aliases: Vec<String>,
    pub affected_version: Option<String>,
    pub fixed_version: Option<String>,
    pub source: String,
    pub source_url: Option<String>,
}

/// OSV.dev batch query request body.
#[derive(serde::Serialize)]
struct OsvBatchQuery {
    queries: Vec<OsvQuery>,
}

#[derive(serde::Serialize)]
struct OsvQuery {
    package: OsvPackage,
    version: Option<String>,
}

#[derive(serde::Serialize)]
struct OsvPackage {
    name: String,
    ecosystem: String,
}

/// A single dependency extracted from a manifest.
#[derive(Debug, Clone)]
pub struct Dependency {
    pub name: String,
    pub version: Option<String>,
    pub ecosystem: String,
}

const CACHE_TTL: Duration = Duration::from_secs(3600); // 1 hour
const OSV_BATCH_URL: &str = "https://api.osv.dev/v1/querybatch";
const GITHUB_ADVISORY_URL: &str = "https://api.github.com/advisories";

impl AdvisoryClient {
    pub fn new(github_token: Option<String>) -> Self {
        Self {
            http: Client::builder()
                .timeout(Duration::from_secs(30))
                .user_agent("artifact-keeper-scanner/1.0")
                .build()
                .expect("failed to build HTTP client"),
            cache: RwLock::new(HashMap::new()),
            github_token,
        }
    }

    /// Query OSV.dev for advisories affecting the given dependencies.
    pub async fn query_osv(&self, deps: &[Dependency]) -> Vec<AdvisoryMatch> {
        if deps.is_empty() {
            return vec![];
        }

        // Check cache first
        let mut uncached = Vec::new();
        let mut results = Vec::new();

        {
            let cache = self.cache.read().await;
            for dep in deps {
                let key = format!(
                    "{}:{}:{}",
                    dep.ecosystem,
                    dep.name,
                    dep.version.as_deref().unwrap_or("*")
                );
                if let Some(cached) = cache.get(&key) {
                    if cached.fetched_at.elapsed() < CACHE_TTL {
                        results.extend(cached.findings.clone());
                        continue;
                    }
                }
                uncached.push(dep.clone());
            }
        }

        if uncached.is_empty() {
            return results;
        }

        // Batch query OSV.dev (max 1000 per batch)
        for chunk in uncached.chunks(1000) {
            let query = OsvBatchQuery {
                queries: chunk
                    .iter()
                    .map(|d| OsvQuery {
                        package: OsvPackage {
                            name: d.name.clone(),
                            ecosystem: d.ecosystem.clone(),
                        },
                        version: d.version.clone(),
                    })
                    .collect(),
            };

            match self.http.post(OSV_BATCH_URL).json(&query).send().await {
                Ok(resp) if resp.status().is_success() => {
                    if let Ok(body) = resp.json::<serde_json::Value>().await {
                        let matches = Self::parse_osv_response(&body, chunk);
                        // Update cache
                        let mut cache = self.cache.write().await;
                        for dep in chunk.iter() {
                            let key = format!(
                                "{}:{}:{}",
                                dep.ecosystem,
                                dep.name,
                                dep.version.as_deref().unwrap_or("*")
                            );
                            let dep_matches: Vec<_> = matches
                                .iter()
                                .filter(|_m| {
                                    // Match by position in batch response
                                    true // OSV returns results indexed by query order
                                })
                                .cloned()
                                .collect();
                            cache.insert(
                                key,
                                CachedAdvisory {
                                    findings: dep_matches,
                                    fetched_at: Instant::now(),
                                },
                            );
                        }
                        results.extend(matches);
                    }
                }
                Ok(resp) => {
                    warn!("OSV.dev returned status {}", resp.status());
                }
                Err(e) => {
                    warn!("OSV.dev request failed: {}", e);
                }
            }
        }

        results
    }

    /// Query GitHub Advisory Database as a fallback/secondary source.
    pub async fn query_github(&self, deps: &[Dependency]) -> Vec<AdvisoryMatch> {
        let token = match &self.github_token {
            Some(t) => t,
            None => return vec![],
        };

        let mut results = Vec::new();

        for dep in deps {
            let ecosystem_param = match dep.ecosystem.as_str() {
                "npm" => "npm",
                "PyPI" | "pypi" => "pip",
                "crates.io" => "rust",
                "Maven" => "maven",
                "Go" => "go",
                "NuGet" => "nuget",
                "RubyGems" => "rubygems",
                _ => continue,
            };

            let url = format!(
                "{}?affects={}&ecosystem={}&per_page=100",
                GITHUB_ADVISORY_URL, dep.name, ecosystem_param
            );

            match self
                .http
                .get(&url)
                .header("Authorization", format!("Bearer {}", token))
                .header("Accept", "application/vnd.github+json")
                .header("X-GitHub-Api-Version", "2022-11-28")
                .send()
                .await
            {
                Ok(resp) if resp.status().is_success() => {
                    if let Ok(advisories) = resp.json::<Vec<serde_json::Value>>().await {
                        for adv in advisories {
                            if let Some(m) = Self::parse_github_advisory(&adv, dep) {
                                results.push(m);
                            }
                        }
                    }
                }
                Ok(resp) => {
                    warn!(
                        "GitHub Advisory API returned {} for {}",
                        resp.status(),
                        dep.name
                    );
                }
                Err(e) => {
                    warn!("GitHub Advisory request failed for {}: {}", dep.name, e);
                }
            }
        }

        results
    }

    fn parse_osv_response(body: &serde_json::Value, deps: &[Dependency]) -> Vec<AdvisoryMatch> {
        let mut matches = Vec::new();

        if let Some(results) = body.get("results").and_then(|r| r.as_array()) {
            for (i, result) in results.iter().enumerate() {
                if let Some(vulns) = result.get("vulns").and_then(|v| v.as_array()) {
                    for vuln in vulns {
                        let id = vuln
                            .get("id")
                            .and_then(|v| v.as_str())
                            .unwrap_or("UNKNOWN")
                            .to_string();

                        let summary = vuln
                            .get("summary")
                            .and_then(|v| v.as_str())
                            .map(String::from);

                        let details = vuln
                            .get("details")
                            .and_then(|v| v.as_str())
                            .map(String::from);

                        // Extract severity from database_specific or severity array
                        let severity = vuln
                            .get("database_specific")
                            .and_then(|d| d.get("severity"))
                            .and_then(|s| s.as_str())
                            .or_else(|| {
                                vuln.get("severity")
                                    .and_then(|s| s.as_array())
                                    .and_then(|arr| arr.first())
                                    .and_then(|s| s.get("type"))
                                    .and_then(|t| t.as_str())
                            })
                            .unwrap_or("medium")
                            .to_lowercase();

                        // Extract aliases (CVE IDs)
                        let aliases: Vec<String> = vuln
                            .get("aliases")
                            .and_then(|a| a.as_array())
                            .map(|arr| {
                                arr.iter()
                                    .filter_map(|v| v.as_str().map(String::from))
                                    .collect()
                            })
                            .unwrap_or_default();

                        // Extract fixed version from affected ranges
                        let fixed_version = vuln
                            .get("affected")
                            .and_then(|a| a.as_array())
                            .and_then(|arr| arr.first())
                            .and_then(|a| a.get("ranges"))
                            .and_then(|r| r.as_array())
                            .and_then(|arr| arr.first())
                            .and_then(|r| r.get("events"))
                            .and_then(|e| e.as_array())
                            .and_then(|events| {
                                events.iter().find_map(|e| {
                                    e.get("fixed").and_then(|f| f.as_str().map(String::from))
                                })
                            });

                        let dep = deps.get(i);

                        matches.push(AdvisoryMatch {
                            id: id.clone(),
                            summary,
                            details,
                            severity,
                            aliases,
                            affected_version: dep.and_then(|d| d.version.clone()),
                            fixed_version,
                            source: "osv.dev".to_string(),
                            source_url: Some(format!("https://osv.dev/vulnerability/{}", id)),
                        });
                    }
                }
            }
        }

        matches
    }

    fn parse_github_advisory(adv: &serde_json::Value, dep: &Dependency) -> Option<AdvisoryMatch> {
        let ghsa_id = adv.get("ghsa_id")?.as_str()?.to_string();
        let summary = adv
            .get("summary")
            .and_then(|v| v.as_str())
            .map(String::from);
        let description = adv
            .get("description")
            .and_then(|v| v.as_str())
            .map(String::from);
        let severity = adv
            .get("severity")
            .and_then(|v| v.as_str())
            .unwrap_or("medium")
            .to_lowercase();
        let cve_id = adv.get("cve_id").and_then(|v| v.as_str()).map(String::from);
        let html_url = adv
            .get("html_url")
            .and_then(|v| v.as_str())
            .map(String::from);

        let mut aliases = vec![ghsa_id.clone()];
        if let Some(cve) = &cve_id {
            aliases.push(cve.clone());
        }

        // Extract fixed version from vulnerabilities array
        let fixed_version = adv
            .get("vulnerabilities")
            .and_then(|v| v.as_array())
            .and_then(|arr| {
                arr.iter().find_map(|vuln| {
                    vuln.get("first_patched_version")
                        .and_then(|v| v.get("identifier"))
                        .and_then(|v| v.as_str())
                        .map(String::from)
                })
            });

        Some(AdvisoryMatch {
            id: ghsa_id,
            summary,
            details: description,
            severity,
            aliases,
            affected_version: dep.version.clone(),
            fixed_version,
            source: "github".to_string(),
            source_url: html_url,
        })
    }
}

// ---------------------------------------------------------------------------
// Dependency scanner (parses manifests, queries advisories)
// ---------------------------------------------------------------------------

pub struct DependencyScanner {
    advisory: Arc<AdvisoryClient>,
}

impl DependencyScanner {
    pub fn new(advisory: Arc<AdvisoryClient>) -> Self {
        Self { advisory }
    }

    /// Extract dependencies from artifact content based on format/name.
    fn extract_dependencies(
        artifact: &Artifact,
        _metadata: Option<&ArtifactMetadata>,
        content: &Bytes,
    ) -> Vec<Dependency> {
        let name = artifact.name.to_lowercase();
        let content_str = match std::str::from_utf8(content) {
            Ok(s) => s,
            Err(_) => return vec![], // binary artifact, skip manifest parsing
        };

        if name == "package.json" || name.ends_with("/package.json") {
            Self::parse_npm(content_str)
        } else if name == "cargo.toml" || name.ends_with("/cargo.toml") {
            Self::parse_cargo(content_str)
        } else if name == "requirements.txt" || name.ends_with("/requirements.txt") {
            Self::parse_pip(content_str)
        } else if name == "go.sum" || name.ends_with("/go.sum") {
            Self::parse_go(content_str)
        } else if name == "pom.xml" || name.ends_with("/pom.xml") {
            Self::parse_maven(content_str)
        } else if name.ends_with(".gemspec")
            || name == "gemfile.lock"
            || name.ends_with("/gemfile.lock")
        {
            Self::parse_rubygems(content_str)
        } else if name.ends_with(".nuspec") || name == "packages.config" {
            Self::parse_nuget(content_str)
        } else {
            // Try to infer from path patterns
            Self::infer_dependencies(artifact, content_str)
        }
    }

    fn parse_npm(content: &str) -> Vec<Dependency> {
        let mut deps = Vec::new();
        if let Ok(pkg) = serde_json::from_str::<serde_json::Value>(content) {
            for section in ["dependencies", "devDependencies", "peerDependencies"] {
                if let Some(obj) = pkg.get(section).and_then(|v| v.as_object()) {
                    for (name, version) in obj {
                        let ver = version.as_str().map(|v| {
                            v.trim_start_matches('^')
                                .trim_start_matches('~')
                                .to_string()
                        });
                        deps.push(Dependency {
                            name: name.clone(),
                            version: ver,
                            ecosystem: "npm".to_string(),
                        });
                    }
                }
            }
        }
        deps
    }

    fn parse_cargo(content: &str) -> Vec<Dependency> {
        let mut deps = Vec::new();
        if let Ok(toml) = content.parse::<toml::Value>() {
            for section in ["dependencies", "dev-dependencies", "build-dependencies"] {
                if let Some(table) = toml.get(section).and_then(|v| v.as_table()) {
                    for (name, value) in table {
                        let version = match value {
                            toml::Value::String(v) => Some(v.clone()),
                            toml::Value::Table(t) => {
                                t.get("version").and_then(|v| v.as_str()).map(String::from)
                            }
                            _ => None,
                        };
                        deps.push(Dependency {
                            name: name.clone(),
                            version,
                            ecosystem: "crates.io".to_string(),
                        });
                    }
                }
            }
        }
        deps
    }

    fn parse_pip(content: &str) -> Vec<Dependency> {
        let mut deps = Vec::new();
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with('-') {
                continue;
            }
            // Handle: package==1.0.0, package>=1.0.0, package~=1.0.0, package
            let (name, version) = if let Some(pos) = line.find("==") {
                (&line[..pos], Some(line[pos + 2..].trim().to_string()))
            } else if let Some(pos) = line.find(">=") {
                (&line[..pos], Some(line[pos + 2..].trim().to_string()))
            } else if let Some(pos) = line.find("~=") {
                (&line[..pos], Some(line[pos + 2..].trim().to_string()))
            } else if let Some(pos) = line.find("<=") {
                (&line[..pos], Some(line[pos + 2..].trim().to_string()))
            } else {
                (line, None)
            };
            deps.push(Dependency {
                name: name.trim().to_string(),
                version,
                ecosystem: "PyPI".to_string(),
            });
        }
        deps
    }

    fn parse_go(content: &str) -> Vec<Dependency> {
        let mut deps = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for line in content.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                let name = parts[0];
                let version = parts[1].trim_start_matches('v');
                // go.sum has hash lines — deduplicate by module name
                if seen.insert(name.to_string()) {
                    deps.push(Dependency {
                        name: name.to_string(),
                        version: Some(version.to_string()),
                        ecosystem: "Go".to_string(),
                    });
                }
            }
        }
        deps
    }

    fn parse_maven(content: &str) -> Vec<Dependency> {
        // Simple XML extraction — not a full parser, handles common pom.xml patterns
        let mut deps = Vec::new();
        let mut in_dependency = false;
        let mut group_id = String::new();
        let mut artifact_id = String::new();
        let mut version = String::new();

        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("<dependency>") {
                in_dependency = true;
                group_id.clear();
                artifact_id.clear();
                version.clear();
            } else if trimmed.starts_with("</dependency>") && in_dependency {
                if !group_id.is_empty() && !artifact_id.is_empty() {
                    deps.push(Dependency {
                        name: format!("{}:{}", group_id, artifact_id),
                        version: if version.is_empty() {
                            None
                        } else {
                            Some(version.clone())
                        },
                        ecosystem: "Maven".to_string(),
                    });
                }
                in_dependency = false;
            } else if in_dependency {
                if let Some(val) = Self::extract_xml_value(trimmed, "groupId") {
                    group_id = val;
                } else if let Some(val) = Self::extract_xml_value(trimmed, "artifactId") {
                    artifact_id = val;
                } else if let Some(val) = Self::extract_xml_value(trimmed, "version") {
                    version = val;
                }
            }
        }
        deps
    }

    fn extract_xml_value(line: &str, tag: &str) -> Option<String> {
        let open = format!("<{}>", tag);
        let close = format!("</{}>", tag);
        if line.contains(&open) && line.contains(&close) {
            let start = line.find(&open)? + open.len();
            let end = line.find(&close)?;
            if start < end {
                return Some(line[start..end].to_string());
            }
        }
        None
    }

    fn parse_rubygems(content: &str) -> Vec<Dependency> {
        let mut deps = Vec::new();
        for line in content.lines() {
            let trimmed = line.trim();
            // Gemfile.lock format: "    gem_name (version)"
            if let Some(stripped) = trimmed.strip_suffix(')') {
                if let Some(paren_pos) = stripped.rfind('(') {
                    let name = stripped[..paren_pos].trim();
                    let version = &stripped[paren_pos + 1..];
                    if !name.is_empty() {
                        deps.push(Dependency {
                            name: name.to_string(),
                            version: Some(version.to_string()),
                            ecosystem: "RubyGems".to_string(),
                        });
                    }
                }
            }
        }
        deps
    }

    fn parse_nuget(content: &str) -> Vec<Dependency> {
        let mut deps = Vec::new();
        for line in content.lines() {
            let trimmed = line.trim();
            // packages.config: <package id="Newtonsoft.Json" version="13.0.1" />
            if trimmed.starts_with("<package ") {
                let id = Self::extract_xml_attr(trimmed, "id");
                let version = Self::extract_xml_attr(trimmed, "version");
                if let Some(name) = id {
                    deps.push(Dependency {
                        name,
                        version,
                        ecosystem: "NuGet".to_string(),
                    });
                }
            }
        }
        deps
    }

    fn extract_xml_attr(line: &str, attr: &str) -> Option<String> {
        let pattern = format!("{}=\"", attr);
        let start = line.find(&pattern)? + pattern.len();
        let end = line[start..].find('"')? + start;
        Some(line[start..end].to_string())
    }

    /// Fallback: try to infer package ecosystem from artifact path patterns.
    fn infer_dependencies(artifact: &Artifact, _content: &str) -> Vec<Dependency> {
        let path = artifact.path.to_lowercase();

        // For RPM/DEB/APK packages, treat the artifact itself as a dependency
        let ecosystem = if path.ends_with(".rpm")
            || path.contains("/rpm/")
            || path.ends_with(".deb")
            || path.contains("/deb/")
            || path.ends_with(".apk")
            || path.contains("/alpine/")
        {
            Some("Linux")
        } else {
            None
        };

        if let Some(eco) = ecosystem {
            vec![Dependency {
                name: artifact.name.clone(),
                version: artifact.version.clone(),
                ecosystem: eco.to_string(),
            }]
        } else {
            vec![]
        }
    }
}

#[async_trait]
impl Scanner for DependencyScanner {
    fn name(&self) -> &str {
        "DependencyScanner"
    }

    fn scan_type(&self) -> &str {
        "dependency"
    }

    async fn scan(
        &self,
        artifact: &Artifact,
        metadata: Option<&ArtifactMetadata>,
        content: &Bytes,
    ) -> Result<Vec<RawFinding>> {
        let deps = Self::extract_dependencies(artifact, metadata, content);
        if deps.is_empty() {
            return Ok(vec![]);
        }

        info!(
            "Scanning {} dependencies for artifact {}",
            deps.len(),
            artifact.id
        );

        // Query both sources in parallel
        let osv_deps = deps.clone();
        let gh_deps = deps.clone();
        let advisory = self.advisory.clone();
        let advisory2 = self.advisory.clone();

        let (osv_results, gh_results) = tokio::join!(
            advisory.query_osv(&osv_deps),
            advisory2.query_github(&gh_deps),
        );

        // Merge and deduplicate by CVE/GHSA ID
        let mut seen_ids = std::collections::HashSet::new();
        let mut findings = Vec::new();

        for advisory_match in osv_results.into_iter().chain(gh_results.into_iter()) {
            // Deduplicate: skip if we've seen the same advisory ID or any alias
            if seen_ids.contains(&advisory_match.id) {
                continue;
            }
            let mut dominated = false;
            for alias in &advisory_match.aliases {
                if seen_ids.contains(alias) {
                    dominated = true;
                    break;
                }
            }
            if dominated {
                continue;
            }

            seen_ids.insert(advisory_match.id.clone());
            for alias in &advisory_match.aliases {
                seen_ids.insert(alias.clone());
            }

            let severity =
                Severity::from_str_loose(&advisory_match.severity).unwrap_or(Severity::Medium);

            let cve_id = advisory_match
                .aliases
                .iter()
                .find(|a| a.starts_with("CVE-"))
                .cloned()
                .or_else(|| {
                    if advisory_match.id.starts_with("CVE-") {
                        Some(advisory_match.id.clone())
                    } else {
                        None
                    }
                });

            let title = advisory_match
                .summary
                .unwrap_or_else(|| format!("Vulnerability {}", advisory_match.id));

            findings.push(RawFinding {
                severity,
                title,
                description: advisory_match.details,
                cve_id,
                affected_component: Some(deps.first().map(|d| d.name.clone()).unwrap_or_default()),
                affected_version: advisory_match.affected_version,
                fixed_version: advisory_match.fixed_version,
                source: Some(advisory_match.source),
                source_url: advisory_match.source_url,
            });
        }

        Ok(findings)
    }
}

// ---------------------------------------------------------------------------
// Scanner orchestrator
// ---------------------------------------------------------------------------

pub struct ScannerService {
    db: PgPool,
    scanners: Vec<Arc<dyn Scanner>>,
    scan_result_service: Arc<ScanResultService>,
    scan_config_service: Arc<ScanConfigService>,
    #[allow(dead_code)]
    storage_base_path: String,
    scan_workspace_path: String,
}

impl ScannerService {
    pub fn new(
        db: PgPool,
        advisory_client: Arc<AdvisoryClient>,
        scan_result_service: Arc<ScanResultService>,
        scan_config_service: Arc<ScanConfigService>,
        trivy_url: Option<String>,
        storage_base_path: String,
        scan_workspace_path: String,
    ) -> Self {
        let dep_scanner: Arc<dyn Scanner> = Arc::new(DependencyScanner::new(advisory_client));
        let mut scanners: Vec<Arc<dyn Scanner>> = vec![dep_scanner];

        if let Some(url) = trivy_url {
            info!("Trivy image scanner enabled at {}", url);
            scanners.push(Arc::new(ImageScanner::new(url.clone())));
            // Trivy filesystem scanner for non-container artifacts
            info!("Trivy filesystem scanner enabled");
            scanners.push(Arc::new(TrivyFsScanner::new(
                url,
                scan_workspace_path.clone(),
            )));
        }

        // Grype scanner (CLI-based, degrades gracefully if binary not available)
        info!("Grype scanner enabled");
        scanners.push(Arc::new(GrypeScanner::new(scan_workspace_path.clone())));

        Self {
            db,
            scanners,
            scan_result_service,
            scan_config_service,
            storage_base_path,
            scan_workspace_path,
        }
    }

    /// Scan a single artifact: run all applicable scanners, persist results,
    /// recalculate the repository security score.
    pub async fn scan_artifact(&self, artifact_id: Uuid) -> Result<()> {
        // Fetch artifact and content
        let artifact = sqlx::query_as!(
            Artifact,
            r#"
            SELECT id, repository_id, path, name, version, size_bytes,
                   checksum_sha256, checksum_md5, checksum_sha1,
                   content_type, storage_key, is_deleted, uploaded_by,
                   created_at, updated_at
            FROM artifacts
            WHERE id = $1 AND is_deleted = false
            "#,
            artifact_id,
        )
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .ok_or_else(|| AppError::NotFound("Artifact not found".to_string()))?;

        // Check if scanning is enabled for this repo
        if !self
            .scan_config_service
            .is_scan_enabled(artifact.repository_id)
            .await?
        {
            info!(
                "Scanning not enabled for repository {}, skipping artifact {}",
                artifact.repository_id, artifact_id
            );
            return Ok(());
        }

        // Load content from storage (we need the storage key)
        // NOTE: The orchestrator is called with content already available in
        // upload/proxy paths. For on-demand scans, we fetch from DB metadata.
        let content = self.fetch_artifact_content(&artifact).await?;

        // Load metadata if available
        let metadata = sqlx::query_as!(
            ArtifactMetadata,
            r#"
            SELECT id, artifact_id, format, metadata, properties
            FROM artifact_metadata
            WHERE artifact_id = $1
            LIMIT 1
            "#,
            artifact_id,
        )
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        let checksum = &artifact.checksum_sha256;
        const DEDUP_TTL_DAYS: i32 = 30;

        for scanner in &self.scanners {
            // Check for reusable scan results (same hash + scan type within TTL)
            if let Ok(Some(source_scan)) = self
                .scan_result_service
                .find_reusable_scan(checksum, scanner.scan_type(), DEDUP_TTL_DAYS)
                .await
            {
                // Skip if the source scan is for the same artifact (already scanned)
                if source_scan.artifact_id != artifact_id {
                    match self
                        .scan_result_service
                        .copy_scan_results(
                            source_scan.id,
                            artifact_id,
                            artifact.repository_id,
                            scanner.scan_type(),
                            checksum,
                        )
                        .await
                    {
                        Ok(reused) => {
                            info!(
                                "Reusing scan results from {} for artifact {} (scanner={}, hash={}..)",
                                source_scan.id,
                                artifact_id,
                                scanner.name(),
                                &checksum[..8.min(checksum.len())],
                            );
                            // Update quarantine status based on copied findings
                            self.update_quarantine_status(artifact_id, reused.findings_count)
                                .await?;
                            continue;
                        }
                        Err(e) => {
                            warn!(
                                "Failed to copy scan results from {}: {}. Running fresh scan.",
                                source_scan.id, e
                            );
                        }
                    }
                }
            }

            let scan_result = self
                .scan_result_service
                .create_scan_result_with_checksum(
                    artifact_id,
                    artifact.repository_id,
                    scanner.scan_type(),
                    Some(checksum),
                )
                .await?;

            match scanner.scan(&artifact, metadata.as_ref(), &content).await {
                Ok(findings) => {
                    let mut critical = 0i32;
                    let mut high = 0i32;
                    let mut medium = 0i32;
                    let mut low = 0i32;
                    let mut info = 0i32;

                    for f in &findings {
                        match f.severity {
                            Severity::Critical => critical += 1,
                            Severity::High => high += 1,
                            Severity::Medium => medium += 1,
                            Severity::Low => low += 1,
                            Severity::Info => info += 1,
                        }
                    }

                    let total = findings.len() as i32;

                    // Persist findings
                    self.scan_result_service
                        .create_findings(scan_result.id, artifact_id, &findings)
                        .await?;

                    // Mark scan complete
                    self.scan_result_service
                        .complete_scan(scan_result.id, total, critical, high, medium, low, info)
                        .await?;

                    info!(
                        "Scan {} completed for artifact {}: {} findings ({} critical, {} high)",
                        scanner.name(),
                        artifact_id,
                        total,
                        critical,
                        high,
                    );

                    // Update quarantine status
                    self.update_quarantine_status(artifact_id, total).await?;
                }
                Err(e) => {
                    error!(
                        "Scanner {} failed for artifact {}: {}",
                        scanner.name(),
                        artifact_id,
                        e
                    );
                    self.scan_result_service
                        .fail_scan(scan_result.id, &e.to_string())
                        .await?;

                    // Mark as flagged on failure (conservative)
                    sqlx::query!(
                        "UPDATE artifacts SET quarantine_status = 'flagged' WHERE id = $1",
                        artifact_id,
                    )
                    .execute(&self.db)
                    .await
                    .ok();
                }
            }
        }

        // Recalculate repository security score
        self.scan_result_service
            .recalculate_score(artifact.repository_id)
            .await?;

        Ok(())
    }

    /// Scan all non-deleted artifacts in a repository.
    pub async fn scan_repository(&self, repository_id: Uuid) -> Result<u32> {
        let artifact_ids: Vec<Uuid> = sqlx::query_scalar!(
            "SELECT id FROM artifacts WHERE repository_id = $1 AND is_deleted = false",
            repository_id,
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        let count = artifact_ids.len() as u32;
        info!(
            "Starting repository scan for {}: {} artifacts",
            repository_id, count
        );

        for artifact_id in artifact_ids {
            if let Err(e) = self.scan_artifact(artifact_id).await {
                warn!(
                    "Failed to scan artifact {} in repo {}: {}",
                    artifact_id, repository_id, e
                );
            }
        }

        Ok(count)
    }

    /// Fetch artifact content from filesystem storage.
    async fn fetch_artifact_content(&self, artifact: &Artifact) -> Result<Bytes> {
        // Look up the repository's storage_path
        let storage_path: String =
            sqlx::query_scalar("SELECT storage_path FROM repositories WHERE id = $1")
                .bind(artifact.repository_id)
                .fetch_one(&self.db)
                .await
                .map_err(|e| {
                    AppError::Database(format!(
                        "Failed to fetch storage_path for repository {}: {}",
                        artifact.repository_id, e
                    ))
                })?;

        // Create a FilesystemStorage for this repository and read the artifact
        let storage = FilesystemStorage::new(&storage_path);
        let content = storage.get(&artifact.storage_key).await.map_err(|e| {
            AppError::Storage(format!(
                "Failed to read artifact {} (key={}): {}",
                artifact.id, artifact.storage_key, e
            ))
        })?;

        Ok(content)
    }

    /// Prepare a scan workspace directory with the artifact content.
    ///
    /// Creates a temporary directory under the shared scan workspace path,
    /// writes the artifact content, and extracts archives when applicable.
    /// Returns the path to the workspace directory.
    pub async fn prepare_scan_workspace(
        &self,
        artifact: &Artifact,
        content: &Bytes,
    ) -> Result<PathBuf> {
        let workspace_dir = PathBuf::from(&self.scan_workspace_path).join(artifact.id.to_string());

        tokio::fs::create_dir_all(&workspace_dir)
            .await
            .map_err(|e| {
                AppError::Storage(format!(
                    "Failed to create scan workspace {}: {}",
                    workspace_dir.display(),
                    e
                ))
            })?;

        let artifact_path = workspace_dir.join(&artifact.name);

        // Write the artifact content to the workspace
        tokio::fs::write(&artifact_path, content)
            .await
            .map_err(|e| {
                AppError::Storage(format!("Failed to write artifact to scan workspace: {}", e))
            })?;

        // Extract archives if applicable
        let name_lower = artifact.name.to_lowercase();
        if name_lower.ends_with(".tar.gz")
            || name_lower.ends_with(".tgz")
            || name_lower.ends_with(".crate")
            || name_lower.ends_with(".gem")
        {
            self.extract_tar_gz(content, &workspace_dir).await?;
        } else if name_lower.ends_with(".zip")
            || name_lower.ends_with(".whl")
            || name_lower.ends_with(".jar")
            || name_lower.ends_with(".nupkg")
        {
            self.extract_zip(content, &workspace_dir).await?;
        }

        Ok(workspace_dir)
    }

    /// Extract a tar.gz archive into the target directory.
    async fn extract_tar_gz(&self, content: &Bytes, target_dir: &Path) -> Result<()> {
        let content = content.clone();
        let target = target_dir.to_path_buf();

        tokio::task::spawn_blocking(move || {
            use flate2::read::GzDecoder;
            use tar::Archive;

            let decoder = GzDecoder::new(content.as_ref());
            let mut archive = Archive::new(decoder);
            archive
                .unpack(&target)
                .map_err(|e| AppError::Storage(format!("Failed to extract tar.gz archive: {}", e)))
        })
        .await
        .map_err(|e| AppError::Internal(format!("Archive extraction task failed: {}", e)))?
    }

    /// Extract a zip archive into the target directory.
    async fn extract_zip(&self, content: &Bytes, target_dir: &Path) -> Result<()> {
        let content = content.clone();
        let target = target_dir.to_path_buf();

        tokio::task::spawn_blocking(move || {
            use std::io::Cursor;

            let reader = Cursor::new(content.as_ref());
            let mut archive = zip::ZipArchive::new(reader)
                .map_err(|e| AppError::Storage(format!("Failed to open zip archive: {}", e)))?;

            for i in 0..archive.len() {
                let mut file = archive.by_index(i).map_err(|e| {
                    AppError::Storage(format!("Failed to read zip entry {}: {}", i, e))
                })?;

                let out_path = match file.enclosed_name() {
                    Some(path) => target.join(path),
                    None => continue, // Skip entries with unsafe paths
                };

                if file.is_dir() {
                    std::fs::create_dir_all(&out_path).map_err(|e| {
                        AppError::Storage(format!("Failed to create directory: {}", e))
                    })?;
                } else {
                    if let Some(parent) = out_path.parent() {
                        std::fs::create_dir_all(parent).map_err(|e| {
                            AppError::Storage(format!("Failed to create parent directory: {}", e))
                        })?;
                    }
                    let mut out_file = std::fs::File::create(&out_path)
                        .map_err(|e| AppError::Storage(format!("Failed to create file: {}", e)))?;
                    std::io::copy(&mut file, &mut out_file).map_err(|e| {
                        AppError::Storage(format!("Failed to write extracted file: {}", e))
                    })?;
                }
            }
            Ok(())
        })
        .await
        .map_err(|e| AppError::Internal(format!("Zip extraction task failed: {}", e)))?
    }

    /// Clean up a scan workspace directory.
    pub async fn cleanup_scan_workspace(&self, path: &Path) -> Result<()> {
        if path.starts_with(&self.scan_workspace_path) {
            tokio::fs::remove_dir_all(path).await.map_err(|e| {
                AppError::Storage(format!(
                    "Failed to clean up scan workspace {}: {}",
                    path.display(),
                    e
                ))
            })?;
        } else {
            warn!(
                "Refusing to clean up path outside scan workspace: {}",
                path.display()
            );
        }
        Ok(())
    }

    /// Update artifact quarantine_status based on scan findings.
    async fn update_quarantine_status(&self, artifact_id: Uuid, findings_count: i32) -> Result<()> {
        let status = if findings_count > 0 {
            "flagged"
        } else {
            "clean"
        };
        sqlx::query!(
            "UPDATE artifacts SET quarantine_status = $2 WHERE id = $1",
            artifact_id,
            status,
        )
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
        Ok(())
    }
}
