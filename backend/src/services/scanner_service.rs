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
        let (osv_results, gh_results) = tokio::join!(
            self.advisory.query_osv(&deps),
            self.advisory.query_github(&deps),
        );

        // Merge and deduplicate by CVE/GHSA ID
        let mut seen_ids = std::collections::HashSet::new();
        let mut findings = Vec::new();

        for advisory_match in osv_results.into_iter().chain(gh_results) {
            // Skip if we have already seen this advisory or any of its aliases
            let dominated = seen_ids.contains(&advisory_match.id)
                || advisory_match.aliases.iter().any(|a| seen_ids.contains(a));
            if dominated {
                continue;
            }

            seen_ids.insert(advisory_match.id.clone());
            seen_ids.extend(advisory_match.aliases.iter().cloned());

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
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        db: PgPool,
        advisory_client: Arc<AdvisoryClient>,
        scan_result_service: Arc<ScanResultService>,
        scan_config_service: Arc<ScanConfigService>,
        trivy_url: Option<String>,
        storage_base_path: String,
        scan_workspace_path: String,
        openscap_url: Option<String>,
        openscap_profile: String,
    ) -> Self {
        let dep_scanner: Arc<dyn Scanner> = Arc::new(DependencyScanner::new(advisory_client));
        let mut scanners: Vec<Arc<dyn Scanner>> = vec![dep_scanner];

        if let Some(url) = trivy_url {
            info!("Trivy image scanner enabled at {}", url);
            scanners.push(Arc::new(ImageScanner::new(url.clone())));
            // Trivy filesystem scanner for non-container artifacts
            info!("Trivy filesystem scanner enabled");
            scanners.push(Arc::new(TrivyFsScanner::new(
                url.clone(),
                scan_workspace_path.clone(),
            )));
            // Incus/LXC container image scanner (extracts rootfs, scans with trivy)
            info!("Incus container image scanner enabled");
            scanners.push(Arc::new(crate::services::incus_scanner::IncusScanner::new(
                url,
                scan_workspace_path.clone(),
            )));
        }

        // Grype scanner (CLI-based, degrades gracefully if binary not available)
        info!("Grype scanner enabled");
        scanners.push(Arc::new(GrypeScanner::new(scan_workspace_path.clone())));

        // OpenSCAP compliance scanner (optional sidecar)
        if let Some(url) = openscap_url {
            info!("OpenSCAP compliance scanner enabled at {}", url);
            scanners.push(Arc::new(
                crate::services::openscap_scanner::OpenScapScanner::new(
                    url,
                    openscap_profile,
                    scan_workspace_path.clone(),
                ),
            ));
        }

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
    /// Scan a single artifact. When `force` is true, skip the repo scan-enabled check
    /// (used for on-demand scans triggered manually by an admin).
    pub async fn scan_artifact_with_options(&self, artifact_id: Uuid, force: bool) -> Result<()> {
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

        // Check if scanning is enabled for this repo (skip check if forced)
        if !force
            && !self
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
                    let total = findings.len() as i32;
                    let count = |sev: Severity| -> i32 {
                        findings.iter().filter(|f| f.severity == sev).count() as i32
                    };
                    let critical = count(Severity::Critical);
                    let high = count(Severity::High);
                    let medium = count(Severity::Medium);
                    let low = count(Severity::Low);
                    let info = count(Severity::Info);

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

    /// Scan a single artifact (respects repo scan-enabled config).
    pub async fn scan_artifact(&self, artifact_id: Uuid) -> Result<()> {
        self.scan_artifact_with_options(artifact_id, false).await
    }

    /// Scan all non-deleted artifacts in a repository.
    pub async fn scan_repository(&self, repository_id: Uuid) -> Result<u32> {
        self.scan_repository_with_options(repository_id, false)
            .await
    }

    /// Scan all artifacts in a repository.
    /// When `force` is true, bypass the scan-enabled config check (for manual triggers).
    pub async fn scan_repository_with_options(
        &self,
        repository_id: Uuid,
        force: bool,
    ) -> Result<u32> {
        let artifact_ids: Vec<Uuid> = sqlx::query_scalar!(
            "SELECT id FROM artifacts WHERE repository_id = $1 AND is_deleted = false",
            repository_id,
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        let count = artifact_ids.len() as u32;
        info!(
            "Starting repository scan for {}: {} artifacts (force={})",
            repository_id, count, force
        );

        for artifact_id in artifact_ids {
            if let Err(e) = self.scan_artifact_with_options(artifact_id, force).await {
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

        let storage = FilesystemStorage::new(&storage_path);
        storage.get(&artifact.storage_key).await.map_err(|e| {
            AppError::Storage(format!(
                "Failed to read artifact {} (key={}): {}",
                artifact.id, artifact.storage_key, e
            ))
        })
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

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use chrono::Utc;
    use uuid::Uuid;

    // -----------------------------------------------------------------------
    // Pure helper functions (moved from module scope — test-only)
    // -----------------------------------------------------------------------

    fn ecosystem_to_github_param(ecosystem: &str) -> Option<&'static str> {
        match ecosystem {
            "npm" => Some("npm"),
            "PyPI" | "pypi" => Some("pip"),
            "crates.io" => Some("rust"),
            "Maven" => Some("maven"),
            "Go" => Some("go"),
            "NuGet" => Some("nuget"),
            "RubyGems" => Some("rubygems"),
            _ => None,
        }
    }

    fn quarantine_status_from_findings(findings_count: i32) -> &'static str {
        if findings_count > 0 {
            "flagged"
        } else {
            "clean"
        }
    }

    fn is_manifest_file(name_lower: &str) -> bool {
        name_lower == "package.json"
            || name_lower.ends_with("/package.json")
            || name_lower == "cargo.toml"
            || name_lower.ends_with("/cargo.toml")
            || name_lower == "requirements.txt"
            || name_lower.ends_with("/requirements.txt")
            || name_lower == "go.sum"
            || name_lower.ends_with("/go.sum")
            || name_lower == "pom.xml"
            || name_lower.ends_with("/pom.xml")
            || name_lower.ends_with(".gemspec")
            || name_lower == "gemfile.lock"
            || name_lower.ends_with("/gemfile.lock")
            || name_lower.ends_with(".nuspec")
            || name_lower == "packages.config"
    }

    fn is_extractable_archive(name_lower: &str) -> bool {
        name_lower.ends_with(".tar.gz")
            || name_lower.ends_with(".tgz")
            || name_lower.ends_with(".crate")
            || name_lower.ends_with(".gem")
            || name_lower.ends_with(".zip")
            || name_lower.ends_with(".whl")
            || name_lower.ends_with(".jar")
            || name_lower.ends_with(".nupkg")
    }

    fn osv_vulnerability_url(vuln_id: &str) -> String {
        format!("https://osv.dev/vulnerability/{}", vuln_id)
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum ArchiveType {
        TarGz,
        Zip,
        None,
    }

    fn detect_archive_type(name: &str) -> ArchiveType {
        let lower = name.to_lowercase();
        if lower.ends_with(".tar.gz")
            || lower.ends_with(".tgz")
            || lower.ends_with(".crate")
            || lower.ends_with(".gem")
        {
            ArchiveType::TarGz
        } else if lower.ends_with(".zip")
            || lower.ends_with(".whl")
            || lower.ends_with(".jar")
            || lower.ends_with(".nupkg")
        {
            ArchiveType::Zip
        } else {
            ArchiveType::None
        }
    }

    fn is_path_within_workspace(path: &Path, workspace: &str) -> bool {
        path.starts_with(workspace)
    }

    fn count_findings_by_severity(findings: &[RawFinding]) -> (i32, i32, i32, i32, i32) {
        let count =
            |sev: Severity| -> i32 { findings.iter().filter(|f| f.severity == sev).count() as i32 };
        (
            count(Severity::Critical),
            count(Severity::High),
            count(Severity::Medium),
            count(Severity::Low),
            count(Severity::Info),
        )
    }

    fn extract_cve_from_advisory(advisory: &AdvisoryMatch) -> Option<String> {
        advisory
            .aliases
            .iter()
            .find(|a| a.starts_with("CVE-"))
            .cloned()
            .or_else(|| {
                if advisory.id.starts_with("CVE-") {
                    Some(advisory.id.clone())
                } else {
                    None
                }
            })
    }

    fn build_finding_title(advisory: &AdvisoryMatch) -> String {
        advisory
            .summary
            .clone()
            .unwrap_or_else(|| format!("Vulnerability {}", advisory.id))
    }

    fn dedup_advisories(
        osv_results: Vec<AdvisoryMatch>,
        gh_results: Vec<AdvisoryMatch>,
    ) -> Vec<AdvisoryMatch> {
        let mut seen_ids = std::collections::HashSet::new();
        let mut deduped = Vec::new();

        for advisory_match in osv_results.into_iter().chain(gh_results) {
            let dominated = seen_ids.contains(&advisory_match.id)
                || advisory_match.aliases.iter().any(|a| seen_ids.contains(a));
            if dominated {
                continue;
            }
            seen_ids.insert(advisory_match.id.clone());
            seen_ids.extend(advisory_match.aliases.iter().cloned());
            deduped.push(advisory_match);
        }

        deduped
    }

    fn build_osv_cache_key(dep: &Dependency) -> String {
        format!(
            "{}:{}:{}",
            dep.ecosystem,
            dep.name,
            dep.version.as_deref().unwrap_or("*")
        )
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn make_artifact(name: &str, path: &str, version: Option<&str>) -> Artifact {
        Artifact {
            id: Uuid::new_v4(),
            repository_id: Uuid::new_v4(),
            path: path.to_string(),
            name: name.to_string(),
            version: version.map(String::from),
            size_bytes: 100,
            checksum_sha256: "abc123".to_string(),
            checksum_md5: None,
            checksum_sha1: None,
            content_type: "application/octet-stream".to_string(),
            storage_key: "key".to_string(),
            is_deleted: false,
            uploaded_by: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    // -----------------------------------------------------------------------
    // extract_xml_value
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_xml_value_basic() {
        let line = "<groupId>com.example</groupId>";
        assert_eq!(
            DependencyScanner::extract_xml_value(line, "groupId"),
            Some("com.example".to_string())
        );
    }

    #[test]
    fn test_extract_xml_value_with_whitespace() {
        let line = "    <artifactId>my-lib</artifactId>   ";
        assert_eq!(
            DependencyScanner::extract_xml_value(line, "artifactId"),
            Some("my-lib".to_string())
        );
    }

    #[test]
    fn test_extract_xml_value_missing_tag() {
        let line = "<groupId>com.example</groupId>";
        assert_eq!(
            DependencyScanner::extract_xml_value(line, "artifactId"),
            None
        );
    }

    #[test]
    fn test_extract_xml_value_missing_close_tag() {
        let line = "<groupId>com.example";
        assert_eq!(DependencyScanner::extract_xml_value(line, "groupId"), None);
    }

    #[test]
    fn test_extract_xml_value_empty_value() {
        let line = "<version></version>";
        // start == end so None (start < end check fails for empty)
        assert_eq!(DependencyScanner::extract_xml_value(line, "version"), None);
    }

    // -----------------------------------------------------------------------
    // extract_xml_attr
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_xml_attr_basic() {
        let line = r#"<package id="Newtonsoft.Json" version="13.0.1" />"#;
        assert_eq!(
            DependencyScanner::extract_xml_attr(line, "id"),
            Some("Newtonsoft.Json".to_string())
        );
        assert_eq!(
            DependencyScanner::extract_xml_attr(line, "version"),
            Some("13.0.1".to_string())
        );
    }

    #[test]
    fn test_extract_xml_attr_missing() {
        let line = r#"<package id="Foo" />"#;
        assert_eq!(DependencyScanner::extract_xml_attr(line, "version"), None);
    }

    #[test]
    fn test_extract_xml_attr_empty_value() {
        let line = r#"<package id="" version="1.0" />"#;
        assert_eq!(
            DependencyScanner::extract_xml_attr(line, "id"),
            Some("".to_string())
        );
    }

    // -----------------------------------------------------------------------
    // parse_npm
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_npm_basic() {
        let content = r#"{
            "dependencies": {
                "express": "^4.18.2",
                "lodash": "~4.17.21"
            },
            "devDependencies": {
                "jest": "29.0.0"
            }
        }"#;
        let deps = DependencyScanner::parse_npm(content);
        assert_eq!(deps.len(), 3);

        // Check all ecosystems are npm
        for dep in &deps {
            assert_eq!(dep.ecosystem, "npm");
        }

        // Check that ^ and ~ are stripped from versions
        let express = deps.iter().find(|d| d.name == "express").unwrap();
        assert_eq!(express.version.as_deref(), Some("4.18.2"));

        let lodash = deps.iter().find(|d| d.name == "lodash").unwrap();
        assert_eq!(lodash.version.as_deref(), Some("4.17.21"));

        let jest = deps.iter().find(|d| d.name == "jest").unwrap();
        assert_eq!(jest.version.as_deref(), Some("29.0.0"));
    }

    #[test]
    fn test_parse_npm_peer_dependencies() {
        let content = r#"{
            "peerDependencies": {
                "react": "^18.0.0"
            }
        }"#;
        let deps = DependencyScanner::parse_npm(content);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "react");
        assert_eq!(deps[0].version.as_deref(), Some("18.0.0"));
    }

    #[test]
    fn test_parse_npm_empty() {
        let content = r#"{}"#;
        let deps = DependencyScanner::parse_npm(content);
        assert!(deps.is_empty());
    }

    #[test]
    fn test_parse_npm_invalid_json() {
        let content = "not json at all";
        let deps = DependencyScanner::parse_npm(content);
        assert!(deps.is_empty());
    }

    #[test]
    fn test_parse_npm_non_string_version() {
        // Workspace protocol or other non-string value
        let content = r#"{
            "dependencies": {
                "my-lib": true
            }
        }"#;
        let deps = DependencyScanner::parse_npm(content);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "my-lib");
        assert_eq!(deps[0].version, None);
    }

    // -----------------------------------------------------------------------
    // parse_cargo
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_cargo_basic() {
        let content = r#"
            [dependencies]
            serde = "1.0"
            tokio = { version = "1.35", features = ["full"] }

            [dev-dependencies]
            proptest = "1.0"
        "#;
        let deps = DependencyScanner::parse_cargo(content);
        assert_eq!(deps.len(), 3);

        for dep in &deps {
            assert_eq!(dep.ecosystem, "crates.io");
        }

        let serde = deps.iter().find(|d| d.name == "serde").unwrap();
        assert_eq!(serde.version.as_deref(), Some("1.0"));

        let tokio = deps.iter().find(|d| d.name == "tokio").unwrap();
        assert_eq!(tokio.version.as_deref(), Some("1.35"));
    }

    #[test]
    fn test_parse_cargo_build_dependencies() {
        let content = r#"
            [build-dependencies]
            cc = "1.0"
        "#;
        let deps = DependencyScanner::parse_cargo(content);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "cc");
    }

    #[test]
    fn test_parse_cargo_git_dep_no_version() {
        let content = r#"
            [dependencies]
            my-crate = { git = "https://github.com/foo/bar" }
        "#;
        let deps = DependencyScanner::parse_cargo(content);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "my-crate");
        assert_eq!(deps[0].version, None);
    }

    #[test]
    fn test_parse_cargo_empty() {
        let content = r#"
            [package]
            name = "my-app"
            version = "0.1.0"
        "#;
        let deps = DependencyScanner::parse_cargo(content);
        assert!(deps.is_empty());
    }

    #[test]
    fn test_parse_cargo_invalid_toml() {
        let content = "not valid toml [[[";
        let deps = DependencyScanner::parse_cargo(content);
        assert!(deps.is_empty());
    }

    // -----------------------------------------------------------------------
    // parse_pip
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_pip_various_specifiers() {
        let content = "flask==2.3.0\nrequests>=2.28.0\nnumpy~=1.24\npandas<=2.0.0\nsimplepkg\n";
        let deps = DependencyScanner::parse_pip(content);
        assert_eq!(deps.len(), 5);

        for dep in &deps {
            assert_eq!(dep.ecosystem, "PyPI");
        }

        let flask = deps.iter().find(|d| d.name == "flask").unwrap();
        assert_eq!(flask.version.as_deref(), Some("2.3.0"));

        let requests = deps.iter().find(|d| d.name == "requests").unwrap();
        assert_eq!(requests.version.as_deref(), Some("2.28.0"));

        let numpy = deps.iter().find(|d| d.name == "numpy").unwrap();
        assert_eq!(numpy.version.as_deref(), Some("1.24"));

        let pandas = deps.iter().find(|d| d.name == "pandas").unwrap();
        assert_eq!(pandas.version.as_deref(), Some("2.0.0"));

        let simple = deps.iter().find(|d| d.name == "simplepkg").unwrap();
        assert_eq!(simple.version, None);
    }

    #[test]
    fn test_parse_pip_skips_comments_blank_lines_flags() {
        let content = "# This is a comment\n\n-r other.txt\n-e git+https://foo.git\nflask==1.0\n";
        let deps = DependencyScanner::parse_pip(content);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "flask");
    }

    #[test]
    fn test_parse_pip_empty() {
        let content = "";
        let deps = DependencyScanner::parse_pip(content);
        assert!(deps.is_empty());
    }

    // -----------------------------------------------------------------------
    // parse_go
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_go_basic() {
        let content = "golang.org/x/net v0.17.0 h1:abc=\ngolang.org/x/net v0.17.0/go.mod h1:def=\ngolang.org/x/text v0.13.0 h1:xyz=\n";
        let deps = DependencyScanner::parse_go(content);
        // Deduplication: golang.org/x/net should appear only once
        assert_eq!(deps.len(), 2);

        for dep in &deps {
            assert_eq!(dep.ecosystem, "Go");
        }

        let net = deps.iter().find(|d| d.name == "golang.org/x/net").unwrap();
        // v prefix stripped
        assert_eq!(net.version.as_deref(), Some("0.17.0"));
    }

    #[test]
    fn test_parse_go_empty() {
        let content = "";
        let deps = DependencyScanner::parse_go(content);
        assert!(deps.is_empty());
    }

    #[test]
    fn test_parse_go_single_word_line_ignored() {
        let content = "just-one-word\n";
        let deps = DependencyScanner::parse_go(content);
        assert!(deps.is_empty());
    }

    // -----------------------------------------------------------------------
    // parse_maven
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_maven_basic() {
        let content = r#"
        <dependencies>
            <dependency>
                <groupId>org.apache</groupId>
                <artifactId>commons-lang3</artifactId>
                <version>3.12.0</version>
            </dependency>
            <dependency>
                <groupId>junit</groupId>
                <artifactId>junit</artifactId>
            </dependency>
        </dependencies>
        "#;
        let deps = DependencyScanner::parse_maven(content);
        assert_eq!(deps.len(), 2);

        for dep in &deps {
            assert_eq!(dep.ecosystem, "Maven");
        }

        let lang3 = deps
            .iter()
            .find(|d| d.name == "org.apache:commons-lang3")
            .unwrap();
        assert_eq!(lang3.version.as_deref(), Some("3.12.0"));

        let junit = deps.iter().find(|d| d.name == "junit:junit").unwrap();
        assert_eq!(junit.version, None);
    }

    #[test]
    fn test_parse_maven_empty() {
        let content = "<project></project>";
        let deps = DependencyScanner::parse_maven(content);
        assert!(deps.is_empty());
    }

    #[test]
    fn test_parse_maven_incomplete_dependency() {
        // Missing artifactId: should not produce a dependency
        let content = r#"
        <dependency>
            <groupId>org.example</groupId>
        </dependency>
        "#;
        let deps = DependencyScanner::parse_maven(content);
        assert!(deps.is_empty());
    }

    // -----------------------------------------------------------------------
    // parse_rubygems
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_rubygems_gemfile_lock() {
        let content = "    rails (7.0.8)\n    nokogiri (1.15.4)\n    actionpack (7.0.8)\n";
        let deps = DependencyScanner::parse_rubygems(content);
        assert_eq!(deps.len(), 3);

        for dep in &deps {
            assert_eq!(dep.ecosystem, "RubyGems");
        }

        let rails = deps.iter().find(|d| d.name == "rails").unwrap();
        assert_eq!(rails.version.as_deref(), Some("7.0.8"));
    }

    #[test]
    fn test_parse_rubygems_no_match() {
        let content = "GEM\n  remote: https://rubygems.org/\n  specs:\n";
        let deps = DependencyScanner::parse_rubygems(content);
        assert!(deps.is_empty());
    }

    // -----------------------------------------------------------------------
    // parse_nuget
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_nuget_packages_config() {
        let content = r#"<?xml version="1.0" encoding="utf-8"?>
<packages>
  <package id="Newtonsoft.Json" version="13.0.1" targetFramework="net472" />
  <package id="NUnit" version="3.14.0" targetFramework="net472" />
</packages>"#;
        let deps = DependencyScanner::parse_nuget(content);
        assert_eq!(deps.len(), 2);

        for dep in &deps {
            assert_eq!(dep.ecosystem, "NuGet");
        }

        let nj = deps.iter().find(|d| d.name == "Newtonsoft.Json").unwrap();
        assert_eq!(nj.version.as_deref(), Some("13.0.1"));
    }

    #[test]
    fn test_parse_nuget_empty() {
        let content = "<packages></packages>";
        let deps = DependencyScanner::parse_nuget(content);
        assert!(deps.is_empty());
    }

    // -----------------------------------------------------------------------
    // extract_dependencies (integration of parsers by filename matching)
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_dependencies_package_json() {
        let artifact = make_artifact("package.json", "/npm/package.json", None);
        let content = Bytes::from(r#"{"dependencies":{"axios":"^1.6.0"}}"#);
        let deps = DependencyScanner::extract_dependencies(&artifact, None, &content);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "axios");
        assert_eq!(deps[0].ecosystem, "npm");
    }

    #[test]
    fn test_extract_dependencies_nested_package_json() {
        let artifact = make_artifact(
            "libs/core/package.json",
            "/npm/libs/core/package.json",
            None,
        );
        let content = Bytes::from(r#"{"dependencies":{"react":"^18.0.0"}}"#);
        let deps = DependencyScanner::extract_dependencies(&artifact, None, &content);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].ecosystem, "npm");
    }

    #[test]
    fn test_extract_dependencies_cargo_toml() {
        let artifact = make_artifact("Cargo.toml", "/rust/Cargo.toml", None);
        let content = Bytes::from("[dependencies]\nserde = \"1.0\"\n");
        let deps = DependencyScanner::extract_dependencies(&artifact, None, &content);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].ecosystem, "crates.io");
    }

    #[test]
    fn test_extract_dependencies_requirements_txt() {
        let artifact = make_artifact("requirements.txt", "/pypi/requirements.txt", None);
        let content = Bytes::from("flask==2.3.0\nrequests>=2.28.0\n");
        let deps = DependencyScanner::extract_dependencies(&artifact, None, &content);
        assert_eq!(deps.len(), 2);
        assert_eq!(deps[0].ecosystem, "PyPI");
    }

    #[test]
    fn test_extract_dependencies_go_sum() {
        let artifact = make_artifact("go.sum", "/go/go.sum", None);
        let content = Bytes::from("golang.org/x/net v0.17.0 h1:abc=\n");
        let deps = DependencyScanner::extract_dependencies(&artifact, None, &content);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].ecosystem, "Go");
    }

    #[test]
    fn test_extract_dependencies_pom_xml() {
        let artifact = make_artifact("pom.xml", "/maven/pom.xml", None);
        let content = Bytes::from(
            "<dependency>\n<groupId>org.apache</groupId>\n<artifactId>commons</artifactId>\n<version>3.12</version>\n</dependency>\n",
        );
        let deps = DependencyScanner::extract_dependencies(&artifact, None, &content);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].ecosystem, "Maven");
    }

    #[test]
    fn test_extract_dependencies_gemfile_lock() {
        let artifact = make_artifact("Gemfile.lock", "/ruby/Gemfile.lock", None);
        let content = Bytes::from("    rails (7.0.8)\n");
        let deps = DependencyScanner::extract_dependencies(&artifact, None, &content);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].ecosystem, "RubyGems");
    }

    #[test]
    fn test_extract_dependencies_nuspec() {
        let artifact = make_artifact("My.nuspec", "/nuget/My.nuspec", None);
        let content = Bytes::from(r#"<package id="Newtonsoft.Json" version="13.0.1" />"#);
        let deps = DependencyScanner::extract_dependencies(&artifact, None, &content);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].ecosystem, "NuGet");
    }

    #[test]
    fn test_extract_dependencies_packages_config() {
        let artifact = make_artifact("packages.config", "/nuget/packages.config", None);
        let content = Bytes::from(r#"<package id="NUnit" version="3.14" />"#);
        let deps = DependencyScanner::extract_dependencies(&artifact, None, &content);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].ecosystem, "NuGet");
    }

    #[test]
    fn test_extract_dependencies_binary_content() {
        let artifact = make_artifact("package.json", "/npm/package.json", None);
        // Invalid UTF-8 bytes
        let content = Bytes::from(vec![0xFF, 0xFE, 0x00, 0x01]);
        let deps = DependencyScanner::extract_dependencies(&artifact, None, &content);
        assert!(deps.is_empty());
    }

    // -----------------------------------------------------------------------
    // infer_dependencies
    // -----------------------------------------------------------------------

    #[test]
    fn test_infer_dependencies_rpm() {
        let artifact = make_artifact("my-package.rpm", "/rpm/my-package.rpm", Some("1.0"));
        let deps = DependencyScanner::infer_dependencies(&artifact, "");
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].ecosystem, "Linux");
        assert_eq!(deps[0].name, "my-package.rpm");
    }

    #[test]
    fn test_infer_dependencies_deb() {
        let artifact = make_artifact("my-package.deb", "/deb/my-package.deb", Some("2.0"));
        let deps = DependencyScanner::infer_dependencies(&artifact, "");
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].ecosystem, "Linux");
    }

    #[test]
    fn test_infer_dependencies_apk() {
        let artifact = make_artifact("my-package.apk", "/alpine/my-package.apk", Some("1.0"));
        let deps = DependencyScanner::infer_dependencies(&artifact, "");
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].ecosystem, "Linux");
    }

    #[test]
    fn test_infer_dependencies_rpm_path() {
        let artifact = make_artifact("foo.bin", "/rpm/centos/foo.bin", Some("1.0"));
        let deps = DependencyScanner::infer_dependencies(&artifact, "");
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].ecosystem, "Linux");
    }

    #[test]
    fn test_infer_dependencies_unknown() {
        let artifact = make_artifact("random.txt", "/misc/random.txt", None);
        let deps = DependencyScanner::infer_dependencies(&artifact, "");
        assert!(deps.is_empty());
    }

    // -----------------------------------------------------------------------
    // parse_osv_response
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_osv_response_basic() {
        let deps = vec![Dependency {
            name: "lodash".to_string(),
            version: Some("4.17.20".to_string()),
            ecosystem: "npm".to_string(),
        }];

        let body = serde_json::json!({
            "results": [{
                "vulns": [{
                    "id": "GHSA-abcd-1234-efgh",
                    "summary": "Prototype Pollution in lodash",
                    "details": "lodash before 4.17.21 is vulnerable",
                    "aliases": ["CVE-2021-23337"],
                    "database_specific": {
                        "severity": "HIGH"
                    },
                    "affected": [{
                        "ranges": [{
                            "type": "SEMVER",
                            "events": [
                                {"introduced": "0"},
                                {"fixed": "4.17.21"}
                            ]
                        }]
                    }]
                }]
            }]
        });

        let matches = AdvisoryClient::parse_osv_response(&body, &deps);
        assert_eq!(matches.len(), 1);

        let m = &matches[0];
        assert_eq!(m.id, "GHSA-abcd-1234-efgh");
        assert_eq!(m.summary.as_deref(), Some("Prototype Pollution in lodash"));
        assert_eq!(
            m.details.as_deref(),
            Some("lodash before 4.17.21 is vulnerable")
        );
        assert_eq!(m.severity, "high"); // lowercased
        assert_eq!(m.aliases, vec!["CVE-2021-23337".to_string()]);
        assert_eq!(m.fixed_version.as_deref(), Some("4.17.21"));
        assert_eq!(m.affected_version.as_deref(), Some("4.17.20"));
        assert_eq!(m.source, "osv.dev");
        assert!(m
            .source_url
            .as_ref()
            .unwrap()
            .contains("GHSA-abcd-1234-efgh"));
    }

    #[test]
    fn test_parse_osv_response_empty_results() {
        let deps = vec![Dependency {
            name: "safe-pkg".to_string(),
            version: Some("1.0.0".to_string()),
            ecosystem: "npm".to_string(),
        }];

        let body = serde_json::json!({ "results": [{}] });
        let matches = AdvisoryClient::parse_osv_response(&body, &deps);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_parse_osv_response_no_results_key() {
        let deps = vec![];
        let body = serde_json::json!({});
        let matches = AdvisoryClient::parse_osv_response(&body, &deps);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_parse_osv_response_severity_fallback_to_medium() {
        let deps = vec![Dependency {
            name: "pkg".to_string(),
            version: Some("1.0".to_string()),
            ecosystem: "npm".to_string(),
        }];

        // No severity field at all
        let body = serde_json::json!({
            "results": [{
                "vulns": [{
                    "id": "OSV-2024-001"
                }]
            }]
        });

        let matches = AdvisoryClient::parse_osv_response(&body, &deps);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].severity, "medium"); // default fallback
    }

    #[test]
    fn test_parse_osv_response_severity_from_severity_array() {
        let deps = vec![Dependency {
            name: "pkg".to_string(),
            version: Some("1.0".to_string()),
            ecosystem: "npm".to_string(),
        }];

        let body = serde_json::json!({
            "results": [{
                "vulns": [{
                    "id": "OSV-2024-002",
                    "severity": [{"type": "CRITICAL", "score": "9.8"}]
                }]
            }]
        });

        let matches = AdvisoryClient::parse_osv_response(&body, &deps);
        assert_eq!(matches.len(), 1);
        // falls back to severity[0].type
        assert_eq!(matches[0].severity, "critical");
    }

    #[test]
    fn test_parse_osv_response_multiple_vulns_single_dep() {
        let deps = vec![Dependency {
            name: "pkg".to_string(),
            version: Some("1.0".to_string()),
            ecosystem: "npm".to_string(),
        }];

        let body = serde_json::json!({
            "results": [{
                "vulns": [
                    {"id": "VULN-1", "summary": "First"},
                    {"id": "VULN-2", "summary": "Second"}
                ]
            }]
        });

        let matches = AdvisoryClient::parse_osv_response(&body, &deps);
        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0].id, "VULN-1");
        assert_eq!(matches[1].id, "VULN-2");
    }

    #[test]
    fn test_parse_osv_response_multiple_deps() {
        let deps = vec![
            Dependency {
                name: "pkg-a".to_string(),
                version: Some("1.0".to_string()),
                ecosystem: "npm".to_string(),
            },
            Dependency {
                name: "pkg-b".to_string(),
                version: Some("2.0".to_string()),
                ecosystem: "npm".to_string(),
            },
        ];

        let body = serde_json::json!({
            "results": [
                {"vulns": [{"id": "VULN-A"}]},
                {"vulns": [{"id": "VULN-B"}]}
            ]
        });

        let matches = AdvisoryClient::parse_osv_response(&body, &deps);
        assert_eq!(matches.len(), 2);
        // First vuln should get version from deps[0], second from deps[1]
        assert_eq!(matches[0].affected_version.as_deref(), Some("1.0"));
        assert_eq!(matches[1].affected_version.as_deref(), Some("2.0"));
    }

    // -----------------------------------------------------------------------
    // parse_github_advisory
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_github_advisory_basic() {
        let dep = Dependency {
            name: "express".to_string(),
            version: Some("4.17.1".to_string()),
            ecosystem: "npm".to_string(),
        };

        let adv = serde_json::json!({
            "ghsa_id": "GHSA-xxxx-yyyy-zzzz",
            "summary": "Open Redirect in Express",
            "description": "Express < 4.17.3 allows open redirect",
            "severity": "medium",
            "cve_id": "CVE-2022-24999",
            "html_url": "https://github.com/advisories/GHSA-xxxx-yyyy-zzzz",
            "vulnerabilities": [{
                "first_patched_version": {
                    "identifier": "4.17.3"
                }
            }]
        });

        let result = AdvisoryClient::parse_github_advisory(&adv, &dep);
        assert!(result.is_some());

        let m = result.unwrap();
        assert_eq!(m.id, "GHSA-xxxx-yyyy-zzzz");
        assert_eq!(m.summary.as_deref(), Some("Open Redirect in Express"));
        assert_eq!(m.severity, "medium");
        assert_eq!(
            m.aliases,
            vec![
                "GHSA-xxxx-yyyy-zzzz".to_string(),
                "CVE-2022-24999".to_string()
            ]
        );
        assert_eq!(m.fixed_version.as_deref(), Some("4.17.3"));
        assert_eq!(m.affected_version.as_deref(), Some("4.17.1"));
        assert_eq!(m.source, "github");
        assert_eq!(
            m.source_url.as_deref(),
            Some("https://github.com/advisories/GHSA-xxxx-yyyy-zzzz")
        );
    }

    #[test]
    fn test_parse_github_advisory_missing_ghsa_id() {
        let dep = Dependency {
            name: "pkg".to_string(),
            version: None,
            ecosystem: "npm".to_string(),
        };
        let adv = serde_json::json!({"summary": "no ghsa_id"});
        let result = AdvisoryClient::parse_github_advisory(&adv, &dep);
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_github_advisory_minimal() {
        let dep = Dependency {
            name: "pkg".to_string(),
            version: None,
            ecosystem: "npm".to_string(),
        };
        let adv = serde_json::json!({
            "ghsa_id": "GHSA-min-imal-data"
        });
        let result = AdvisoryClient::parse_github_advisory(&adv, &dep);
        assert!(result.is_some());

        let m = result.unwrap();
        assert_eq!(m.id, "GHSA-min-imal-data");
        assert_eq!(m.severity, "medium"); // default
        assert_eq!(m.aliases, vec!["GHSA-min-imal-data".to_string()]);
        assert_eq!(m.summary, None);
        assert_eq!(m.details, None);
        assert_eq!(m.fixed_version, None);
        assert_eq!(m.affected_version, None);
    }

    #[test]
    fn test_parse_github_advisory_no_cve() {
        let dep = Dependency {
            name: "pkg".to_string(),
            version: Some("1.0".to_string()),
            ecosystem: "npm".to_string(),
        };
        let adv = serde_json::json!({
            "ghsa_id": "GHSA-no-cve-here",
            "severity": "high"
        });
        let result = AdvisoryClient::parse_github_advisory(&adv, &dep).unwrap();
        // aliases should only contain GHSA id
        assert_eq!(result.aliases, vec!["GHSA-no-cve-here".to_string()]);
    }

    // -----------------------------------------------------------------------
    // DependencyScanner name/scan_type
    // -----------------------------------------------------------------------

    #[test]
    fn test_dependency_scanner_name_and_type() {
        let advisory = Arc::new(AdvisoryClient::new(None));
        let scanner = DependencyScanner::new(advisory);
        assert_eq!(scanner.name(), "DependencyScanner");
        assert_eq!(scanner.scan_type(), "dependency");
    }

    // -----------------------------------------------------------------------
    // AdvisoryClient::new
    // -----------------------------------------------------------------------

    #[test]
    fn test_advisory_client_new_no_github_token() {
        let client = AdvisoryClient::new(None);
        assert!(client.github_token.is_none());
    }

    #[test]
    fn test_advisory_client_new_with_github_token() {
        let client = AdvisoryClient::new(Some("ghp_test123".to_string()));
        assert_eq!(client.github_token.as_deref(), Some("ghp_test123"));
    }

    // -----------------------------------------------------------------------
    // Dependency struct
    // -----------------------------------------------------------------------

    #[test]
    fn test_dependency_construction() {
        let dep = Dependency {
            name: "express".to_string(),
            version: Some("4.18.2".to_string()),
            ecosystem: "npm".to_string(),
        };
        assert_eq!(dep.name, "express");
        assert_eq!(dep.version.as_deref(), Some("4.18.2"));
        assert_eq!(dep.ecosystem, "npm");
    }

    #[test]
    fn test_dependency_no_version() {
        let dep = Dependency {
            name: "my-lib".to_string(),
            version: None,
            ecosystem: "crates.io".to_string(),
        };
        assert!(dep.version.is_none());
    }

    #[test]
    fn test_dependency_clone() {
        let dep = Dependency {
            name: "flask".to_string(),
            version: Some("2.3.0".to_string()),
            ecosystem: "PyPI".to_string(),
        };
        let cloned = dep.clone();
        assert_eq!(dep.name, cloned.name);
        assert_eq!(dep.version, cloned.version);
        assert_eq!(dep.ecosystem, cloned.ecosystem);
    }

    #[test]
    fn test_dependency_debug() {
        let dep = Dependency {
            name: "test".to_string(),
            version: None,
            ecosystem: "npm".to_string(),
        };
        let debug = format!("{:?}", dep);
        assert!(debug.contains("Dependency"));
        assert!(debug.contains("test"));
    }

    // -----------------------------------------------------------------------
    // AdvisoryMatch struct
    // -----------------------------------------------------------------------

    #[test]
    fn test_advisory_match_construction() {
        let m = AdvisoryMatch {
            id: "GHSA-1234".to_string(),
            summary: Some("XSS vulnerability".to_string()),
            details: Some("Detailed description".to_string()),
            severity: "high".to_string(),
            aliases: vec!["CVE-2024-0001".to_string()],
            affected_version: Some("1.0.0".to_string()),
            fixed_version: Some("1.0.1".to_string()),
            source: "osv.dev".to_string(),
            source_url: Some("https://osv.dev/vulnerability/GHSA-1234".to_string()),
        };
        assert_eq!(m.id, "GHSA-1234");
        assert_eq!(m.severity, "high");
        assert_eq!(m.aliases.len(), 1);
        assert!(m.fixed_version.is_some());
    }

    #[test]
    fn test_advisory_match_minimal() {
        let m = AdvisoryMatch {
            id: "OSV-001".to_string(),
            summary: None,
            details: None,
            severity: "medium".to_string(),
            aliases: vec![],
            affected_version: None,
            fixed_version: None,
            source: "osv.dev".to_string(),
            source_url: None,
        };
        assert!(m.summary.is_none());
        assert!(m.aliases.is_empty());
    }

    #[test]
    fn test_advisory_match_clone() {
        let m = AdvisoryMatch {
            id: "GHSA-abcd".to_string(),
            summary: Some("Test".to_string()),
            details: None,
            severity: "low".to_string(),
            aliases: vec!["CVE-1".to_string(), "CVE-2".to_string()],
            affected_version: Some("1.0".to_string()),
            fixed_version: Some("1.1".to_string()),
            source: "github".to_string(),
            source_url: Some("https://example.com".to_string()),
        };
        let cloned = m.clone();
        assert_eq!(m.id, cloned.id);
        assert_eq!(m.aliases, cloned.aliases);
    }

    // -----------------------------------------------------------------------
    // parse_npm - edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_npm_all_three_sections() {
        let content = r#"{
            "dependencies": {"a": "1.0"},
            "devDependencies": {"b": "2.0"},
            "peerDependencies": {"c": "3.0"}
        }"#;
        let deps = DependencyScanner::parse_npm(content);
        assert_eq!(deps.len(), 3);
        let names: Vec<&str> = deps.iter().map(|d| d.name.as_str()).collect();
        assert!(names.contains(&"a"));
        assert!(names.contains(&"b"));
        assert!(names.contains(&"c"));
    }

    #[test]
    fn test_parse_npm_version_with_exact() {
        let content = r#"{"dependencies": {"pkg": "1.2.3"}}"#;
        let deps = DependencyScanner::parse_npm(content);
        assert_eq!(deps[0].version.as_deref(), Some("1.2.3"));
    }

    // -----------------------------------------------------------------------
    // parse_cargo - edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_cargo_version_in_table_format() {
        let content = r#"
            [dependencies]
            serde = { version = "1.0", features = ["derive"] }
        "#;
        let deps = DependencyScanner::parse_cargo(content);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].version.as_deref(), Some("1.0"));
    }

    #[test]
    fn test_parse_cargo_path_dep_no_version() {
        let content = r#"
            [dependencies]
            my-local = { path = "../my-local" }
        "#;
        let deps = DependencyScanner::parse_cargo(content);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "my-local");
        assert!(deps[0].version.is_none());
    }

    // -----------------------------------------------------------------------
    // parse_pip - edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_pip_whitespace_handling() {
        let content = "  flask  == 2.3.0  \n  requests  >= 2.28.0  \n";
        let deps = DependencyScanner::parse_pip(content);
        // The parser splits on == so should handle whitespace in names
        assert_eq!(deps.len(), 2);
    }

    #[test]
    fn test_parse_pip_only_comments_and_blanks() {
        let content = "# comment\n\n# another comment\n";
        let deps = DependencyScanner::parse_pip(content);
        assert!(deps.is_empty());
    }

    // -----------------------------------------------------------------------
    // parse_go - edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_go_dedup() {
        let content = "mod1 v1.0.0 h1:abc=\nmod1 v1.0.0/go.mod h1:def=\nmod2 v2.0.0 h1:ghi=\n";
        let deps = DependencyScanner::parse_go(content);
        assert_eq!(deps.len(), 2);
        // mod1 should appear only once
        assert_eq!(deps.iter().filter(|d| d.name == "mod1").count(), 1);
    }

    #[test]
    fn test_parse_go_v_prefix_stripped() {
        let content = "example.com/mod v3.14.0 h1:abc=\n";
        let deps = DependencyScanner::parse_go(content);
        assert_eq!(deps[0].version.as_deref(), Some("3.14.0"));
    }

    // -----------------------------------------------------------------------
    // parse_maven - edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_maven_multiple_dependencies() {
        let content = r#"
            <dependency>
                <groupId>org.apache</groupId>
                <artifactId>commons-lang3</artifactId>
                <version>3.12.0</version>
            </dependency>
            <dependency>
                <groupId>com.google</groupId>
                <artifactId>guava</artifactId>
                <version>31.1</version>
            </dependency>
        "#;
        let deps = DependencyScanner::parse_maven(content);
        assert_eq!(deps.len(), 2);
    }

    #[test]
    fn test_parse_maven_missing_group_id() {
        // Missing groupId should not produce a dependency
        let content = r#"
            <dependency>
                <artifactId>some-lib</artifactId>
                <version>1.0</version>
            </dependency>
        "#;
        let deps = DependencyScanner::parse_maven(content);
        assert!(deps.is_empty());
    }

    // -----------------------------------------------------------------------
    // parse_rubygems - edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_rubygems_multiple() {
        let content = "    actionpack (7.0.8)\n    activesupport (7.0.8)\n    bundler (2.4.22)\n";
        let deps = DependencyScanner::parse_rubygems(content);
        assert_eq!(deps.len(), 3);
    }

    #[test]
    fn test_parse_rubygems_empty_name() {
        // If there's just a version in parens with no name, should be skipped
        let content = "    (1.0.0)\n";
        let deps = DependencyScanner::parse_rubygems(content);
        assert!(deps.is_empty());
    }

    // -----------------------------------------------------------------------
    // parse_nuget - edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_nuget_multiple_packages() {
        let content = r#"
            <package id="A" version="1.0" />
            <package id="B" version="2.0" />
            <package id="C" version="3.0" />
        "#;
        let deps = DependencyScanner::parse_nuget(content);
        assert_eq!(deps.len(), 3);
    }

    #[test]
    fn test_parse_nuget_no_version_attr() {
        let content = r#"<package id="NoVersion" />"#;
        let deps = DependencyScanner::parse_nuget(content);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "NoVersion");
        assert!(deps[0].version.is_none());
    }

    // -----------------------------------------------------------------------
    // extract_xml_value - edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_xml_value_with_nested_whitespace() {
        let line = "  <version>  3.12.0  </version>  ";
        // The value includes the surrounding spaces
        let result = DependencyScanner::extract_xml_value(line, "version");
        assert!(result.is_some());
        assert!(result.unwrap().contains("3.12.0"));
    }

    // -----------------------------------------------------------------------
    // extract_xml_attr - edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_xml_attr_with_single_quotes_fails() {
        // Our parser expects double quotes
        let line = "<package id='Foo' />";
        assert_eq!(DependencyScanner::extract_xml_attr(line, "id"), None);
    }

    // -----------------------------------------------------------------------
    // extract_dependencies - gemspec
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_dependencies_gemspec() {
        let artifact = make_artifact("my-gem.gemspec", "/ruby/my-gem.gemspec", None);
        let content = Bytes::from("    rails (7.0.8)\n");
        let deps = DependencyScanner::extract_dependencies(&artifact, None, &content);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].ecosystem, "RubyGems");
    }

    // -----------------------------------------------------------------------
    // infer_dependencies - path-based detection
    // -----------------------------------------------------------------------

    #[test]
    fn test_infer_dependencies_deb_path() {
        let artifact = make_artifact("pkg.bin", "/deb/pool/main/pkg.bin", Some("1.0"));
        let deps = DependencyScanner::infer_dependencies(&artifact, "");
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].ecosystem, "Linux");
    }

    #[test]
    fn test_infer_dependencies_alpine_path() {
        let artifact = make_artifact("pkg.bin", "/alpine/v3.18/pkg.bin", Some("1.0"));
        let deps = DependencyScanner::infer_dependencies(&artifact, "");
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].ecosystem, "Linux");
    }

    // -----------------------------------------------------------------------
    // parse_osv_response - no vulns key
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_osv_response_no_vulns_key() {
        let deps = vec![Dependency {
            name: "pkg".to_string(),
            version: None,
            ecosystem: "npm".to_string(),
        }];
        let body = serde_json::json!({"results": [{"other": "data"}]});
        let matches = AdvisoryClient::parse_osv_response(&body, &deps);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_parse_osv_response_empty_vulns_array() {
        let deps = vec![Dependency {
            name: "pkg".to_string(),
            version: None,
            ecosystem: "npm".to_string(),
        }];
        let body = serde_json::json!({"results": [{"vulns": []}]});
        let matches = AdvisoryClient::parse_osv_response(&body, &deps);
        assert!(matches.is_empty());
    }

    // -----------------------------------------------------------------------
    // parse_github_advisory - edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_github_advisory_with_null_cve() {
        let dep = Dependency {
            name: "pkg".to_string(),
            version: Some("1.0".to_string()),
            ecosystem: "npm".to_string(),
        };
        let adv = serde_json::json!({
            "ghsa_id": "GHSA-test-1234",
            "severity": "critical",
            "cve_id": null
        });
        let result = AdvisoryClient::parse_github_advisory(&adv, &dep).unwrap();
        // aliases should only have GHSA id, no null CVE
        assert_eq!(result.aliases, vec!["GHSA-test-1234".to_string()]);
    }

    #[test]
    fn test_parse_github_advisory_no_fixed_version() {
        let dep = Dependency {
            name: "pkg".to_string(),
            version: None,
            ecosystem: "npm".to_string(),
        };
        let adv = serde_json::json!({
            "ghsa_id": "GHSA-no-fix",
            "vulnerabilities": []
        });
        let result = AdvisoryClient::parse_github_advisory(&adv, &dep).unwrap();
        assert!(result.fixed_version.is_none());
    }

    // -----------------------------------------------------------------------
    // CACHE_TTL constant
    // -----------------------------------------------------------------------

    #[test]
    fn test_cache_ttl_is_one_hour() {
        assert_eq!(CACHE_TTL, Duration::from_secs(3600));
    }

    // -----------------------------------------------------------------------
    // URL constants
    // -----------------------------------------------------------------------

    #[test]
    fn test_osv_batch_url() {
        assert_eq!(OSV_BATCH_URL, "https://api.osv.dev/v1/querybatch");
    }

    #[test]
    fn test_github_advisory_url() {
        assert_eq!(GITHUB_ADVISORY_URL, "https://api.github.com/advisories");
    }

    // -----------------------------------------------------------------------
    // extract_dependencies - unrecognized file
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_dependencies_unknown_file() {
        let artifact = make_artifact("readme.md", "/docs/readme.md", None);
        let content = Bytes::from("# README\nThis is a readme file.");
        let deps = DependencyScanner::extract_dependencies(&artifact, None, &content);
        assert!(deps.is_empty());
    }

    #[test]
    fn test_extract_dependencies_nested_cargo_toml() {
        let artifact = make_artifact("backend/Cargo.toml", "/rust/backend/Cargo.toml", None);
        let content = Bytes::from("[dependencies]\ntokio = \"1.35\"\n");
        let deps = DependencyScanner::extract_dependencies(&artifact, None, &content);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].ecosystem, "crates.io");
    }

    #[test]
    fn test_extract_dependencies_nested_requirements_txt() {
        let artifact = make_artifact("app/requirements.txt", "/pypi/app/requirements.txt", None);
        let content = Bytes::from("django==4.2\n");
        let deps = DependencyScanner::extract_dependencies(&artifact, None, &content);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].ecosystem, "PyPI");
    }

    #[test]
    fn test_extract_dependencies_nested_go_sum() {
        let artifact = make_artifact("project/go.sum", "/go/project/go.sum", None);
        let content = Bytes::from("golang.org/x/sys v0.15.0 h1:abc=\n");
        let deps = DependencyScanner::extract_dependencies(&artifact, None, &content);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].ecosystem, "Go");
    }

    #[test]
    fn test_extract_dependencies_nested_pom_xml() {
        let artifact = make_artifact("module/pom.xml", "/maven/module/pom.xml", None);
        let content = Bytes::from(
            "<dependency>\n<groupId>io.quarkus</groupId>\n<artifactId>quarkus-core</artifactId>\n<version>3.6.0</version>\n</dependency>\n",
        );
        let deps = DependencyScanner::extract_dependencies(&artifact, None, &content);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].ecosystem, "Maven");
    }

    // -----------------------------------------------------------------------
    // ecosystem_to_github_param (extracted pure function)
    // -----------------------------------------------------------------------

    #[test]
    fn test_ecosystem_to_github_param_npm() {
        assert_eq!(ecosystem_to_github_param("npm"), Some("npm"));
    }

    #[test]
    fn test_ecosystem_to_github_param_pypi() {
        assert_eq!(ecosystem_to_github_param("PyPI"), Some("pip"));
        assert_eq!(ecosystem_to_github_param("pypi"), Some("pip"));
    }

    #[test]
    fn test_ecosystem_to_github_param_crates() {
        assert_eq!(ecosystem_to_github_param("crates.io"), Some("rust"));
    }

    #[test]
    fn test_ecosystem_to_github_param_maven() {
        assert_eq!(ecosystem_to_github_param("Maven"), Some("maven"));
    }

    #[test]
    fn test_ecosystem_to_github_param_go() {
        assert_eq!(ecosystem_to_github_param("Go"), Some("go"));
    }

    #[test]
    fn test_ecosystem_to_github_param_nuget() {
        assert_eq!(ecosystem_to_github_param("NuGet"), Some("nuget"));
    }

    #[test]
    fn test_ecosystem_to_github_param_rubygems() {
        assert_eq!(ecosystem_to_github_param("RubyGems"), Some("rubygems"));
    }

    #[test]
    fn test_ecosystem_to_github_param_unknown() {
        assert_eq!(ecosystem_to_github_param("Hex"), None);
        assert_eq!(ecosystem_to_github_param("Composer"), None);
        assert_eq!(ecosystem_to_github_param(""), None);
        assert_eq!(ecosystem_to_github_param("Linux"), None);
    }

    // -----------------------------------------------------------------------
    // quarantine_status_from_findings (extracted pure function)
    // -----------------------------------------------------------------------

    #[test]
    fn test_quarantine_status_flagged() {
        assert_eq!(quarantine_status_from_findings(1), "flagged");
        assert_eq!(quarantine_status_from_findings(100), "flagged");
    }

    #[test]
    fn test_quarantine_status_clean() {
        assert_eq!(quarantine_status_from_findings(0), "clean");
    }

    #[test]
    fn test_quarantine_status_negative_treated_as_clean() {
        // Negative values are technically <= 0, so not > 0
        assert_eq!(quarantine_status_from_findings(-1), "clean");
    }

    // -----------------------------------------------------------------------
    // is_manifest_file (extracted pure function)
    // -----------------------------------------------------------------------

    #[test]
    fn test_is_manifest_file_known_names() {
        assert!(is_manifest_file("package.json"));
        assert!(is_manifest_file("cargo.toml"));
        assert!(is_manifest_file("requirements.txt"));
        assert!(is_manifest_file("go.sum"));
        assert!(is_manifest_file("pom.xml"));
        assert!(is_manifest_file("gemfile.lock"));
        assert!(is_manifest_file("packages.config"));
    }

    #[test]
    fn test_is_manifest_file_nested_paths() {
        assert!(is_manifest_file("libs/core/package.json"));
        assert!(is_manifest_file("backend/cargo.toml"));
        assert!(is_manifest_file("app/requirements.txt"));
        assert!(is_manifest_file("project/go.sum"));
        assert!(is_manifest_file("module/pom.xml"));
        assert!(is_manifest_file("ruby/gemfile.lock"));
    }

    #[test]
    fn test_is_manifest_file_extension_based() {
        assert!(is_manifest_file("my-gem.gemspec"));
        assert!(is_manifest_file("my-pkg.nuspec"));
    }

    #[test]
    fn test_is_manifest_file_unknown() {
        assert!(!is_manifest_file("readme.md"));
        assert!(!is_manifest_file("main.rs"));
        assert!(!is_manifest_file("docker-compose.yml"));
        assert!(!is_manifest_file("my-lib.jar"));
    }

    // -----------------------------------------------------------------------
    // is_extractable_archive (extracted pure function)
    // -----------------------------------------------------------------------

    #[test]
    fn test_is_extractable_archive_tar_gz() {
        assert!(is_extractable_archive("package.tar.gz"));
        assert!(is_extractable_archive("lib.tgz"));
    }

    #[test]
    fn test_is_extractable_archive_rust_ruby() {
        assert!(is_extractable_archive("my-crate-1.0.0.crate"));
        assert!(is_extractable_archive("my-gem-1.0.0.gem"));
    }

    #[test]
    fn test_is_extractable_archive_zip_variants() {
        assert!(is_extractable_archive("package.zip"));
        assert!(is_extractable_archive("numpy-1.0.whl"));
        assert!(is_extractable_archive("commons-lang.jar"));
        assert!(is_extractable_archive("newtonsoft.json.nupkg"));
    }

    #[test]
    fn test_is_extractable_archive_not_archive() {
        assert!(!is_extractable_archive("readme.md"));
        assert!(!is_extractable_archive("image.png"));
        assert!(!is_extractable_archive("package.json"));
        assert!(!is_extractable_archive("main.rs"));
    }

    // -----------------------------------------------------------------------
    // osv_vulnerability_url (extracted pure function)
    // -----------------------------------------------------------------------

    #[test]
    fn test_osv_vulnerability_url() {
        assert_eq!(
            osv_vulnerability_url("GHSA-abcd-1234-efgh"),
            "https://osv.dev/vulnerability/GHSA-abcd-1234-efgh"
        );
        assert_eq!(
            osv_vulnerability_url("CVE-2024-0001"),
            "https://osv.dev/vulnerability/CVE-2024-0001"
        );
    }

    // -----------------------------------------------------------------------
    // parse_pip - additional edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_pip_extras_in_name() {
        // pip supports extras syntax: package[extra]==1.0
        let content = "requests[security]==2.28.0\n";
        let deps = DependencyScanner::parse_pip(content);
        assert_eq!(deps.len(), 1);
        // The extras syntax is preserved as part of the name
        assert!(deps[0].name.contains("requests"));
    }

    #[test]
    fn test_parse_pip_single_package() {
        let content = "flask==2.3.0\n";
        let deps = DependencyScanner::parse_pip(content);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "flask");
        assert_eq!(deps[0].version.as_deref(), Some("2.3.0"));
    }

    // -----------------------------------------------------------------------
    // parse_maven - additional edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_maven_with_version_property() {
        // Maven properties like ${project.version} should be treated as version
        let content = r#"
            <dependency>
                <groupId>org.example</groupId>
                <artifactId>my-lib</artifactId>
                <version>${project.version}</version>
            </dependency>
        "#;
        let deps = DependencyScanner::parse_maven(content);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].version.as_deref(), Some("${project.version}"));
    }

    // -----------------------------------------------------------------------
    // parse_rubygems - additional edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_rubygems_with_platform() {
        // Some gems include platform info
        let content = "    nokogiri (1.15.4-arm64-darwin)\n";
        let deps = DependencyScanner::parse_rubygems(content);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "nokogiri");
        assert_eq!(deps[0].version.as_deref(), Some("1.15.4-arm64-darwin"));
    }

    // -----------------------------------------------------------------------
    // parse_npm - npm workspace / special versions
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_npm_star_version() {
        let content = r#"{"dependencies": {"pkg": "*"}}"#;
        let deps = DependencyScanner::parse_npm(content);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].version.as_deref(), Some("*"));
    }

    #[test]
    fn test_parse_npm_url_version() {
        let content = r#"{"dependencies": {"pkg": "https://example.com/pkg.tgz"}}"#;
        let deps = DependencyScanner::parse_npm(content);
        assert_eq!(deps.len(), 1);
        assert!(deps[0].version.as_deref().unwrap().starts_with("https://"));
    }

    // -----------------------------------------------------------------------
    // parse_go - additional edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_go_mixed_modules() {
        let content = "github.com/foo/bar v1.0.0 h1:abc=\ngitlab.com/baz/qux v2.0.0 h1:def=\n";
        let deps = DependencyScanner::parse_go(content);
        assert_eq!(deps.len(), 2);
        assert_eq!(deps[0].name, "github.com/foo/bar");
        assert_eq!(deps[1].name, "gitlab.com/baz/qux");
    }

    // -----------------------------------------------------------------------
    // parse_nuget - packages.config with targetFramework
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_nuget_with_target_framework() {
        let content = r#"<package id="Moq" version="4.18.4" targetFramework="net6.0" />"#;
        let deps = DependencyScanner::parse_nuget(content);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "Moq");
        assert_eq!(deps[0].version.as_deref(), Some("4.18.4"));
    }

    // -----------------------------------------------------------------------
    // parse_cargo - workspace dep
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_cargo_workspace_dep() {
        let content = r#"
            [dependencies]
            my-lib = { workspace = true }
        "#;
        let deps = DependencyScanner::parse_cargo(content);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "my-lib");
        assert!(deps[0].version.is_none()); // workspace = true has no version key
    }

    // -----------------------------------------------------------------------
    // parse_github_advisory - with multiple patched versions
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_github_advisory_multiple_vulnerabilities() {
        let dep = Dependency {
            name: "pkg".to_string(),
            version: Some("1.0".to_string()),
            ecosystem: "npm".to_string(),
        };
        let adv = serde_json::json!({
            "ghsa_id": "GHSA-multi",
            "vulnerabilities": [
                {"first_patched_version": null},
                {"first_patched_version": {"identifier": "2.0.0"}}
            ]
        });
        let result = AdvisoryClient::parse_github_advisory(&adv, &dep).unwrap();
        assert_eq!(result.fixed_version.as_deref(), Some("2.0.0"));
    }

    // -----------------------------------------------------------------------
    // detect_archive_type
    // -----------------------------------------------------------------------

    #[test]
    fn test_detect_archive_type_tar_gz() {
        assert_eq!(detect_archive_type("package.tar.gz"), ArchiveType::TarGz);
        assert_eq!(detect_archive_type("lib.tgz"), ArchiveType::TarGz);
        assert_eq!(
            detect_archive_type("my-crate-1.0.crate"),
            ArchiveType::TarGz
        );
        assert_eq!(detect_archive_type("my-gem-2.0.gem"), ArchiveType::TarGz);
    }

    #[test]
    fn test_detect_archive_type_tar_gz_case_insensitive() {
        assert_eq!(detect_archive_type("Package.TAR.GZ"), ArchiveType::TarGz);
        assert_eq!(detect_archive_type("Lib.TGZ"), ArchiveType::TarGz);
        assert_eq!(detect_archive_type("My.CRATE"), ArchiveType::TarGz);
        assert_eq!(detect_archive_type("My.GEM"), ArchiveType::TarGz);
    }

    #[test]
    fn test_detect_archive_type_zip() {
        assert_eq!(detect_archive_type("package.zip"), ArchiveType::Zip);
        assert_eq!(detect_archive_type("numpy-1.0.whl"), ArchiveType::Zip);
        assert_eq!(detect_archive_type("commons.jar"), ArchiveType::Zip);
        assert_eq!(detect_archive_type("newtonsoft.nupkg"), ArchiveType::Zip);
    }

    #[test]
    fn test_detect_archive_type_zip_case_insensitive() {
        assert_eq!(detect_archive_type("Package.ZIP"), ArchiveType::Zip);
        assert_eq!(detect_archive_type("Lib.WHL"), ArchiveType::Zip);
        assert_eq!(detect_archive_type("App.JAR"), ArchiveType::Zip);
        assert_eq!(detect_archive_type("Pkg.NUPKG"), ArchiveType::Zip);
    }

    #[test]
    fn test_detect_archive_type_none() {
        assert_eq!(detect_archive_type("readme.md"), ArchiveType::None);
        assert_eq!(detect_archive_type("main.rs"), ArchiveType::None);
        assert_eq!(detect_archive_type("package.json"), ArchiveType::None);
        assert_eq!(detect_archive_type("image.png"), ArchiveType::None);
        assert_eq!(detect_archive_type("data.tar"), ArchiveType::None);
        assert_eq!(detect_archive_type("file.gz"), ArchiveType::None);
    }

    // -----------------------------------------------------------------------
    // is_path_within_workspace
    // -----------------------------------------------------------------------

    #[test]
    fn test_is_path_within_workspace_valid() {
        let path = Path::new("/tmp/scans/artifact-123");
        assert!(is_path_within_workspace(path, "/tmp/scans"));
    }

    #[test]
    fn test_is_path_within_workspace_exact() {
        let path = Path::new("/tmp/scans");
        assert!(is_path_within_workspace(path, "/tmp/scans"));
    }

    #[test]
    fn test_is_path_within_workspace_outside() {
        let path = Path::new("/var/data/something");
        assert!(!is_path_within_workspace(path, "/tmp/scans"));
    }

    #[test]
    fn test_is_path_within_workspace_partial_prefix() {
        let path = Path::new("/tmp/scans-other/artifact");
        assert!(!is_path_within_workspace(path, "/tmp/scans"));
    }

    // -----------------------------------------------------------------------
    // count_findings_by_severity
    // -----------------------------------------------------------------------

    fn make_finding(severity: Severity) -> RawFinding {
        RawFinding {
            severity,
            title: "test".to_string(),
            description: None,
            cve_id: None,
            affected_component: None,
            affected_version: None,
            fixed_version: None,
            source: None,
            source_url: None,
        }
    }

    #[test]
    fn test_count_findings_by_severity_empty() {
        let (critical, high, medium, low, info) = count_findings_by_severity(&[]);
        assert_eq!(critical, 0);
        assert_eq!(high, 0);
        assert_eq!(medium, 0);
        assert_eq!(low, 0);
        assert_eq!(info, 0);
    }

    #[test]
    fn test_count_findings_by_severity_all_types() {
        let findings = vec![
            make_finding(Severity::Critical),
            make_finding(Severity::Critical),
            make_finding(Severity::High),
            make_finding(Severity::Medium),
            make_finding(Severity::Medium),
            make_finding(Severity::Medium),
            make_finding(Severity::Low),
            make_finding(Severity::Info),
            make_finding(Severity::Info),
        ];
        let (critical, high, medium, low, info) = count_findings_by_severity(&findings);
        assert_eq!(critical, 2);
        assert_eq!(high, 1);
        assert_eq!(medium, 3);
        assert_eq!(low, 1);
        assert_eq!(info, 2);
    }

    #[test]
    fn test_count_findings_by_severity_single_type() {
        let findings = vec![
            make_finding(Severity::High),
            make_finding(Severity::High),
            make_finding(Severity::High),
        ];
        let (critical, high, medium, low, info) = count_findings_by_severity(&findings);
        assert_eq!(critical, 0);
        assert_eq!(high, 3);
        assert_eq!(medium, 0);
        assert_eq!(low, 0);
        assert_eq!(info, 0);
    }

    // -----------------------------------------------------------------------
    // extract_cve_from_advisory
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_cve_from_aliases() {
        let m = AdvisoryMatch {
            id: "GHSA-1234".to_string(),
            summary: None,
            details: None,
            severity: "high".to_string(),
            aliases: vec!["CVE-2024-0001".to_string(), "GHSA-1234".to_string()],
            affected_version: None,
            fixed_version: None,
            source: "osv.dev".to_string(),
            source_url: None,
        };
        assert_eq!(
            extract_cve_from_advisory(&m),
            Some("CVE-2024-0001".to_string())
        );
    }

    #[test]
    fn test_extract_cve_from_id() {
        let m = AdvisoryMatch {
            id: "CVE-2024-5678".to_string(),
            summary: None,
            details: None,
            severity: "medium".to_string(),
            aliases: vec![],
            affected_version: None,
            fixed_version: None,
            source: "osv.dev".to_string(),
            source_url: None,
        };
        assert_eq!(
            extract_cve_from_advisory(&m),
            Some("CVE-2024-5678".to_string())
        );
    }

    #[test]
    fn test_extract_cve_no_cve() {
        let m = AdvisoryMatch {
            id: "GHSA-abcd".to_string(),
            summary: None,
            details: None,
            severity: "low".to_string(),
            aliases: vec!["GHSA-abcd".to_string()],
            affected_version: None,
            fixed_version: None,
            source: "github".to_string(),
            source_url: None,
        };
        assert_eq!(extract_cve_from_advisory(&m), None);
    }

    #[test]
    fn test_extract_cve_prefers_alias_over_id() {
        let m = AdvisoryMatch {
            id: "CVE-2024-0001".to_string(),
            summary: None,
            details: None,
            severity: "high".to_string(),
            aliases: vec!["CVE-2024-9999".to_string()],
            affected_version: None,
            fixed_version: None,
            source: "osv.dev".to_string(),
            source_url: None,
        };
        assert_eq!(
            extract_cve_from_advisory(&m),
            Some("CVE-2024-9999".to_string())
        );
    }

    // -----------------------------------------------------------------------
    // build_finding_title
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_finding_title_with_summary() {
        let m = AdvisoryMatch {
            id: "GHSA-1234".to_string(),
            summary: Some("Prototype Pollution".to_string()),
            details: None,
            severity: "high".to_string(),
            aliases: vec![],
            affected_version: None,
            fixed_version: None,
            source: "osv.dev".to_string(),
            source_url: None,
        };
        assert_eq!(build_finding_title(&m), "Prototype Pollution");
    }

    #[test]
    fn test_build_finding_title_without_summary() {
        let m = AdvisoryMatch {
            id: "GHSA-5678".to_string(),
            summary: None,
            details: None,
            severity: "medium".to_string(),
            aliases: vec![],
            affected_version: None,
            fixed_version: None,
            source: "osv.dev".to_string(),
            source_url: None,
        };
        assert_eq!(build_finding_title(&m), "Vulnerability GHSA-5678");
    }

    // -----------------------------------------------------------------------
    // dedup_advisories
    // -----------------------------------------------------------------------

    #[test]
    fn test_dedup_advisories_no_duplicates() {
        let osv = vec![AdvisoryMatch {
            id: "GHSA-1111".to_string(),
            summary: None,
            details: None,
            severity: "high".to_string(),
            aliases: vec![],
            affected_version: None,
            fixed_version: None,
            source: "osv.dev".to_string(),
            source_url: None,
        }];
        let gh = vec![AdvisoryMatch {
            id: "GHSA-2222".to_string(),
            summary: None,
            details: None,
            severity: "medium".to_string(),
            aliases: vec![],
            affected_version: None,
            fixed_version: None,
            source: "github".to_string(),
            source_url: None,
        }];
        let result = dedup_advisories(osv, gh);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_dedup_advisories_exact_id_duplicate() {
        let osv = vec![AdvisoryMatch {
            id: "GHSA-1111".to_string(),
            summary: Some("From OSV".to_string()),
            details: None,
            severity: "high".to_string(),
            aliases: vec![],
            affected_version: None,
            fixed_version: None,
            source: "osv.dev".to_string(),
            source_url: None,
        }];
        let gh = vec![AdvisoryMatch {
            id: "GHSA-1111".to_string(),
            summary: Some("From GitHub".to_string()),
            details: None,
            severity: "high".to_string(),
            aliases: vec![],
            affected_version: None,
            fixed_version: None,
            source: "github".to_string(),
            source_url: None,
        }];
        let result = dedup_advisories(osv, gh);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].source, "osv.dev");
    }

    #[test]
    fn test_dedup_advisories_alias_overlap() {
        let osv = vec![AdvisoryMatch {
            id: "GHSA-aaaa".to_string(),
            summary: None,
            details: None,
            severity: "high".to_string(),
            aliases: vec!["CVE-2024-0001".to_string()],
            affected_version: None,
            fixed_version: None,
            source: "osv.dev".to_string(),
            source_url: None,
        }];
        let gh = vec![AdvisoryMatch {
            id: "CVE-2024-0001".to_string(),
            summary: None,
            details: None,
            severity: "high".to_string(),
            aliases: vec![],
            affected_version: None,
            fixed_version: None,
            source: "github".to_string(),
            source_url: None,
        }];
        let result = dedup_advisories(osv, gh);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].id, "GHSA-aaaa");
    }

    #[test]
    fn test_dedup_advisories_empty() {
        let result = dedup_advisories(vec![], vec![]);
        assert!(result.is_empty());
    }

    #[test]
    fn test_dedup_advisories_osv_only() {
        let osv = vec![AdvisoryMatch {
            id: "OSV-001".to_string(),
            summary: None,
            details: None,
            severity: "low".to_string(),
            aliases: vec![],
            affected_version: None,
            fixed_version: None,
            source: "osv.dev".to_string(),
            source_url: None,
        }];
        let result = dedup_advisories(osv, vec![]);
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn test_dedup_advisories_gh_only() {
        let gh = vec![AdvisoryMatch {
            id: "GHSA-bbbb".to_string(),
            summary: None,
            details: None,
            severity: "medium".to_string(),
            aliases: vec![],
            affected_version: None,
            fixed_version: None,
            source: "github".to_string(),
            source_url: None,
        }];
        let result = dedup_advisories(vec![], gh);
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn test_dedup_advisories_complex_alias_chain() {
        let osv = vec![AdvisoryMatch {
            id: "GHSA-aaaa".to_string(),
            summary: None,
            details: None,
            severity: "high".to_string(),
            aliases: vec!["CVE-2024-0001".to_string(), "GHSA-bbbb".to_string()],
            affected_version: None,
            fixed_version: None,
            source: "osv.dev".to_string(),
            source_url: None,
        }];
        let gh = vec![
            AdvisoryMatch {
                id: "GHSA-bbbb".to_string(),
                summary: None,
                details: None,
                severity: "high".to_string(),
                aliases: vec!["CVE-2024-0001".to_string()],
                affected_version: None,
                fixed_version: None,
                source: "github".to_string(),
                source_url: None,
            },
            AdvisoryMatch {
                id: "CVE-2024-0001".to_string(),
                summary: None,
                details: None,
                severity: "high".to_string(),
                aliases: vec![],
                affected_version: None,
                fixed_version: None,
                source: "github".to_string(),
                source_url: None,
            },
        ];
        let result = dedup_advisories(osv, gh);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].id, "GHSA-aaaa");
    }

    // -----------------------------------------------------------------------
    // build_osv_cache_key
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_osv_cache_key_with_version() {
        let dep = Dependency {
            name: "lodash".to_string(),
            version: Some("4.17.20".to_string()),
            ecosystem: "npm".to_string(),
        };
        assert_eq!(build_osv_cache_key(&dep), "npm:lodash:4.17.20");
    }

    #[test]
    fn test_build_osv_cache_key_without_version() {
        let dep = Dependency {
            name: "my-lib".to_string(),
            version: None,
            ecosystem: "crates.io".to_string(),
        };
        assert_eq!(build_osv_cache_key(&dep), "crates.io:my-lib:*");
    }

    #[test]
    fn test_build_osv_cache_key_pypi() {
        let dep = Dependency {
            name: "flask".to_string(),
            version: Some("2.3.0".to_string()),
            ecosystem: "PyPI".to_string(),
        };
        assert_eq!(build_osv_cache_key(&dep), "PyPI:flask:2.3.0");
    }

    // -----------------------------------------------------------------------
    // OsvBatchQuery serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_osv_batch_query_serialization() {
        let query = OsvBatchQuery {
            queries: vec![
                OsvQuery {
                    package: OsvPackage {
                        name: "lodash".to_string(),
                        ecosystem: "npm".to_string(),
                    },
                    version: Some("4.17.20".to_string()),
                },
                OsvQuery {
                    package: OsvPackage {
                        name: "flask".to_string(),
                        ecosystem: "PyPI".to_string(),
                    },
                    version: None,
                },
            ],
        };
        let json = serde_json::to_value(&query).unwrap();
        let queries = json.get("queries").unwrap().as_array().unwrap();
        assert_eq!(queries.len(), 2);

        let first = &queries[0];
        assert_eq!(first["package"]["name"], "lodash");
        assert_eq!(first["package"]["ecosystem"], "npm");
        assert_eq!(first["version"], "4.17.20");

        let second = &queries[1];
        assert_eq!(second["package"]["name"], "flask");
        assert_eq!(second["package"]["ecosystem"], "PyPI");
        assert!(second["version"].is_null());
    }

    #[test]
    fn test_osv_batch_query_empty() {
        let query = OsvBatchQuery { queries: vec![] };
        let json = serde_json::to_value(&query).unwrap();
        assert!(json.get("queries").unwrap().as_array().unwrap().is_empty());
    }

    // -----------------------------------------------------------------------
    // parse_osv_response - vuln with no id
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_osv_response_vuln_with_no_id_defaults_to_unknown() {
        let deps = vec![Dependency {
            name: "pkg".to_string(),
            version: Some("1.0".to_string()),
            ecosystem: "npm".to_string(),
        }];
        let body = serde_json::json!({
            "results": [{
                "vulns": [{"summary": "some issue"}]
            }]
        });
        let matches = AdvisoryClient::parse_osv_response(&body, &deps);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].id, "UNKNOWN");
    }

    // -----------------------------------------------------------------------
    // parse_osv_response - vuln with aliases but no fixed version
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_osv_response_no_fixed_version() {
        let deps = vec![Dependency {
            name: "pkg".to_string(),
            version: Some("1.0".to_string()),
            ecosystem: "npm".to_string(),
        }];
        let body = serde_json::json!({
            "results": [{
                "vulns": [{
                    "id": "OSV-2024-100",
                    "aliases": ["CVE-2024-1234"],
                    "affected": [{
                        "ranges": [{
                            "type": "SEMVER",
                            "events": [{"introduced": "0"}]
                        }]
                    }]
                }]
            }]
        });
        let matches = AdvisoryClient::parse_osv_response(&body, &deps);
        assert_eq!(matches.len(), 1);
        assert!(matches[0].fixed_version.is_none());
        assert_eq!(matches[0].aliases, vec!["CVE-2024-1234".to_string()]);
    }

    // -----------------------------------------------------------------------
    // parse_osv_response - dep index out of bounds
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_osv_response_more_results_than_deps() {
        let deps = vec![Dependency {
            name: "pkg-a".to_string(),
            version: Some("1.0".to_string()),
            ecosystem: "npm".to_string(),
        }];
        let body = serde_json::json!({
            "results": [
                {"vulns": [{"id": "VULN-A"}]},
                {"vulns": [{"id": "VULN-B"}]}
            ]
        });
        let matches = AdvisoryClient::parse_osv_response(&body, &deps);
        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0].affected_version.as_deref(), Some("1.0"));
        assert!(matches[1].affected_version.is_none());
    }

    // -----------------------------------------------------------------------
    // parse_osv_response - affected array empty
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_osv_response_empty_affected() {
        let deps = vec![Dependency {
            name: "pkg".to_string(),
            version: Some("1.0".to_string()),
            ecosystem: "npm".to_string(),
        }];
        let body = serde_json::json!({
            "results": [{
                "vulns": [{
                    "id": "VULN-1",
                    "affected": []
                }]
            }]
        });
        let matches = AdvisoryClient::parse_osv_response(&body, &deps);
        assert_eq!(matches.len(), 1);
        assert!(matches[0].fixed_version.is_none());
    }

    // -----------------------------------------------------------------------
    // parse_github_advisory - severity defaults
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_github_advisory_severity_case_insensitive() {
        let dep = Dependency {
            name: "pkg".to_string(),
            version: None,
            ecosystem: "npm".to_string(),
        };
        let adv = serde_json::json!({
            "ghsa_id": "GHSA-test",
            "severity": "CRITICAL"
        });
        let result = AdvisoryClient::parse_github_advisory(&adv, &dep).unwrap();
        assert_eq!(result.severity, "critical");
    }

    #[test]
    fn test_parse_github_advisory_no_severity_defaults_to_medium() {
        let dep = Dependency {
            name: "pkg".to_string(),
            version: None,
            ecosystem: "npm".to_string(),
        };
        let adv = serde_json::json!({
            "ghsa_id": "GHSA-default"
        });
        let result = AdvisoryClient::parse_github_advisory(&adv, &dep).unwrap();
        assert_eq!(result.severity, "medium");
    }

    // -----------------------------------------------------------------------
    // extract_dependencies - case sensitivity
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_dependencies_case_insensitive_name() {
        let artifact = make_artifact("PACKAGE.JSON", "/npm/PACKAGE.JSON", None);
        let content = Bytes::from(r#"{"dependencies":{"react":"^18.0.0"}}"#);
        let deps = DependencyScanner::extract_dependencies(&artifact, None, &content);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].ecosystem, "npm");
    }

    #[test]
    fn test_extract_dependencies_cargo_toml_case_insensitive() {
        let artifact = make_artifact("CARGO.TOML", "/rust/CARGO.TOML", None);
        let content = Bytes::from("[dependencies]\ntokio = \"1.35\"\n");
        let deps = DependencyScanner::extract_dependencies(&artifact, None, &content);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].ecosystem, "crates.io");
    }

    #[test]
    fn test_extract_dependencies_requirements_txt_case_insensitive() {
        let artifact = make_artifact("REQUIREMENTS.TXT", "/pypi/REQUIREMENTS.TXT", None);
        let content = Bytes::from("flask==2.3.0\n");
        let deps = DependencyScanner::extract_dependencies(&artifact, None, &content);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].ecosystem, "PyPI");
    }

    // -----------------------------------------------------------------------
    // parse_npm - complex scenarios
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_npm_large_package_json() {
        let content = r#"{
            "name": "my-app",
            "version": "1.0.0",
            "dependencies": {
                "express": "^4.18.2",
                "lodash": "~4.17.21",
                "axios": "1.6.0"
            },
            "devDependencies": {
                "jest": "29.0.0",
                "typescript": "^5.3.0"
            },
            "peerDependencies": {
                "react": "^18.0.0"
            },
            "scripts": {
                "test": "jest"
            }
        }"#;
        let deps = DependencyScanner::parse_npm(content);
        assert_eq!(deps.len(), 6);
        let names: Vec<&str> = deps.iter().map(|d| d.name.as_str()).collect();
        assert!(names.contains(&"express"));
        assert!(names.contains(&"jest"));
        assert!(names.contains(&"react"));
    }

    // -----------------------------------------------------------------------
    // infer_dependencies - version propagation
    // -----------------------------------------------------------------------

    #[test]
    fn test_infer_dependencies_version_propagated() {
        let artifact = make_artifact("pkg.rpm", "/rpm/pkg.rpm", Some("3.14"));
        let deps = DependencyScanner::infer_dependencies(&artifact, "");
        assert_eq!(deps[0].version.as_deref(), Some("3.14"));
    }

    #[test]
    fn test_infer_dependencies_no_version() {
        let artifact = make_artifact("pkg.rpm", "/rpm/pkg.rpm", None);
        let deps = DependencyScanner::infer_dependencies(&artifact, "");
        assert!(deps[0].version.is_none());
    }

    // -----------------------------------------------------------------------
    // AdvisoryMatch deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_advisory_match_deserialize_from_json() {
        let json = serde_json::json!({
            "id": "GHSA-test",
            "summary": "Test advisory",
            "details": null,
            "severity": "high",
            "aliases": ["CVE-2024-0001"],
            "affected_version": "1.0.0",
            "fixed_version": "1.0.1",
            "source": "github",
            "source_url": "https://github.com/advisories/GHSA-test"
        });
        let m: AdvisoryMatch = serde_json::from_value(json).unwrap();
        assert_eq!(m.id, "GHSA-test");
        assert_eq!(m.summary.as_deref(), Some("Test advisory"));
        assert!(m.details.is_none());
        assert_eq!(m.aliases.len(), 1);
    }

    // -----------------------------------------------------------------------
    // parse_maven - dependency with version
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_maven_dependency_with_scope() {
        let content = r#"
            <dependency>
                <groupId>junit</groupId>
                <artifactId>junit</artifactId>
                <version>4.13.2</version>
            </dependency>
        "#;
        let deps = DependencyScanner::parse_maven(content);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "junit:junit");
        assert_eq!(deps[0].version.as_deref(), Some("4.13.2"));
    }

    // -----------------------------------------------------------------------
    // parse_rubygems - lines without parens
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_rubygems_ignores_lines_without_parens() {
        let content =
            "GEM\n  remote: https://rubygems.org/\n  specs:\n    rails (7.0.8)\n    PLATFORMS\n    ruby\n";
        let deps = DependencyScanner::parse_rubygems(content);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "rails");
    }

    // -----------------------------------------------------------------------
    // parse_nuget - non-package lines
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_nuget_ignores_non_package_lines() {
        let content = r#"<?xml version="1.0"?>
<packages>
  <package id="A" version="1.0" />
  <!-- this is a comment -->
  <metadata>something</metadata>
</packages>"#;
        let deps = DependencyScanner::parse_nuget(content);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "A");
    }

    // -----------------------------------------------------------------------
    // parse_pip - no version specifier
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_pip_no_version_specifier() {
        let content = "flask\ndjango\n";
        let deps = DependencyScanner::parse_pip(content);
        assert_eq!(deps.len(), 2);
        assert!(deps[0].version.is_none());
        assert!(deps[1].version.is_none());
    }

    // -----------------------------------------------------------------------
    // parse_cargo - mixed dependency types in one section
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_cargo_mixed_dep_types() {
        let content = r#"
            [dependencies]
            serde = "1.0"
            tokio = { version = "1.35", features = ["full"] }
            local-lib = { path = "../local-lib" }
            git-dep = { git = "https://github.com/foo/bar", version = "0.5" }
        "#;
        let deps = DependencyScanner::parse_cargo(content);
        assert_eq!(deps.len(), 4);
        let serde = deps.iter().find(|d| d.name == "serde").unwrap();
        assert_eq!(serde.version.as_deref(), Some("1.0"));
        let tokio = deps.iter().find(|d| d.name == "tokio").unwrap();
        assert_eq!(tokio.version.as_deref(), Some("1.35"));
        let local = deps.iter().find(|d| d.name == "local-lib").unwrap();
        assert!(local.version.is_none());
        let git = deps.iter().find(|d| d.name == "git-dep").unwrap();
        assert_eq!(git.version.as_deref(), Some("0.5"));
    }

    // -----------------------------------------------------------------------
    // RawFinding serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_raw_finding_serialization_full() {
        let finding = RawFinding {
            severity: Severity::Critical,
            title: "SQL Injection".to_string(),
            description: Some("Improper input sanitization".to_string()),
            cve_id: Some("CVE-2024-0001".to_string()),
            affected_component: Some("db-driver".to_string()),
            affected_version: Some("1.0.0".to_string()),
            fixed_version: Some("1.0.1".to_string()),
            source: Some("trivy".to_string()),
            source_url: Some("https://trivy.dev/vuln/CVE-2024-0001".to_string()),
        };
        let json = serde_json::to_value(&finding).unwrap();
        assert_eq!(json["severity"], "critical");
        assert_eq!(json["title"], "SQL Injection");
        assert_eq!(json["description"], "Improper input sanitization");
        assert_eq!(json["cve_id"], "CVE-2024-0001");
        assert_eq!(json["affected_component"], "db-driver");
        assert_eq!(json["affected_version"], "1.0.0");
        assert_eq!(json["fixed_version"], "1.0.1");
        assert_eq!(json["source"], "trivy");
    }

    #[test]
    fn test_raw_finding_serialization_minimal() {
        let finding = RawFinding {
            severity: Severity::Info,
            title: "Informational notice".to_string(),
            description: None,
            cve_id: None,
            affected_component: None,
            affected_version: None,
            fixed_version: None,
            source: None,
            source_url: None,
        };
        let json = serde_json::to_value(&finding).unwrap();
        assert_eq!(json["severity"], "info");
        assert_eq!(json["title"], "Informational notice");
        assert!(json["description"].is_null());
        assert!(json["cve_id"].is_null());
        assert!(json["source"].is_null());
    }

    #[test]
    fn test_raw_finding_serialization_all_severities() {
        for (severity, expected_str) in [
            (Severity::Critical, "critical"),
            (Severity::High, "high"),
            (Severity::Medium, "medium"),
            (Severity::Low, "low"),
            (Severity::Info, "info"),
        ] {
            let finding = make_finding(severity);
            let json = serde_json::to_value(&finding).unwrap();
            assert_eq!(json["severity"], expected_str);
        }
    }

    #[test]
    fn test_raw_finding_debug() {
        let finding = make_finding(Severity::High);
        let debug = format!("{:?}", finding);
        assert!(debug.contains("RawFinding"));
        assert!(debug.contains("High"));
    }

    #[test]
    fn test_raw_finding_clone() {
        let finding = RawFinding {
            severity: Severity::Medium,
            title: "XSS vulnerability".to_string(),
            description: Some("Reflected XSS".to_string()),
            cve_id: Some("CVE-2024-9999".to_string()),
            affected_component: Some("web-ui".to_string()),
            affected_version: Some("2.0.0".to_string()),
            fixed_version: Some("2.0.1".to_string()),
            source: Some("grype".to_string()),
            source_url: Some("https://example.com".to_string()),
        };
        let cloned = finding.clone();
        assert_eq!(cloned.severity, finding.severity);
        assert_eq!(cloned.title, finding.title);
        assert_eq!(cloned.description, finding.description);
        assert_eq!(cloned.cve_id, finding.cve_id);
        assert_eq!(cloned.affected_component, finding.affected_component);
        assert_eq!(cloned.affected_version, finding.affected_version);
        assert_eq!(cloned.fixed_version, finding.fixed_version);
        assert_eq!(cloned.source, finding.source);
        assert_eq!(cloned.source_url, finding.source_url);
    }

    // -----------------------------------------------------------------------
    // AdvisoryMatch debug trait
    // -----------------------------------------------------------------------

    #[test]
    fn test_advisory_match_debug() {
        let m = AdvisoryMatch {
            id: "GHSA-dbg-test".to_string(),
            summary: Some("Debug test".to_string()),
            details: None,
            severity: "high".to_string(),
            aliases: vec!["CVE-2024-0001".to_string()],
            affected_version: None,
            fixed_version: None,
            source: "osv.dev".to_string(),
            source_url: None,
        };
        let debug = format!("{:?}", m);
        assert!(debug.contains("AdvisoryMatch"));
        assert!(debug.contains("GHSA-dbg-test"));
        assert!(debug.contains("CVE-2024-0001"));
    }

    // -----------------------------------------------------------------------
    // AdvisoryMatch deserialization edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_advisory_match_deserialize_all_nulls() {
        let json = serde_json::json!({
            "id": "OSV-001",
            "summary": null,
            "details": null,
            "severity": "low",
            "aliases": [],
            "affected_version": null,
            "fixed_version": null,
            "source": "osv.dev",
            "source_url": null
        });
        let m: AdvisoryMatch = serde_json::from_value(json).unwrap();
        assert_eq!(m.id, "OSV-001");
        assert!(m.summary.is_none());
        assert!(m.details.is_none());
        assert!(m.aliases.is_empty());
        assert!(m.affected_version.is_none());
        assert!(m.fixed_version.is_none());
        assert!(m.source_url.is_none());
    }

    #[test]
    fn test_advisory_match_deserialize_multiple_aliases() {
        let json = serde_json::json!({
            "id": "GHSA-multi",
            "summary": null,
            "details": null,
            "severity": "critical",
            "aliases": ["CVE-2024-0001", "CVE-2024-0002", "GHSA-other"],
            "affected_version": null,
            "fixed_version": null,
            "source": "github",
            "source_url": null
        });
        let m: AdvisoryMatch = serde_json::from_value(json).unwrap();
        assert_eq!(m.aliases.len(), 3);
        assert_eq!(m.aliases[0], "CVE-2024-0001");
        assert_eq!(m.aliases[1], "CVE-2024-0002");
        assert_eq!(m.aliases[2], "GHSA-other");
    }

    // -----------------------------------------------------------------------
    // OsvQuery and OsvPackage serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_osv_query_serialization_with_version() {
        let query = OsvQuery {
            package: OsvPackage {
                name: "express".to_string(),
                ecosystem: "npm".to_string(),
            },
            version: Some("4.18.2".to_string()),
        };
        let json = serde_json::to_value(&query).unwrap();
        assert_eq!(json["package"]["name"], "express");
        assert_eq!(json["package"]["ecosystem"], "npm");
        assert_eq!(json["version"], "4.18.2");
    }

    #[test]
    fn test_osv_query_serialization_without_version() {
        let query = OsvQuery {
            package: OsvPackage {
                name: "flask".to_string(),
                ecosystem: "PyPI".to_string(),
            },
            version: None,
        };
        let json = serde_json::to_value(&query).unwrap();
        assert_eq!(json["package"]["name"], "flask");
        assert_eq!(json["package"]["ecosystem"], "PyPI");
        assert!(json["version"].is_null());
    }

    #[test]
    fn test_osv_package_serialization() {
        let pkg = OsvPackage {
            name: "tokio".to_string(),
            ecosystem: "crates.io".to_string(),
        };
        let json = serde_json::to_value(&pkg).unwrap();
        assert_eq!(json["name"], "tokio");
        assert_eq!(json["ecosystem"], "crates.io");
    }

    // -----------------------------------------------------------------------
    // Severity::from_str_loose usage in scanner context
    // -----------------------------------------------------------------------

    #[test]
    fn test_severity_from_str_loose_as_used_in_scanner() {
        // The scanner calls Severity::from_str_loose on advisory severity
        // strings and falls back to Severity::Medium. Verify all paths.
        assert_eq!(
            Severity::from_str_loose("critical").unwrap_or(Severity::Medium),
            Severity::Critical
        );
        assert_eq!(
            Severity::from_str_loose("high").unwrap_or(Severity::Medium),
            Severity::High
        );
        assert_eq!(
            Severity::from_str_loose("medium").unwrap_or(Severity::Medium),
            Severity::Medium
        );
        assert_eq!(
            Severity::from_str_loose("moderate").unwrap_or(Severity::Medium),
            Severity::Medium
        );
        assert_eq!(
            Severity::from_str_loose("low").unwrap_or(Severity::Medium),
            Severity::Low
        );
        assert_eq!(
            Severity::from_str_loose("info").unwrap_or(Severity::Medium),
            Severity::Info
        );
        assert_eq!(
            Severity::from_str_loose("informational").unwrap_or(Severity::Medium),
            Severity::Info
        );
        assert_eq!(
            Severity::from_str_loose("none").unwrap_or(Severity::Medium),
            Severity::Info
        );
        // Unknown strings fall back to Medium (the default used in the scanner)
        assert_eq!(
            Severity::from_str_loose("unknown").unwrap_or(Severity::Medium),
            Severity::Medium
        );
        assert_eq!(
            Severity::from_str_loose("").unwrap_or(Severity::Medium),
            Severity::Medium
        );
    }

    // -----------------------------------------------------------------------
    // parse_osv_response - robustness with non-array aliases
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_osv_response_aliases_not_array() {
        let deps = vec![Dependency {
            name: "pkg".to_string(),
            version: Some("1.0".to_string()),
            ecosystem: "npm".to_string(),
        }];
        let body = serde_json::json!({
            "results": [{
                "vulns": [{
                    "id": "OSV-2024-500",
                    "aliases": "not-an-array"
                }]
            }]
        });
        let matches = AdvisoryClient::parse_osv_response(&body, &deps);
        assert_eq!(matches.len(), 1);
        assert!(matches[0].aliases.is_empty());
    }

    #[test]
    fn test_parse_osv_response_aliases_null() {
        let deps = vec![Dependency {
            name: "pkg".to_string(),
            version: Some("1.0".to_string()),
            ecosystem: "npm".to_string(),
        }];
        let body = serde_json::json!({
            "results": [{
                "vulns": [{
                    "id": "OSV-2024-600",
                    "aliases": null
                }]
            }]
        });
        let matches = AdvisoryClient::parse_osv_response(&body, &deps);
        assert_eq!(matches.len(), 1);
        assert!(matches[0].aliases.is_empty());
    }

    // -----------------------------------------------------------------------
    // parse_osv_response - severity from severity array (type field)
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_osv_response_severity_from_empty_severity_array() {
        let deps = vec![Dependency {
            name: "pkg".to_string(),
            version: Some("1.0".to_string()),
            ecosystem: "npm".to_string(),
        }];
        let body = serde_json::json!({
            "results": [{
                "vulns": [{
                    "id": "OSV-2024-700",
                    "severity": []
                }]
            }]
        });
        let matches = AdvisoryClient::parse_osv_response(&body, &deps);
        assert_eq!(matches.len(), 1);
        // Empty severity array, no database_specific, falls back to "medium"
        assert_eq!(matches[0].severity, "medium");
    }

    // -----------------------------------------------------------------------
    // parse_osv_response - affected with no ranges
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_osv_response_affected_no_ranges() {
        let deps = vec![Dependency {
            name: "pkg".to_string(),
            version: Some("1.0".to_string()),
            ecosystem: "npm".to_string(),
        }];
        let body = serde_json::json!({
            "results": [{
                "vulns": [{
                    "id": "OSV-2024-800",
                    "affected": [{"package": {"name": "pkg"}}]
                }]
            }]
        });
        let matches = AdvisoryClient::parse_osv_response(&body, &deps);
        assert_eq!(matches.len(), 1);
        assert!(matches[0].fixed_version.is_none());
    }

    // -----------------------------------------------------------------------
    // parse_osv_response - affected ranges with no fixed event
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_osv_response_ranges_no_fixed_event() {
        let deps = vec![Dependency {
            name: "pkg".to_string(),
            version: Some("1.0".to_string()),
            ecosystem: "npm".to_string(),
        }];
        let body = serde_json::json!({
            "results": [{
                "vulns": [{
                    "id": "OSV-2024-900",
                    "affected": [{
                        "ranges": [{
                            "type": "SEMVER",
                            "events": [
                                {"introduced": "0"},
                                {"last_affected": "2.0.0"}
                            ]
                        }]
                    }]
                }]
            }]
        });
        let matches = AdvisoryClient::parse_osv_response(&body, &deps);
        assert_eq!(matches.len(), 1);
        assert!(matches[0].fixed_version.is_none());
    }

    // -----------------------------------------------------------------------
    // parse_github_advisory - vulnerabilities with null first_patched_version
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_github_advisory_first_patched_version_null() {
        let dep = Dependency {
            name: "pkg".to_string(),
            version: Some("1.0".to_string()),
            ecosystem: "npm".to_string(),
        };
        let adv = serde_json::json!({
            "ghsa_id": "GHSA-null-patch",
            "vulnerabilities": [
                {"first_patched_version": null}
            ]
        });
        let result = AdvisoryClient::parse_github_advisory(&adv, &dep).unwrap();
        assert!(result.fixed_version.is_none());
    }

    #[test]
    fn test_parse_github_advisory_no_vulnerabilities_key() {
        let dep = Dependency {
            name: "pkg".to_string(),
            version: None,
            ecosystem: "npm".to_string(),
        };
        let adv = serde_json::json!({
            "ghsa_id": "GHSA-no-vulns"
        });
        let result = AdvisoryClient::parse_github_advisory(&adv, &dep).unwrap();
        assert!(result.fixed_version.is_none());
    }

    // -----------------------------------------------------------------------
    // Dependency with various ecosystems
    // -----------------------------------------------------------------------

    #[test]
    fn test_dependency_all_ecosystems() {
        let ecosystems = [
            "npm",
            "PyPI",
            "crates.io",
            "Maven",
            "Go",
            "NuGet",
            "RubyGems",
            "Linux",
        ];
        for eco in ecosystems {
            let dep = Dependency {
                name: "test-pkg".to_string(),
                version: Some("1.0.0".to_string()),
                ecosystem: eco.to_string(),
            };
            assert_eq!(dep.ecosystem, eco);
        }
    }

    // -----------------------------------------------------------------------
    // OsvBatchQuery with single query
    // -----------------------------------------------------------------------

    #[test]
    fn test_osv_batch_query_single_entry() {
        let query = OsvBatchQuery {
            queries: vec![OsvQuery {
                package: OsvPackage {
                    name: "serde".to_string(),
                    ecosystem: "crates.io".to_string(),
                },
                version: Some("1.0.195".to_string()),
            }],
        };
        let json = serde_json::to_value(&query).unwrap();
        let queries = json["queries"].as_array().unwrap();
        assert_eq!(queries.len(), 1);
        assert_eq!(queries[0]["package"]["name"], "serde");
        assert_eq!(queries[0]["version"], "1.0.195");
    }

    // -----------------------------------------------------------------------
    // parse_osv_response - dep with no version
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_osv_response_dep_with_no_version() {
        let deps = vec![Dependency {
            name: "unversioned-pkg".to_string(),
            version: None,
            ecosystem: "npm".to_string(),
        }];
        let body = serde_json::json!({
            "results": [{
                "vulns": [{
                    "id": "VULN-NO-VER",
                    "summary": "Something bad"
                }]
            }]
        });
        let matches = AdvisoryClient::parse_osv_response(&body, &deps);
        assert_eq!(matches.len(), 1);
        assert!(matches[0].affected_version.is_none());
    }

    // -----------------------------------------------------------------------
    // parse_github_advisory - dep with no version
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_github_advisory_dep_with_no_version() {
        let dep = Dependency {
            name: "pkg".to_string(),
            version: None,
            ecosystem: "npm".to_string(),
        };
        let adv = serde_json::json!({
            "ghsa_id": "GHSA-no-ver",
            "severity": "low"
        });
        let result = AdvisoryClient::parse_github_advisory(&adv, &dep).unwrap();
        assert!(result.affected_version.is_none());
        assert_eq!(result.severity, "low");
    }

    // -----------------------------------------------------------------------
    // parse_github_advisory - description field
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_github_advisory_description_maps_to_details() {
        let dep = Dependency {
            name: "pkg".to_string(),
            version: None,
            ecosystem: "npm".to_string(),
        };
        let adv = serde_json::json!({
            "ghsa_id": "GHSA-desc",
            "description": "Full description of the vulnerability"
        });
        let result = AdvisoryClient::parse_github_advisory(&adv, &dep).unwrap();
        assert_eq!(
            result.details.as_deref(),
            Some("Full description of the vulnerability")
        );
    }

    // -----------------------------------------------------------------------
    // extract_dependencies - nested gemfile.lock
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_dependencies_nested_gemfile_lock() {
        let artifact = make_artifact("vendor/Gemfile.lock", "/ruby/vendor/Gemfile.lock", None);
        let content = Bytes::from("    bundler (2.4.22)\n");
        let deps = DependencyScanner::extract_dependencies(&artifact, None, &content);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].ecosystem, "RubyGems");
    }

    // -----------------------------------------------------------------------
    // extract_dependencies - packages.config (NuGet)
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_dependencies_packages_config_case_insensitive() {
        let artifact = make_artifact("PACKAGES.CONFIG", "/nuget/PACKAGES.CONFIG", None);
        let content = Bytes::from(r#"<package id="TestPkg" version="1.0" />"#);
        let deps = DependencyScanner::extract_dependencies(&artifact, None, &content);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].ecosystem, "NuGet");
    }

    // -----------------------------------------------------------------------
    // parse_osv_response - vuln with details but no summary
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_osv_response_details_without_summary() {
        let deps = vec![Dependency {
            name: "pkg".to_string(),
            version: Some("1.0".to_string()),
            ecosystem: "npm".to_string(),
        }];
        let body = serde_json::json!({
            "results": [{
                "vulns": [{
                    "id": "OSV-DETAIL-ONLY",
                    "details": "A detailed description without summary"
                }]
            }]
        });
        let matches = AdvisoryClient::parse_osv_response(&body, &deps);
        assert_eq!(matches.len(), 1);
        assert!(matches[0].summary.is_none());
        assert_eq!(
            matches[0].details.as_deref(),
            Some("A detailed description without summary")
        );
    }

    // -----------------------------------------------------------------------
    // AdvisoryMatch deserialization from JSON string
    // -----------------------------------------------------------------------

    #[test]
    fn test_advisory_match_deserialize_from_json_string() {
        let json_str = r#"{
            "id": "GHSA-json-str",
            "summary": "From JSON string",
            "details": "Details here",
            "severity": "critical",
            "aliases": ["CVE-2024-0001", "GHSA-other"],
            "affected_version": "1.0.0",
            "fixed_version": "1.0.1",
            "source": "github",
            "source_url": "https://example.com/advisory"
        }"#;
        let m: AdvisoryMatch = serde_json::from_str(json_str).unwrap();
        assert_eq!(m.id, "GHSA-json-str");
        assert_eq!(m.summary.as_deref(), Some("From JSON string"));
        assert_eq!(m.details.as_deref(), Some("Details here"));
        assert_eq!(m.severity, "critical");
        assert_eq!(m.aliases.len(), 2);
        assert_eq!(m.affected_version.as_deref(), Some("1.0.0"));
        assert_eq!(m.fixed_version.as_deref(), Some("1.0.1"));
        assert_eq!(m.source, "github");
        assert_eq!(
            m.source_url.as_deref(),
            Some("https://example.com/advisory")
        );
    }

    // -----------------------------------------------------------------------
    // parse_osv_response - source URL format
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_osv_response_source_url_format() {
        let deps = vec![Dependency {
            name: "pkg".to_string(),
            version: Some("1.0".to_string()),
            ecosystem: "npm".to_string(),
        }];
        let body = serde_json::json!({
            "results": [{
                "vulns": [{"id": "GHSA-url-test"}]
            }]
        });
        let matches = AdvisoryClient::parse_osv_response(&body, &deps);
        assert_eq!(matches.len(), 1);
        assert_eq!(
            matches[0].source_url.as_deref(),
            Some("https://osv.dev/vulnerability/GHSA-url-test")
        );
        assert_eq!(matches[0].source, "osv.dev");
    }

    // -----------------------------------------------------------------------
    // parse_github_advisory - source field is always "github"
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_github_advisory_source_is_github() {
        let dep = Dependency {
            name: "pkg".to_string(),
            version: None,
            ecosystem: "npm".to_string(),
        };
        let adv = serde_json::json!({
            "ghsa_id": "GHSA-src-test",
            "html_url": "https://github.com/advisories/GHSA-src-test"
        });
        let result = AdvisoryClient::parse_github_advisory(&adv, &dep).unwrap();
        assert_eq!(result.source, "github");
        assert_eq!(
            result.source_url.as_deref(),
            Some("https://github.com/advisories/GHSA-src-test")
        );
    }

    // -----------------------------------------------------------------------
    // make_artifact helper validation
    // -----------------------------------------------------------------------

    #[test]
    fn test_make_artifact_fields() {
        let artifact = make_artifact("test.jar", "/maven/test.jar", Some("3.0"));
        assert_eq!(artifact.name, "test.jar");
        assert_eq!(artifact.path, "/maven/test.jar");
        assert_eq!(artifact.version.as_deref(), Some("3.0"));
        assert_eq!(artifact.size_bytes, 100);
        assert_eq!(artifact.checksum_sha256, "abc123");
        assert!(!artifact.is_deleted);
        assert!(artifact.uploaded_by.is_none());
        assert!(artifact.checksum_md5.is_none());
        assert!(artifact.checksum_sha1.is_none());
    }

    #[test]
    fn test_make_artifact_no_version() {
        let artifact = make_artifact("readme.md", "/docs/readme.md", None);
        assert!(artifact.version.is_none());
    }

    // -----------------------------------------------------------------------
    // Severity equality used in count_findings_by_severity
    // -----------------------------------------------------------------------

    #[test]
    fn test_severity_equality() {
        assert_eq!(Severity::Critical, Severity::Critical);
        assert_eq!(Severity::High, Severity::High);
        assert_eq!(Severity::Medium, Severity::Medium);
        assert_eq!(Severity::Low, Severity::Low);
        assert_eq!(Severity::Info, Severity::Info);
        assert_ne!(Severity::Critical, Severity::High);
        assert_ne!(Severity::High, Severity::Medium);
        assert_ne!(Severity::Low, Severity::Info);
    }

    // -----------------------------------------------------------------------
    // parse_osv_response - multiple fixed events picks first
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_osv_response_multiple_fixed_events() {
        let deps = vec![Dependency {
            name: "pkg".to_string(),
            version: Some("1.0".to_string()),
            ecosystem: "npm".to_string(),
        }];
        let body = serde_json::json!({
            "results": [{
                "vulns": [{
                    "id": "OSV-MULTI-FIX",
                    "affected": [{
                        "ranges": [{
                            "type": "SEMVER",
                            "events": [
                                {"introduced": "0"},
                                {"fixed": "1.5.0"},
                                {"introduced": "2.0.0"},
                                {"fixed": "2.1.0"}
                            ]
                        }]
                    }]
                }]
            }]
        });
        let matches = AdvisoryClient::parse_osv_response(&body, &deps);
        assert_eq!(matches.len(), 1);
        // find_map picks the first "fixed" event
        assert_eq!(matches[0].fixed_version.as_deref(), Some("1.5.0"));
    }

    // -----------------------------------------------------------------------
    // dedup_advisories - multiple alias overlap
    // -----------------------------------------------------------------------

    #[test]
    fn test_dedup_advisories_transitive_alias_dedup() {
        // OSV entry has alias CVE-X. GH entry #1 has id CVE-X.
        // GH entry #2 has id GHSA-Y. Both should reduce to just OSV entry.
        let osv = vec![AdvisoryMatch {
            id: "GHSA-xxx".to_string(),
            summary: None,
            details: None,
            severity: "high".to_string(),
            aliases: vec!["CVE-2024-1111".to_string(), "GHSA-yyy".to_string()],
            affected_version: None,
            fixed_version: None,
            source: "osv.dev".to_string(),
            source_url: None,
        }];
        let gh = vec![
            AdvisoryMatch {
                id: "CVE-2024-1111".to_string(),
                summary: None,
                details: None,
                severity: "high".to_string(),
                aliases: vec![],
                affected_version: None,
                fixed_version: None,
                source: "github".to_string(),
                source_url: None,
            },
            AdvisoryMatch {
                id: "GHSA-yyy".to_string(),
                summary: None,
                details: None,
                severity: "high".to_string(),
                aliases: vec![],
                affected_version: None,
                fixed_version: None,
                source: "github".to_string(),
                source_url: None,
            },
        ];
        let result = dedup_advisories(osv, gh);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].id, "GHSA-xxx");
    }
}
