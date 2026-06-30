use async_trait::async_trait;
use bytes::Bytes;
use serde::Deserialize;
use std::sync::{Arc, Mutex};
use tracing::{info, warn};

use crate::error::{AppError, Result};
use crate::models::artifact::{Artifact, ArtifactMetadata};
use crate::models::user::User;
use crate::services::auth_service::AuthService;
use crate::services::scanner_service::{ScanOutput, ScanTarget, Scanner};

#[cfg(test)]
use crate::models::security::RawFinding;
#[cfg(test)]
use crate::services::scanner_service::convert_trivy_findings;

// ---------------------------------------------------------------------------
// Trivy JSON report structures
//
// These are retained as the *internal* canonical report shape because
// `TrivyFsScanner` and `IncusScanner` still drive the trivy server directly
// (CLI `--server` / dir-mode) and deserialize this exact JSON, and because the
// shared `scanner_service::convert_trivy_findings` / `convert_trivy_packages`
// converters consume it. The container `ImageScanner` no longer produces this
// from a trivy server: it talks to a Harbor scanner-adapter (below) and maps
// the adapter's report INTO this shape so the conversion + dashboards
// (source = 'trivy') stay byte-for-byte compatible.
// ---------------------------------------------------------------------------
#[derive(Debug, Deserialize)]
pub struct TrivyReport {
    #[serde(rename = "Results", default)]
    pub results: Vec<TrivyResult>,
}

#[derive(Debug, Deserialize)]
pub struct TrivyResult {
    #[serde(rename = "Target")]
    pub target: String,
    #[serde(rename = "Class", default)]
    pub class: String,
    #[serde(rename = "Type", default)]
    pub result_type: String,
    #[serde(rename = "Vulnerabilities", default)]
    pub vulnerabilities: Option<Vec<TrivyVulnerability>>,
    /// Populated when Trivy is invoked with `--list-all-pkgs`. Lists every
    /// package the scanner enumerated for this target, including ones with
    /// no known vulnerabilities, so SBOM generation (#903) can reflect the
    /// full dependency tree rather than only the CVE-bearing subset.
    #[serde(rename = "Packages", default)]
    pub packages: Option<Vec<TrivyPackage>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TrivyVulnerability {
    #[serde(rename = "VulnerabilityID")]
    pub vulnerability_id: String,
    #[serde(rename = "PkgName")]
    pub pkg_name: String,
    #[serde(rename = "InstalledVersion")]
    pub installed_version: String,
    #[serde(rename = "FixedVersion")]
    pub fixed_version: Option<String>,
    #[serde(rename = "Severity")]
    pub severity: String,
    #[serde(rename = "Title")]
    pub title: Option<String>,
    #[serde(rename = "Description")]
    pub description: Option<String>,
    #[serde(rename = "PrimaryURL")]
    pub primary_url: Option<String>,
}

/// A package entry from a Trivy `Packages` block. Only fields used by
/// inventory persistence are deserialized; everything else (DependsOn,
/// SrcVersion, Layer, etc.) is dropped silently via the default
/// `deny_unknown_fields` policy being absent.
#[derive(Debug, Clone, Deserialize)]
pub struct TrivyPackage {
    #[serde(rename = "Name", default)]
    pub name: String,
    #[serde(rename = "Version", default)]
    pub version: String,
    /// Trivy emits `Licenses` as an array of strings. Multi-license packages
    /// produce multiple entries; persistence joins them with `" OR "` per
    /// CycloneDX convention.
    #[serde(rename = "Licenses", default)]
    pub licenses: Option<Vec<String>>,
    #[serde(rename = "Identifier", default)]
    pub identifier: Option<TrivyPackageIdentifier>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TrivyPackageIdentifier {
    #[serde(rename = "PURL", default)]
    pub purl: Option<String>,
}

// ---------------------------------------------------------------------------
// Harbor Pluggable Scanner API v1 report structures
//
// https://github.com/goharbor/pluggable-scanner-spec — the `harbor-scanner-trivy`
// adapter (and any other Harbor-compatible adapter) returns this shape from
// GET /api/v1/scan/{id}/report. Only the fields we map into `TrivyReport` are
// deserialized; unknown fields (`artifact`, `severity` aggregate, CVSS blocks)
// are ignored.
// ---------------------------------------------------------------------------

/// Response body of `POST /api/v1/scan` — the adapter accepts the scan and
/// returns the opaque id used to fetch the report.
#[derive(Debug, Deserialize)]
struct HarborScanResponse {
    id: String,
}

/// Top-level Harbor vulnerability report (`version=1.1`).
#[derive(Debug, Deserialize)]
pub struct HarborScanReport {
    #[serde(default)]
    pub scanner: Option<HarborScanner>,
    #[serde(default)]
    pub vulnerabilities: Vec<HarborVulnerability>,
}

/// Identifies the scanner that produced the report. Feeds
/// `Scanner::version()` now that the in-image trivy CLI (and its
/// `trivy --version` probe) is gone (#2059).
#[derive(Debug, Deserialize)]
pub struct HarborScanner {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
}

/// A single Harbor vulnerability row.
#[derive(Debug, Deserialize)]
pub struct HarborVulnerability {
    pub id: String,
    #[serde(default)]
    pub package: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub fix_version: Option<String>,
    #[serde(default)]
    pub severity: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub links: Option<Vec<String>>,
}

/// Normalize a Harbor severity token to the trivy severity vocabulary the
/// shared converter understands. Harbor adds `Negligible` (mapped to `Low`)
/// and `Unknown` (mapped to `Unknown`, which `Severity::from_str_loose` does
/// not recognise and therefore falls back to `Info` in the converter). All
/// other tokens (Critical/High/Medium/Low/None) pass through unchanged. Pure
/// fn so it is covered without a network.
fn normalize_harbor_severity(sev: &str) -> String {
    match sev.to_ascii_lowercase().as_str() {
        "negligible" => "Low".to_string(),
        // Empty severity is normalized to `Unknown` (-> Info in the converter).
        // `Unknown` itself is intentionally passed through: `from_str_loose`
        // returns None for it and the converter defaults to Info, matching the
        // spec's "Unknown -> Info" requirement without duplicating the mapping.
        "" => "Unknown".to_string(),
        _ => sev.to_string(),
    }
}

/// Map a Harbor scan report into the internal [`TrivyReport`] shape so the
/// shared `convert_trivy_findings` / `ScanOutput::from_trivy_report`
/// conversion (and the `source = 'trivy'` dashboards) are reused verbatim —
/// no duplicated severity mapping. Pure fn: fully unit-testable.
fn harbor_report_to_trivy(report: &HarborScanReport, target: &str) -> TrivyReport {
    let vulnerabilities: Vec<TrivyVulnerability> = report
        .vulnerabilities
        .iter()
        .map(|v| TrivyVulnerability {
            vulnerability_id: v.id.clone(),
            pkg_name: v.package.clone(),
            installed_version: v.version.clone(),
            fixed_version: v.fix_version.clone(),
            severity: normalize_harbor_severity(&v.severity),
            // Leave the title empty so the converter synthesizes
            // "<id> in <pkg>" exactly as it does for native trivy rows.
            title: None,
            description: v.description.clone(),
            primary_url: v.links.as_ref().and_then(|l| l.first()).cloned(),
        })
        .collect();

    TrivyReport {
        results: vec![TrivyResult {
            target: target.to_string(),
            class: "os-pkgs".to_string(),
            result_type: String::new(),
            vulnerabilities: if vulnerabilities.is_empty() {
                None
            } else {
                Some(vulnerabilities)
            },
            // Harbor's vulnerability report (v1.1) does not enumerate the full
            // package inventory, so there is no Packages block to map. Image
            // SBOM inventory continues to come from the grype path.
            packages: None,
        }],
    }
}

/// How the adapter should address the artifact: by tag or by digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AdapterReference {
    Tag(String),
    Digest(String),
}

/// A resolved Harbor scan target: the registry-relative repository path and
/// the tag/digest reference. Produced by [`build_adapter_scan_artifact`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AdapterScanArtifact {
    /// `<repo_key>/<name>` (or bare `<name>` for the legacy keyless path).
    pub repository: String,
    pub reference: AdapterReference,
}

/// Build the Harbor `artifact` target from the stored OCI manifest path.
///
/// Reuses `parse_oci_manifest_path` to split `(name, reference)` and
/// `resolve_scan_reference` to (a) resolve a multi-arch image index to a
/// concrete child-platform digest (#1971) and (b) keep digest-pinned refs
/// (#1483) as digests. The owning `repository_key` is prepended so the adapter
/// pulls Artifact Keeper's own stored image rather than a same-named public
/// image. Pure fn: no network, fully unit-testable.
pub(crate) fn build_adapter_scan_artifact(
    artifact_path: &str,
    repository_key: Option<&str>,
    body: &[u8],
) -> Option<AdapterScanArtifact> {
    let (name, reference) =
        crate::services::scanner_service::parse_oci_manifest_path(artifact_path)?;
    let resolved =
        crate::services::scanner_service::resolve_scan_reference(body, reference).into_reference();

    let repository = match repository_key {
        Some(key) => format!("{}/{}", key, name),
        None => name.to_string(),
    };

    let reference = if crate::services::scanner_service::is_oci_digest_reference(&resolved) {
        AdapterReference::Digest(resolved)
    } else {
        AdapterReference::Tag(resolved)
    };

    Some(AdapterScanArtifact {
        repository,
        reference,
    })
}

/// Container image scanner that delegates to a Harbor Pluggable Scanner API v1
/// adapter (e.g. `harbor-scanner-trivy`) over HTTP.
///
/// FAIL-CLOSED contract (#2088): every adapter error — unreachable, non-2xx,
/// timeout, or a report that never becomes ready within the scan budget —
/// surfaces as `Err(AppError::BadGateway)` so the orchestrator marks the scan
/// `failed`. This scanner MUST NEVER return `Ok` with empty findings on an
/// error path: a silent zero-finding completion is exactly the false-clean
/// regression #2088 tracks (the old trivy-server Twirp `Scan` call returned an
/// empty result that was mapped to "completed, 0 findings").
pub struct ImageScanner {
    /// Base URL of the Harbor scanner adapter, e.g. `http://trivy:8090`.
    adapter_url: String,
    http: reqwest::Client,
    /// Dedicated client with redirects disabled so a `302 Found` "report not
    /// ready" response from the adapter is observed rather than followed.
    poll_http: reqwest::Client,
    /// Optional token minter for private-repo pulls. When both an
    /// `AuthService` and a system scan identity are wired, each scan request
    /// carries a short-lived scoped JWT as `registry.authorization` so the
    /// adapter can pull internal/private images. Absent in the default
    /// (anonymous) wiring; provisioning a scanner service account to populate
    /// it is an ops follow-up (see PR notes).
    auth: Option<Arc<AuthService>>,
    scan_identity: Option<User>,
    /// TTL (seconds) for the per-repo scan token minted for each scan request
    /// (config `scan_token_ttl_seconds`). Only consulted when a minter is
    /// wired.
    scan_token_ttl_seconds: i64,
    /// Scanner version reported by the adapter on the most recent successful
    /// scan (e.g. `trivy-0.71.2`). The in-image `trivy --version` probe is
    /// gone (#2059), so this is the only available provenance.
    last_scanner_version: Mutex<Option<String>>,
}

impl ImageScanner {
    pub fn new(adapter_url: String) -> Self {
        Self {
            adapter_url,
            http: crate::services::http_client::base_client_builder()
                .timeout(std::time::Duration::from_secs(300))
                .build()
                .unwrap_or_default(),
            poll_http: crate::services::http_client::base_client_builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .unwrap_or_default(),
            auth: None,
            scan_identity: None,
            scan_token_ttl_seconds: 300,
            last_scanner_version: Mutex::new(None),
        }
    }

    /// Attach a token minter so private-repo image pulls carry a short-lived
    /// scoped JWT in `registry.authorization`. The identity is a scanner /
    /// system account; the token is minted per scan via
    /// `AuthService::generate_scan_token` — pinned to the repository being
    /// scanned and short-lived (`ttl_seconds`) — and is NEVER logged.
    #[must_use]
    pub fn with_token_minter(
        mut self,
        auth: Arc<AuthService>,
        identity: User,
        ttl_seconds: i64,
    ) -> Self {
        self.auth = Some(auth);
        self.scan_identity = Some(identity);
        self.scan_token_ttl_seconds = ttl_seconds;
        self
    }

    /// Check if this artifact is an OCI/Docker image manifest. Thin wrapper
    /// around the shared [`crate::services::scanner_service::is_oci_image_artifact`]
    /// helper so the predicate has one source of truth.
    fn is_container_image(artifact: &Artifact) -> bool {
        crate::services::scanner_service::is_oci_image_artifact(artifact)
    }

    /// Registry base URL the adapter should pull from. Host comes from the
    /// shared `grype_scanner::resolve_registry_host` (AK_GRYPE_REGISTRY_HOST /
    /// PEER_PUBLIC_ENDPOINT / `localhost:8080`), which strips any scheme and
    /// embedded credentials; we re-add an `http://` scheme for the adapter's
    /// registry client.
    fn registry_url() -> String {
        let host = crate::services::grype_scanner::resolve_registry_host();
        format!("http://{}", host)
    }

    /// Mint the `registry.authorization` value for a scan request, or `None`
    /// for an anonymous pull. The token is short-lived (`scan_token_ttl_seconds`)
    /// and scoped to exactly the repository being scanned (`repo_key`, matched
    /// against the OCI pull handler's `scan_pull_repo` gate), so a leaked scan
    /// token cannot pull any other repository. NEVER log the result.
    fn registry_authorization(&self, repo_key: &str) -> Option<String> {
        match (&self.auth, &self.scan_identity) {
            (Some(auth), Some(user)) => {
                match auth.generate_scan_token(user, repo_key, self.scan_token_ttl_seconds) {
                    Ok(token) => Some(format!("Bearer {}", token)),
                    Err(e) => {
                        // Token minting failure degrades to an anonymous pull
                        // rather than failing the scan outright: the scan still
                        // fails-closed downstream if the (now anonymous) pull is
                        // rejected by the adapter. Do not include the error's
                        // token material.
                        warn!("Image scan registry token minting failed: {}", e);
                        None
                    }
                }
            }
            _ => None,
        }
    }

    /// Best-effort manifest media type for the Harbor request. Uses the stored
    /// content type when it is a recognised manifest media type, otherwise
    /// defaults to the Docker v2 manifest type the adapter accepts.
    fn manifest_mime_type(content_type: &str) -> String {
        if content_type.contains("manifest") || content_type.contains("image.index") {
            content_type.to_string()
        } else {
            "application/vnd.docker.distribution.manifest.v2+json".to_string()
        }
    }

    /// Build the JSON body for `POST /api/v1/scan`.
    fn build_scan_request(
        registry_url: &str,
        authorization: Option<&str>,
        artifact: &AdapterScanArtifact,
        mime_type: &str,
    ) -> serde_json::Value {
        let mut registry = serde_json::json!({ "url": registry_url });
        if let Some(auth) = authorization {
            registry["authorization"] = serde_json::Value::String(auth.to_string());
        }

        let mut artifact_obj = serde_json::json!({
            "repository": artifact.repository,
            "mime_type": mime_type,
        });
        match &artifact.reference {
            AdapterReference::Tag(t) => {
                artifact_obj["tag"] = serde_json::Value::String(t.clone());
            }
            AdapterReference::Digest(d) => {
                artifact_obj["digest"] = serde_json::Value::String(d.clone());
            }
        }

        serde_json::json!({
            "registry": registry,
            "artifact": artifact_obj,
        })
    }

    /// Number of `/probe/ready` attempts before declaring the adapter down.
    /// Mirrors the previous trivy `/healthz` gate (#888): three attempts with
    /// backoff absorbs a short pod restart without permanently failing
    /// in-flight scans.
    const HEALTH_CHECK_ATTEMPTS: u32 = 3;
    const HEALTH_CHECK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
    const HEALTH_CHECK_BACKOFF: std::time::Duration = std::time::Duration::from_millis(500);

    /// Total wall-clock budget for polling the report. Kept under the 300s
    /// client timeout so we surface a descriptive BadGateway rather than a
    /// raw reqwest timeout.
    const REPORT_POLL_BUDGET: std::time::Duration = std::time::Duration::from_secs(280);
    /// Default delay between report polls when the adapter does not send a
    /// `Refresh-After` header.
    const REPORT_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

    /// Adapter readiness gate. Returns `Ok(())` when `/probe/ready` responds
    /// 2xx, otherwise `Err(AppError::BadGateway)` after retries so the
    /// orchestrator marks the scan FAILED rather than silently completing with
    /// zero findings (#888 / #2088).
    async fn check_adapter_health(&self) -> Result<()> {
        let url = format!("{}/probe/ready", self.adapter_url);
        let mut last_err: Option<AppError> = None;

        for attempt in 1..=Self::HEALTH_CHECK_ATTEMPTS {
            let result = self
                .http
                .get(&url)
                .timeout(Self::HEALTH_CHECK_TIMEOUT)
                .send()
                .await;

            match result {
                Ok(resp) if resp.status().is_success() => return Ok(()),
                Ok(resp) => {
                    let msg = format!(
                        "Scanner adapter at {} is not ready: HTTP {}",
                        self.adapter_url,
                        resp.status()
                    );
                    crate::services::metrics_service::record_scanner_health_check_failure(
                        "trivy",
                        "unhealthy",
                    );
                    warn!(
                        "Scanner adapter /probe/ready attempt {} failed: {}",
                        attempt, msg
                    );
                    last_err = Some(AppError::BadGateway(msg));
                }
                Err(e) => {
                    let msg = format!(
                        "Scanner adapter at {} is unreachable: {}",
                        self.adapter_url, e
                    );
                    crate::services::metrics_service::record_scanner_health_check_failure(
                        "trivy",
                        "unreachable",
                    );
                    warn!(
                        "Scanner adapter /probe/ready attempt {} failed: {}",
                        attempt, msg
                    );
                    last_err = Some(AppError::BadGateway(msg));
                }
            }

            if attempt < Self::HEALTH_CHECK_ATTEMPTS {
                tokio::time::sleep(Self::HEALTH_CHECK_BACKOFF).await;
            }
        }

        Err(last_err.unwrap_or_else(|| {
            AppError::BadGateway(format!(
                "Scanner adapter at {} readiness check failed",
                self.adapter_url
            ))
        }))
    }

    /// Submit a scan request and return the adapter-assigned scan id.
    async fn submit_scan(&self, body: &serde_json::Value) -> Result<String> {
        let url = format!("{}/api/v1/scan", self.adapter_url);
        let resp = self.http.post(&url).json(body).send().await.map_err(|e| {
            AppError::BadGateway(format!("Scanner adapter scan request failed: {}", e))
        })?;

        let status = resp.status();
        // Harbor returns 202 Accepted; tolerate any 2xx with a parseable id.
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(AppError::BadGateway(format!(
                "Scanner adapter returned {} on scan submit: {}",
                status, text
            )));
        }

        let parsed: HarborScanResponse = resp.json().await.map_err(|e| {
            AppError::BadGateway(format!(
                "Failed to parse scanner adapter scan response: {}",
                e
            ))
        })?;
        // An empty/whitespace id would produce a bogus `/scan//report` poll URL
        // that can never resolve; reject it up front (fail-closed) rather than
        // polling a nonsensical endpoint until the budget is exhausted.
        if parsed.id.trim().is_empty() {
            return Err(AppError::BadGateway(
                "Scanner adapter returned an empty scan id on submit".to_string(),
            ));
        }
        Ok(parsed.id)
    }

    /// Poll `GET /api/v1/scan/{id}/report` until the report is ready or the
    /// poll budget is exhausted. Honors a `Refresh-After` header when present.
    ///
    /// Fail-closed: a never-ready report, a non-2xx terminal status, or a
    /// transport error all return `Err(AppError::BadGateway)` — never an empty
    /// report.
    async fn poll_report(&self, scan_id: &str) -> Result<HarborScanReport> {
        let url = format!("{}/api/v1/scan/{}/report", self.adapter_url, scan_id);
        let deadline = std::time::Instant::now() + Self::REPORT_POLL_BUDGET;

        loop {
            let resp = self
                .poll_http
                .get(&url)
                .header(
                    reqwest::header::ACCEPT,
                    "application/vnd.security.vulnerability.report; version=1.1",
                )
                .send()
                .await
                .map_err(|e| {
                    AppError::BadGateway(format!("Scanner adapter report request failed: {}", e))
                })?;

            let status = resp.status();

            if status.is_success() {
                return resp.json::<HarborScanReport>().await.map_err(|e| {
                    AppError::BadGateway(format!("Failed to parse scanner adapter report: {}", e))
                });
            }

            // "Not ready yet": Harbor (and our in-house adapter #2092) signal
            // this with a 302 Found and a `Refresh-After` header. Everything
            // else — including a 404 — is terminal: #2092 returns 404 for a
            // genuinely unknown/expired scan id, so treating it as pending would
            // poll fruitlessly until the ~280s budget is exhausted, tying up a
            // scan worker for ~5 minutes. Fail fast (still fail-closed: an Err,
            // never an Ok-with-0-findings).
            let pending = status == reqwest::StatusCode::FOUND;
            if !pending {
                let text = resp.text().await.unwrap_or_default();
                return Err(AppError::BadGateway(format!(
                    "Scanner adapter returned {} fetching report: {}",
                    status, text
                )));
            }

            let refresh_after = resp
                .headers()
                .get("Refresh-After")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.trim().parse::<u64>().ok())
                .map(std::time::Duration::from_secs)
                .unwrap_or(Self::REPORT_POLL_INTERVAL);

            if std::time::Instant::now() + refresh_after >= deadline {
                return Err(AppError::BadGateway(format!(
                    "Scanner adapter report for {} not ready within {}s budget",
                    scan_id,
                    Self::REPORT_POLL_BUDGET.as_secs()
                )));
            }

            tokio::time::sleep(refresh_after).await;
        }
    }

    /// Submit a scan, poll for the report, and convert it. Shared by the
    /// legacy `scan` (bare repository) and the repository-aware `scan_target`.
    async fn run_image_scan(
        &self,
        artifact: &AdapterScanArtifact,
        mime_type: &str,
        repo_key: Option<&str>,
    ) -> Result<ScanOutput> {
        // Readiness gate first so a down adapter fails the scan with a clear
        // BadGateway rather than mid-stream.
        self.check_adapter_health().await?;

        let registry_url = Self::registry_url();
        // Mint a per-repository scoped pull token only when we know which repo
        // is being scanned (the repository-aware `scan_target` path). The
        // legacy keyless `scan` path pulls anonymously as before.
        let authorization = repo_key.and_then(|k| self.registry_authorization(k));
        let body =
            Self::build_scan_request(&registry_url, authorization.as_deref(), artifact, mime_type);

        let reference_label = match &artifact.reference {
            AdapterReference::Tag(t) => format!("{}:{}", artifact.repository, t),
            AdapterReference::Digest(d) => format!("{}@{}", artifact.repository, d),
        };
        info!("Starting adapter image scan for {}", reference_label);

        let scan_id = self.submit_scan(&body).await?;
        let report = self.poll_report(&scan_id).await?;

        // Cache the adapter-reported scanner version for `version()` — the
        // in-image trivy --version probe is gone (#2059).
        if let Some(scanner) = report.scanner.as_ref() {
            if let Some(ver) = scanner.version.as_ref().filter(|v| !v.is_empty()) {
                let normalized = if ver.starts_with("trivy-") {
                    ver.clone()
                } else {
                    format!("trivy-{}", ver)
                };
                if let Ok(mut guard) = self.last_scanner_version.lock() {
                    *guard = Some(normalized);
                }
            }
        }

        // Source label is intentionally "trivy" (not "trivy-image") to
        // preserve back-compat with dashboards / filters that group findings
        // by `source = 'trivy'`.
        let trivy_report = harbor_report_to_trivy(&report, &reference_label);
        let output = ScanOutput::from_trivy_report(&trivy_report, "trivy");

        info!(
            "Adapter image scan complete for {}: {} vulnerabilities",
            reference_label,
            output.findings.len()
        );

        Ok(output)
    }

    /// Convert Trivy vulnerabilities into RawFinding rows. Thin wrapper around
    /// the shared [`convert_trivy_findings`] helper so the existing tests can
    /// call `ImageScanner::convert_findings(report)` as before.
    #[cfg(test)]
    pub(crate) fn convert_findings(report: &TrivyReport) -> Vec<RawFinding> {
        convert_trivy_findings(report, "trivy")
    }
}

#[async_trait]
impl Scanner for ImageScanner {
    fn name(&self) -> &str {
        "container-image"
    }

    fn scan_type(&self) -> &str {
        "image"
    }

    /// Surface the container-image content-type check through the trait so the
    /// orchestrator can gate on it without creating a `scan_results` row for
    /// non-image artifacts (issues #961, #994).
    fn is_applicable(&self, artifact: &Artifact) -> bool {
        Self::is_container_image(artifact)
    }

    /// an OCI manifest artifact passes `is_container_image` purely on its
    /// manifest mediaType, which is byte-identical between a real image and a
    /// Helm chart / cosign signature / SBOM / WASM module. When the
    /// orchestrator supplies the manifest body, additionally require that the
    /// body classify as a real container image (container config + non-
    /// signature layers, or an image index). Bodyless callers (tests, legacy)
    /// keep the path-only decision (#1971).
    fn is_applicable_for_target(&self, target: &ScanTarget<'_>) -> bool {
        Self::is_container_image(target.artifact)
            && crate::services::scanner_service::oci_target_is_scannable_image(target)
    }

    /// Scanner version reported by the adapter on the last successful scan
    /// (e.g. `trivy-0.71.2`). `None` until a scan has run, because the
    /// in-image `trivy --version` probe was removed with the CLI (#2059).
    async fn version(&self) -> Option<String> {
        self.last_scanner_version
            .lock()
            .ok()
            .and_then(|g| g.clone())
    }

    async fn scan(
        &self,
        artifact: &Artifact,
        _metadata: Option<&ArtifactMetadata>,
        content: &Bytes,
    ) -> Result<ScanOutput> {
        debug_assert!(
            Self::is_container_image(artifact),
            "ImageScanner::scan called on a non-container artifact; the orchestrator must gate on is_applicable first"
        );

        // Legacy keyless path retained for the trait contract / direct
        // callers. A malformed path is a real error, not "not applicable":
        // surface it so the operator sees a failed scan rather than a silent
        // completed-with-zero-findings row (#994).
        let target = match build_adapter_scan_artifact(&artifact.path, None, content) {
            Some(t) => t,
            None => {
                return Err(AppError::Internal(format!(
                    "Could not extract image reference from artifact path: {}",
                    artifact.path
                )));
            }
        };
        let mime = Self::manifest_mime_type(&artifact.content_type);
        // Legacy keyless path: no owning repository key, so pull anonymously.
        self.run_image_scan(&target, &mime, None).await
    }

    /// Repository-aware scan hook used by the orchestrator. Prepends the owning
    /// repository key so the adapter pulls Artifact Keeper's own stored
    /// artifact rather than a same-named public image (mirrors
    /// `GrypeScanner::scan_target`).
    async fn scan_target(
        &self,
        target: &ScanTarget<'_>,
        _metadata: Option<&ArtifactMetadata>,
        content: &Bytes,
    ) -> Result<ScanOutput> {
        debug_assert!(
            Self::is_container_image(target.artifact),
            "ImageScanner::scan_target called on a non-container artifact; the orchestrator must gate on is_applicable first"
        );
        let scan_target = build_adapter_scan_artifact(
            &target.artifact.path,
            Some(target.repository_key),
            content,
        )
        .ok_or_else(|| {
            AppError::Internal(format!(
                "Could not extract image reference from artifact path: {}",
                target.artifact.path
            ))
        })?;
        let mime = Self::manifest_mime_type(&target.artifact.content_type);
        // Repository-aware path: mint a pull token scoped to this repository.
        self.run_image_scan(&scan_target, &mime, Some(target.repository_key))
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::security::Severity;

    /// Build an Artifact fixture for scanner tests. Most fields are not
    /// load-bearing for the scanner — the scanner only branches on `path` and
    /// `content_type` — so we collapse the boilerplate here.
    fn make_test_artifact(path: &str, content_type: &str) -> Artifact {
        Artifact {
            id: uuid::Uuid::new_v4(),
            repository_id: uuid::Uuid::new_v4(),
            path: path.to_string(),
            name: "test".to_string(),
            version: None,
            size_bytes: 1000,
            checksum_sha256: "abc123".to_string(),
            checksum_md5: None,
            checksum_sha1: None,
            content_type: content_type.to_string(),
            storage_key: "test".to_string(),
            is_deleted: false,
            uploaded_by: None,
            quarantine_status: None,
            quarantine_until: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    use crate::services::scanner_service::test_helpers::{make_scanner_auth, make_scanner_user};

    #[test]
    fn test_registry_authorization_none_without_minter() {
        // Default (anonymous) wiring: no token minter -> no Authorization,
        // preserving the public-only pull behavior.
        let scanner = ImageScanner::new("http://trivy:8090".to_string());
        assert!(scanner.registry_authorization("docker-private-a").is_none());
    }

    #[tokio::test]
    async fn test_registry_authorization_mints_repo_scoped_bearer() {
        let auth = make_scanner_auth();
        let scanner = ImageScanner::new("http://trivy:8090".to_string()).with_token_minter(
            auth.clone(),
            make_scanner_user(),
            300,
        );

        let header = scanner
            .registry_authorization("docker-private-a")
            .expect("minter wired -> Authorization present");
        let token = header
            .strip_prefix("Bearer ")
            .expect("registry.authorization must be a Bearer credential");

        // The minted token must be pinned to exactly the scanned repository so
        // the OCI pull gate (enforce_scan_pull_scope) admits this repo only.
        let claims = auth
            .validate_access_token(token)
            .expect("minted scan token must validate");
        assert_eq!(claims.scan_pull_repo.as_deref(), Some("docker-private-a"));
        assert!(!claims.is_admin);
    }

    #[test]
    fn test_is_container_image() {
        let mut artifact = make_test_artifact(
            "v2/myapp/manifests/latest",
            "application/vnd.oci.image.manifest.v1+json",
        );
        assert!(ImageScanner::is_container_image(&artifact));

        artifact.content_type = "application/json".to_string();
        artifact.path = "some/other/path".to_string();
        assert!(!ImageScanner::is_container_image(&artifact));
    }

    // -----------------------------------------------------------------------
    // build_adapter_scan_artifact: ref + tag-vs-digest resolution (pure fn)
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_adapter_artifact_keyless_tag() {
        let a = build_adapter_scan_artifact("v2/myapp/manifests/v1.0.0", None, &[])
            .expect("valid OCI manifest path");
        assert_eq!(a.repository, "myapp");
        assert_eq!(a.reference, AdapterReference::Tag("v1.0.0".to_string()));
    }

    #[test]
    fn test_build_adapter_artifact_prepends_repository_key() {
        let a = build_adapter_scan_artifact(
            "v2/library/nginx/manifests/latest",
            Some("docker-local"),
            &[],
        )
        .expect("valid OCI manifest path");
        assert_eq!(a.repository, "docker-local/library/nginx");
        assert_eq!(a.reference, AdapterReference::Tag("latest".to_string()));
    }

    /// Regression for #1483: a digest-pinned manifest (written by every
    /// `docker buildx push`) must be addressed by DIGEST, never as a tag. The
    /// `@`-separator decision lives in `is_oci_digest_reference`; here we prove
    /// the adapter target carries it as `AdapterReference::Digest`.
    #[test]
    fn test_build_adapter_artifact_digest_uses_digest_reference() {
        let digest = "sha256:cf4501fe4ed427dfc7c81f68be661271ffd164bb2e774caf0e3aa8eac775eb6b";
        let a = build_adapter_scan_artifact(
            &format!("v2/org/app/manifests/{}", digest),
            Some("oci-prod"),
            &[],
        )
        .expect("valid digest-pinned manifest path");
        assert_eq!(a.repository, "oci-prod/org/app");
        assert_eq!(a.reference, AdapterReference::Digest(digest.to_string()));
    }

    /// #1971: a multi-arch image index body resolves to a concrete child
    /// platform digest, addressed by digest.
    #[test]
    fn test_build_adapter_artifact_resolves_index_to_child_digest() {
        let child = match crate::services::scanner_service::runner_arch() {
            "arm64" => "sha256:2222222222222222222222222222222222222222222222222222222222222222",
            _ => "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        };
        let index_body = r#"{"manifests":[
             {"digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","platform":{"os":"linux","architecture":"amd64"}},
             {"digest":"sha256:2222222222222222222222222222222222222222222222222222222222222222","platform":{"os":"linux","architecture":"arm64"}}
           ]}"#;
        let a = build_adapter_scan_artifact(
            "v2/library/nginx/manifests/latest",
            Some("docker-local"),
            index_body.as_bytes(),
        )
        .expect("valid OCI index path");
        assert_eq!(a.repository, "docker-local/library/nginx");
        assert_eq!(a.reference, AdapterReference::Digest(child.to_string()));
    }

    #[test]
    fn test_build_adapter_artifact_invalid_path() {
        assert_eq!(
            build_adapter_scan_artifact("some/random/path", Some("k"), &[]),
            None
        );
    }

    // -----------------------------------------------------------------------
    // Harbor report -> TrivyReport mapping (pure fn)
    // -----------------------------------------------------------------------

    #[test]
    fn test_harbor_report_to_trivy_maps_fields_and_severity() {
        let report = HarborScanReport {
            scanner: Some(HarborScanner {
                name: Some("Trivy".to_string()),
                version: Some("0.71.2".to_string()),
            }),
            vulnerabilities: vec![
                HarborVulnerability {
                    id: "CVE-2021-36159".to_string(),
                    package: "apk-tools".to_string(),
                    version: "2.12.5-r1".to_string(),
                    fix_version: Some("2.12.6-r0".to_string()),
                    severity: "Critical".to_string(),
                    description: Some("heap overflow".to_string()),
                    links: Some(vec!["https://avd.aquasec.com/x".to_string()]),
                },
                HarborVulnerability {
                    id: "CVE-2026-0002".to_string(),
                    package: "zlib".to_string(),
                    version: "1.0".to_string(),
                    fix_version: None,
                    severity: "Negligible".to_string(),
                    description: None,
                    links: None,
                },
                HarborVulnerability {
                    id: "CVE-2026-0003".to_string(),
                    package: "musl".to_string(),
                    version: "1.0".to_string(),
                    fix_version: None,
                    severity: "Unknown".to_string(),
                    description: None,
                    links: None,
                },
            ],
        };

        let findings = ImageScanner::convert_findings(&harbor_report_to_trivy(&report, "img:tag"));
        assert_eq!(findings.len(), 3);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(findings[0].cve_id, Some("CVE-2021-36159".to_string()));
        assert_eq!(findings[0].source, Some("trivy".to_string()));
        assert_eq!(findings[0].fixed_version, Some("2.12.6-r0".to_string()));
        // Negligible -> Low
        assert_eq!(findings[1].severity, Severity::Low);
        // Unknown -> Info (from_str_loose returns None -> default Info)
        assert_eq!(findings[2].severity, Severity::Info);
        // No title -> synthesized "<id> in <pkg>"
        assert!(findings[2].title.contains("CVE-2026-0003"));
    }

    #[test]
    fn test_normalize_harbor_severity() {
        assert_eq!(normalize_harbor_severity("Negligible"), "Low");
        assert_eq!(normalize_harbor_severity("Critical"), "Critical");
        assert_eq!(normalize_harbor_severity("Unknown"), "Unknown");
        assert_eq!(normalize_harbor_severity(""), "Unknown");
    }

    // -----------------------------------------------------------------------
    // Retained TrivyReport conversion tests (shape still used by fs/incus)
    // -----------------------------------------------------------------------

    #[test]
    fn test_convert_findings() {
        let report = TrivyReport {
            results: vec![TrivyResult {
                target: "alpine:3.14 (alpine 3.14.2)".to_string(),
                class: "os-pkgs".to_string(),
                result_type: "alpine".to_string(),
                vulnerabilities: Some(vec![TrivyVulnerability {
                    vulnerability_id: "CVE-2021-36159".to_string(),
                    pkg_name: "apk-tools".to_string(),
                    installed_version: "2.12.5-r1".to_string(),
                    fixed_version: Some("2.12.6-r0".to_string()),
                    severity: "CRITICAL".to_string(),
                    title: Some("apk-tools: heap overflow in libfetch".to_string()),
                    description: Some("A vulnerability was found in apk-tools".to_string()),
                    primary_url: Some("https://avd.aquasec.com/nvd/cve-2021-36159".to_string()),
                }]),
                packages: None,
            }],
        };

        let findings = ImageScanner::convert_findings(&report);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(findings[0].source, Some("trivy".to_string()));
    }

    #[test]
    fn test_convert_findings_empty() {
        let report = TrivyReport {
            results: vec![TrivyResult {
                target: "alpine:3.18".to_string(),
                class: "os-pkgs".to_string(),
                result_type: "alpine".to_string(),
                vulnerabilities: None,
                packages: None,
            }],
        };
        assert_eq!(ImageScanner::convert_findings(&report).len(), 0);
    }

    /// a Helm-OCI chart has the image manifest mediaType (so
    /// `is_container_image` is true) but a Helm config mediaType. With the
    /// manifest body threaded through `ScanTarget`, ImageScanner must classify
    /// it not-applicable so Trivy never produces a false clean scan.
    #[test]
    fn test_is_applicable_for_target_rejects_helm_oci_chart() {
        use crate::services::scanner_service::Scanner;
        let scanner = ImageScanner::new("http://trivy:8080".to_string());
        let artifact = make_test_artifact(
            "v2/demochart/manifests/0.1.0",
            "application/vnd.oci.image.manifest.v1+json",
        );
        let helm_body: &[u8] = br#"{"schemaVersion":2,
          "config":{"mediaType":"application/vnd.cncf.helm.config.v1+json","digest":"sha256:cfg","size":7},
          "layers":[{"mediaType":"application/vnd.cncf.helm.chart.content.v1.tar+gzip","digest":"sha256:l1","size":9}]}"#;
        let target = ScanTarget {
            artifact: &artifact,
            repository_key: "helm-local",
            repository_type: "local",
            db: None,
            storage: None,
            manifest_body: Some(helm_body),
        };
        assert!(!scanner.is_applicable_for_target(&target));
    }

    /// a real OCI image with a container config stays applicable.
    #[test]
    fn test_is_applicable_for_target_accepts_real_oci_image() {
        use crate::services::scanner_service::Scanner;
        let scanner = ImageScanner::new("http://trivy:8080".to_string());
        let artifact = make_test_artifact(
            "v2/library/nginx/manifests/latest",
            "application/vnd.oci.image.manifest.v1+json",
        );
        let image_body: &[u8] = br#"{"schemaVersion":2,
          "config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:cfg","size":7},
          "layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"sha256:l1","size":9}]}"#;
        let target = ScanTarget {
            artifact: &artifact,
            repository_key: "docker-local",
            repository_type: "local",
            db: None,
            storage: None,
            manifest_body: Some(image_body),
        };
        assert!(scanner.is_applicable_for_target(&target));
    }

    /// Regression guard: a bodyless target (legacy/path-only) keeps the
    /// existing applicable decision so #1971 fail-open is preserved.
    #[test]
    fn test_is_applicable_for_target_bodyless_stays_applicable() {
        use crate::services::scanner_service::Scanner;
        let scanner = ImageScanner::new("http://trivy:8080".to_string());
        let artifact = make_test_artifact(
            "v2/library/nginx/manifests/latest",
            "application/vnd.oci.image.manifest.v1+json",
        );
        let target = ScanTarget {
            artifact: &artifact,
            repository_key: "docker-local",
            repository_type: "local",
            db: None,
            storage: None,
            manifest_body: None,
        };
        assert!(scanner.is_applicable_for_target(&target));
    }

    #[test]
    fn test_trivy_report_deserialization() {
        let json = r#"{
            "Results": [{
                "Target": "alpine:3.14",
                "Class": "os-pkgs",
                "Type": "alpine",
                "Vulnerabilities": [{
                    "VulnerabilityID": "CVE-2021-36159",
                    "PkgName": "apk-tools",
                    "InstalledVersion": "2.12.5-r1",
                    "FixedVersion": "2.12.6-r0",
                    "Severity": "CRITICAL",
                    "Title": "heap overflow",
                    "Description": "A vulnerability",
                    "PrimaryURL": "https://example.com"
                }]
            }]
        }"#;
        let report: TrivyReport = serde_json::from_str(json).unwrap();
        assert_eq!(report.results.len(), 1);
        assert_eq!(report.results[0].vulnerabilities.as_ref().unwrap().len(), 1);
    }

    #[test]
    fn test_is_applicable_rejects_non_container_artifact() {
        use crate::services::scanner_service::Scanner;
        let scanner = ImageScanner::new("http://127.0.0.1:1".to_string());
        let artifact = make_test_artifact("pypi/pkg/1.0.0/pkg-1.0.0.tar.gz", "application/gzip");
        assert!(
            !Scanner::is_applicable(&scanner, &artifact),
            "ImageScanner must yield to a filesystem scanner for non-container artifacts (#961, #994)"
        );
    }

    // -----------------------------------------------------------------------
    // Adapter scan flow tests (the #2088 regression surface)
    // -----------------------------------------------------------------------

    /// REPLACES the #2059 `test_scan_with_trivy_http_fallback_parses_report`
    /// wiremock test.
    ///
    /// BLIND SPOT of the removed test: it mocked the trivy-server Twirp
    /// `/twirp/.../Scan` endpoint and asserted only that a hand-fed report
    /// PARSED. It never checked that the call actually scans the image — and in
    /// production the Twirp `Scan` endpoint, invoked with only `{"target":...}`,
    /// returns an EMPTY result (it requires the client to walk + PutBlob every
    /// layer first). That empty result was mapped to "completed, 0 findings": a
    /// false-clean (#2088). The tests below assert the two properties that
    /// actually matter: a real report yields NON-EMPTY findings, and EVERY
    /// adapter error path FAILS the scan (never Ok-empty).
    /// A standard OCI image artifact fixture for the adapter flow tests.
    fn oci_image_artifact() -> Artifact {
        make_test_artifact(
            "v2/myapp/manifests/latest",
            "application/vnd.oci.image.manifest.v1+json",
        )
    }

    /// Mount the readiness gate (200) and scan-submit (202 {id}) mocks shared
    /// by every adapter-flow test, so each test only declares its own
    /// report-endpoint behavior. Extracted to keep the tests DRY (jscpd).
    #[cfg(test)]
    async fn mount_ready_and_submit(server: &wiremock::MockServer, scan_id: &str) {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};

        Mock::given(method("GET"))
            .and(path("/probe/ready"))
            .respond_with(ResponseTemplate::new(200))
            .mount(server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/v1/scan"))
            .respond_with(
                ResponseTemplate::new(202).set_body_json(serde_json::json!({ "id": scan_id })),
            )
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn test_adapter_scan_returns_findings() {
        use wiremock::matchers::{method, path_regex};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        mount_ready_and_submit(&server, "scan-abc").await;
        let report = serde_json::json!({
            "scanner": {"name": "Trivy", "version": "0.71.2"},
            "vulnerabilities": [{
                "id": "CVE-2026-0001",
                "package": "openssl",
                "version": "3.1.0",
                "fix_version": "3.1.1",
                "severity": "High",
                "description": "test vuln",
                "links": ["https://example.test/cve"]
            }]
        });
        Mock::given(method("GET"))
            .and(path_regex(r"^/api/v1/scan/.+/report$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(report))
            .mount(&server)
            .await;

        let scanner = ImageScanner::new(server.uri());
        let out = scanner
            .scan(&oci_image_artifact(), None, &Bytes::new())
            .await
            .expect("adapter scan should complete");

        assert_eq!(out.findings.len(), 1, "real report must yield findings");
        assert_eq!(out.findings[0].cve_id, Some("CVE-2026-0001".to_string()));
        assert_eq!(out.findings[0].severity, Severity::High);
        assert_eq!(out.findings[0].source, Some("trivy".to_string()));
        assert_eq!(scanner.version().await, Some("trivy-0.71.2".to_string()));
    }

    /// Mirror of #888 `test_scan_fails_when_trivy_unreachable`: an unreachable
    /// adapter must fail the scan, never silently complete with zero findings.
    #[tokio::test]
    async fn test_adapter_unreachable_fails_scan() {
        let scanner = ImageScanner::new("http://127.0.0.1:1".to_string());
        let result = scanner
            .scan(&oci_image_artifact(), None, &Bytes::new())
            .await;
        assert!(
            result.is_err(),
            "scan() must Err when the adapter is unreachable, not Ok(empty)"
        );
        assert!(matches!(result.unwrap_err(), AppError::BadGateway(_)));
    }

    /// A non-2xx submit response must fail the scan.
    #[tokio::test]
    async fn test_adapter_non_2xx_fails_scan() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/probe/ready"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/v1/scan"))
            .respond_with(ResponseTemplate::new(500).set_body_string("boom"))
            .mount(&server)
            .await;

        let scanner = ImageScanner::new(server.uri());
        let result = scanner
            .scan(&oci_image_artifact(), None, &Bytes::new())
            .await;
        assert!(
            matches!(result, Err(AppError::BadGateway(_))),
            "adapter 500 must fail the scan with BadGateway, got {:?}",
            result
        );
    }

    /// A report that never becomes ready must FAIL after the bounded budget,
    /// not return Ok(empty). We trip the deadline immediately by sending a
    /// Refresh-After larger than the remaining budget on the first pending poll.
    #[tokio::test]
    async fn test_adapter_report_pending_then_timeout_fails() {
        use wiremock::matchers::{method, path_regex};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        mount_ready_and_submit(&server, "scan-pending").await;
        // Always pending, with a Refresh-After far beyond the poll budget so
        // the deadline check trips on the first poll (keeps the test fast).
        Mock::given(method("GET"))
            .and(path_regex(r"^/api/v1/scan/.+/report$"))
            .respond_with(ResponseTemplate::new(302).insert_header("Refresh-After", "100000"))
            .mount(&server)
            .await;

        let scanner = ImageScanner::new(server.uri());
        let result = scanner
            .scan(&oci_image_artifact(), None, &Bytes::new())
            .await;
        assert!(
            matches!(result, Err(AppError::BadGateway(_))),
            "a never-ready report must fail the scan (NOT Ok-empty), got {:?}",
            result
        );
    }

    /// A 404 report response is a TERMINAL error, not "pending": our in-house
    /// adapter (#2092) returns 404 for a genuinely unknown/expired scan id. It
    /// must fail the scan immediately (fail-fast) rather than polling until the
    /// ~280s budget is exhausted and tying up a worker. We wrap the call in a
    /// short timeout to prove it returns promptly rather than waiting out the
    /// poll budget.
    #[tokio::test]
    async fn test_adapter_report_404_fails_fast() {
        use wiremock::matchers::{method, path_regex};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        mount_ready_and_submit(&server, "scan-unknown").await;
        // Adapter reports 404 for an unknown id — terminal, not pending.
        Mock::given(method("GET"))
            .and(path_regex(r"^/api/v1/scan/.+/report$"))
            .respond_with(ResponseTemplate::new(404).set_body_string("unknown scan id"))
            .mount(&server)
            .await;

        let scanner = ImageScanner::new(server.uri());
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            scanner.scan(&oci_image_artifact(), None, &Bytes::new()),
        )
        .await
        .expect("404 report must fail fast, not poll out the ~280s budget");
        assert!(
            matches!(result, Err(AppError::BadGateway(_))),
            "a 404 report (unknown scan id) must fail the scan immediately, got {:?}",
            result
        );
    }

    /// An empty scan id from the submit endpoint must fail the scan up front:
    /// an empty id yields a bogus `/scan//report` poll URL that never resolves.
    #[tokio::test]
    async fn test_adapter_empty_scan_id_fails_scan() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/probe/ready"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/v1/scan"))
            .respond_with(ResponseTemplate::new(202).set_body_json(serde_json::json!({ "id": "" })))
            .mount(&server)
            .await;

        let scanner = ImageScanner::new(server.uri());
        let result = scanner
            .scan(&oci_image_artifact(), None, &Bytes::new())
            .await;
        assert!(
            matches!(result, Err(AppError::BadGateway(_))),
            "an empty scan id must fail the scan with BadGateway, got {:?}",
            result
        );
    }

    /// `scan_target` builds the repository-qualified target. With an
    /// unreachable adapter the scan must fail (never a silent zero-finding
    /// completion, cf. #888).
    #[tokio::test]
    async fn test_scan_target_fails_when_adapter_unreachable() {
        let scanner = ImageScanner::new("http://127.0.0.1:1".to_string());
        let artifact = make_test_artifact(
            "v2/myapp/manifests/latest",
            "application/vnd.oci.image.manifest.v1+json",
        );
        let target = ScanTarget {
            artifact: &artifact,
            repository_key: "docker-local",
            repository_type: "local",
            db: None,
            storage: None,
            manifest_body: None,
        };
        let result = scanner.scan_target(&target, None, &Bytes::new()).await;
        assert!(
            matches!(result, Err(AppError::BadGateway(_))),
            "scan_target must fail-closed when the adapter is unreachable"
        );
    }

    /// The Harbor scan request carries the `registry.authorization` bearer when
    /// a token minter is wired, and the repository/reference shape is correct.
    /// Proves the token is attached (private-repo pull support) and exercises
    /// the request builder. Uses a lazily-connected pool so no DB is needed.
    #[test]
    fn test_build_scan_request_shape_and_authorization() {
        let artifact = AdapterScanArtifact {
            repository: "docker-local/library/nginx".to_string(),
            reference: AdapterReference::Tag("latest".to_string()),
        };
        let body = ImageScanner::build_scan_request(
            "http://localhost:8080",
            Some("Bearer test-jwt"),
            &artifact,
            "application/vnd.docker.distribution.manifest.v2+json",
        );
        assert_eq!(body["registry"]["url"], "http://localhost:8080");
        assert_eq!(body["registry"]["authorization"], "Bearer test-jwt");
        assert_eq!(body["artifact"]["repository"], "docker-local/library/nginx");
        assert_eq!(body["artifact"]["tag"], "latest");
        assert!(body["artifact"].get("digest").is_none());

        // Digest target uses `digest`, not `tag`.
        let dref = AdapterScanArtifact {
            repository: "oci-prod/org/app".to_string(),
            reference: AdapterReference::Digest("sha256:deadbeef".to_string()),
        };
        let dbody = ImageScanner::build_scan_request(
            "http://localhost:8080",
            None,
            &dref,
            "application/vnd.oci.image.manifest.v1+json",
        );
        assert_eq!(dbody["artifact"]["digest"], "sha256:deadbeef");
        assert!(dbody["artifact"].get("tag").is_none());
        // No minter -> no authorization field.
        assert!(dbody["registry"].get("authorization").is_none());
    }
}
