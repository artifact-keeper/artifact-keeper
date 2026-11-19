//! OpenSCAP compliance scanner.
//!
//! Unpacks a stored container image's root filesystem into the shared scan
//! workspace ([`crate::services::oci_rootfs`]), asks the OpenSCAP HTTP wrapper
//! sidecar to evaluate THAT tree offline (`OSCAP_PROBE_ROOT`), and converts
//! the failed rules into policy findings.
//!
//! What a scan evaluates (#6000): XCCDF profiles describe an operating
//! system's configuration, so the target is the image's unpacked root
//! filesystem. An RPM or DEB package is not a system and is not applicable;
//! neither is an OCI artifact that is not a runnable image (Helm chart,
//! signature, SBOM). Before #6000 the scanner wrote the raw artifact bytes
//! into the workspace and every scan evaluated the sidecar's own filesystem.
//!
//! An image that cannot be evaluated meaningfully (layers not stored here, no
//! `os-release`, no shipped datastream for its OS, no applicable rule, or a
//! sidecar that cannot root its probes in the tree) is recorded
//! `not_applicable` with the reason, through
//! [`AppError::ScannerEngineUnavailable`]. It is never recorded as a pass.

use crate::services::http_client::Client;
use async_trait::async_trait;
use bytes::Bytes;
use serde::Deserialize;
use std::path::Path;
use std::time::Duration;
use tracing::{info, warn};

use crate::error::{AppError, Result};
use crate::models::artifact::{Artifact, ArtifactMetadata};
use crate::models::security::{RawFinding, Severity};
use crate::services::oci_rootfs::{NotUnpackable, OciRootfsExtractor};
use crate::services::scanner_service::{
    cached_cli_version, fail_scan, is_oci_image_artifact, oci_target_is_scannable_image,
    ScanOutput, ScanTarget, ScanWorkspace, Scanner, VersionCache,
};

/// The profile evaluated when `OPENSCAP_PROFILE` is unset: CIS Level 1 -
/// Server, a generic baseline present in every datastream the openscap image
/// ships (`ssg-rhel9-ds.xml`, `ssg-cs9-ds.xml`). The previous default,
/// `content_profile_standard`, is in neither, and the wrapper silently ran
/// `profiles[0]` (`anssi_bp28_enhanced`) instead (#6000). Kept in step with
/// `DEFAULT_PROFILE` in `scripts/openscap-wrapper.py`.
pub const DEFAULT_OPENSCAP_PROFILE: &str = "xccdf_org.ssgproject.content_profile_cis_server_l1";

/// Response shape from the OpenSCAP wrapper sidecar's `/health` endpoint.
/// Used by `Scanner::version()` to capture the running `oscap` binary
/// version for `scan_results.scanner_version`.
#[derive(Debug, Deserialize)]
struct OpenScapHealth {
    #[serde(default)]
    version: Option<String>,
}

// ---------------------------------------------------------------------------
// OpenSCAP wrapper JSON response structures
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
pub struct OpenScapResponse {
    /// `completed` or `not_applicable`. Absent from a wrapper that predates
    /// #6000, which evaluated its own filesystem.
    #[serde(default)]
    pub status: Option<String>,
    /// Why the target could not be evaluated (`not_applicable`).
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub findings: Vec<OpenScapFinding>,
    /// The profile the wrapper actually evaluated.
    #[serde(default)]
    pub profile: Option<String>,
    /// The datastream label the wrapper chose for the target's OS.
    #[serde(default)]
    pub content: Option<String>,
    /// `ID VERSION_ID` from the target's os-release.
    #[serde(default)]
    pub target_os: Option<String>,
    /// Rules evaluated against the target (not notapplicable/notselected).
    #[serde(default)]
    pub evaluated: Option<u64>,
    /// Ownership-dependent rules reported as not evaluated: the tree is
    /// unpacked without root, so file ownership is not the image's.
    #[serde(default)]
    pub not_evaluated: Vec<String>,
    #[serde(default)]
    pub error: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct OpenScapFinding {
    pub rule_id: String,
    pub result: String,
    pub severity: String,
    pub title: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub references: Vec<String>,
}

// ---------------------------------------------------------------------------
// Scanner implementation
// ---------------------------------------------------------------------------

pub struct OpenScapScanner {
    http: Client,
    openscap_url: String,
    profile: String,
    scan_workspace: String,
    /// Lazily-probed version string from the wrapper sidecar's `/health`
    /// endpoint, e.g. `openscap-1.4.0`. Successful probes are cached for an
    /// hour; failed probes (sidecar starting up, transient network blip)
    /// expire after 60s so the field starts populating once the sidecar is
    /// reachable.
    cached_version: VersionCache,
}

/// Map a workspace-creation IO error to an actionable [`AppError`].
///
/// The default deployment shares a single `scan_workspace` named volume
/// between the backend (read-write) and the OpenSCAP/Trivy sidecars
/// (read-only). On hosts where the container runtime does not propagate the
/// image mountpoint's ownership to a freshly-created named volume — notably
/// Podman + SELinux on Fedora (issue #1563) — the volume root ends up owned
/// by `root` and mode `0755`, so the non-root backend (UID 1001) cannot
/// create the per-scan subdirectory and `create_dir_all` fails with EACCES
/// (`os error 13`).
///
/// A bare "Permission denied" gives operators nothing to act on, so for the
/// permission-denied case we point them at the volume ownership fix. This is a
/// pure function so the message-building logic is unit-testable without
/// depending on filesystem permission state.
fn workspace_create_error(base: &str, err: &std::io::Error) -> AppError {
    if err.kind() == std::io::ErrorKind::PermissionDenied {
        AppError::Internal(format!(
            "Failed to create scan workspace under {base}: {err}. \
             The shared scan-workspace volume is not writable by the backend \
             (UID 1001). Ensure the volume is owned by 1001:0 (e.g. run the \
             scan-workspace-init step in the compose file, or `chown -R 1001:0` \
             the volume) — this is common on Podman/SELinux hosts where named \
             volumes are not chowned to the image's mountpoint owner."
        ))
    } else {
        AppError::Internal(format!(
            "Failed to create scan workspace under {base}: {err}"
        ))
    }
}

impl OpenScapScanner {
    pub fn new(openscap_url: String, profile: String, scan_workspace: String) -> Self {
        let http = crate::services::http_client::internal_service_client_builder()
            .timeout(Duration::from_secs(600))
            .build()
            .expect("failed to build HTTP client");

        Self {
            http,
            openscap_url,
            profile,
            scan_workspace,
            cached_version: VersionCache::new(),
        }
    }

    /// Probe the OpenSCAP wrapper's `/health` endpoint to capture the
    /// running `oscap` binary version. Returns `None` on any error so the
    /// scan still completes; the version is metadata, not a scan result.
    async fn probe_version(&self) -> Option<String> {
        let url = format!("{}/health", self.openscap_url);
        let resp = self
            .http
            .get(&url)
            .timeout(Duration::from_secs(5))
            .send()
            .await
            .ok()?;
        if !resp.status().is_success() {
            return None;
        }
        let health: OpenScapHealth = resp.json().await.ok()?;
        let raw = health.version?;
        // `oscap --version` first line is e.g. `OpenSCAP command line tool
        // (oscap) 1.4.0`. Capture just the version token for compactness.
        let token = raw.split_whitespace().last()?.trim();
        if token.is_empty() {
            None
        } else {
            Some(format!("openscap-{}", token))
        }
    }

    /// Returns true if this scanner applies to the given artifact: an OCI or
    /// Docker image manifest (#6000). RPM and DEB packages are not operating
    /// system root filesystems, so a compliance profile has nothing to
    /// evaluate in them; they used to be applicable and were "scanned" by
    /// evaluating the sidecar instead.
    fn is_applicable(artifact: &Artifact) -> bool {
        is_oci_image_artifact(artifact)
    }

    /// Ask the wrapper to evaluate the unpacked tree at `root`.
    async fn call_openscap(&self, root: &Path) -> Result<OpenScapResponse> {
        let root_str = root.to_string_lossy().to_string();
        let scan_request = serde_json::json!({
            "path": root_str,
            "profile": self.profile,
        });

        let resp = self
            .http
            .post(format!("{}/scan", self.openscap_url))
            .json(&scan_request)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("OpenSCAP request failed: {}", e)))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            // Include the workspace path in the error so operators can match
            // it against the sidecar's OPENSCAP_ALLOWED_SCAN_DIRS allowlist
            // (issue #1466). Without this, debugging the "scan path not
            // found or not allowed" 400 requires turning on wrapper debug
            // logs or guessing which path was sent. A 422 is an unknown
            // profile (#6000); its body names the profiles that exist.
            return Err(AppError::Internal(format!(
                "OpenSCAP scan failed (HTTP {}) for path {}: {}",
                status, root_str, body
            )));
        }

        resp.json::<OpenScapResponse>()
            .await
            .map_err(|e| AppError::Internal(format!("Failed to parse OpenSCAP response: {}", e)))
    }

    /// Turn a wrapper response into findings, or into the error the
    /// orchestrator records (#6000).
    ///
    /// * an `error` field fails the scan. It used to be logged and the scan
    ///   completed with zero findings: a wrapper error read as a clean pass;
    /// * `not_applicable` records the scan `not_applicable` with the reason;
    /// * `completed` must name the profile that was requested, so a wrapper
    ///   that substitutes another profile cannot pass its results off as the
    ///   configured one;
    /// * no status at all is a wrapper from before #6000, which evaluated its
    ///   own filesystem; its findings are not about the artifact.
    fn interpret_response(response: &OpenScapResponse, requested: &str) -> Result<Vec<RawFinding>> {
        if let Some(err) = &response.error {
            return Err(AppError::Internal(format!(
                "OpenSCAP wrapper reported an error: {err}"
            )));
        }
        match response.status.as_deref() {
            Some("not_applicable") => Err(AppError::ScannerEngineUnavailable(format!(
                "OpenSCAP: {}",
                response
                    .reason
                    .as_deref()
                    .unwrap_or("the image cannot be evaluated")
            ))),
            Some("completed") => {
                if response.profile.as_deref() != Some(requested) {
                    return Err(AppError::Internal(format!(
                        "OpenSCAP evaluated profile {} instead of the configured {requested}",
                        response.profile.as_deref().unwrap_or("(none)")
                    )));
                }
                Ok(Self::convert_findings(response))
            }
            other => Err(AppError::Internal(format!(
                "OpenSCAP sidecar returned scan status {other:?}: it predates the fix for \
                 #6000 and evaluates its own filesystem, not the image. Run the openscap \
                 image from the same release as the backend."
            ))),
        }
    }

    /// Evaluate the unpacked image root at `root` and return its findings.
    async fn evaluate_root(&self, artifact: &Artifact, root: &Path) -> Result<Vec<RawFinding>> {
        let response = self.call_openscap(root).await?;
        let findings = Self::interpret_response(&response, &self.profile)?;
        info!(
            "OpenSCAP scan complete for {} ({} on {}, profile {}): {} rules evaluated, \
             {} compliance issues, {} ownership rules not evaluated",
            artifact.name,
            response.content.as_deref().unwrap_or("?"),
            response.target_os.as_deref().unwrap_or("?"),
            self.profile,
            response.evaluated.unwrap_or(0),
            findings.len(),
            response.not_evaluated.len(),
        );
        Ok(findings)
    }

    fn convert_findings(response: &OpenScapResponse) -> Vec<RawFinding> {
        response
            .findings
            .iter()
            .filter(|f| matches!(f.result.as_str(), "fail" | "error" | "unknown"))
            .map(|f| {
                // #3294: shared classifier, replacing a private match that
                // recognised only `high | medium | moderate | low` and sent
                // everything else to `Severity::Info`. It had no `critical`
                // arm, so content emitting `critical` had its MOST severe
                // result filed as the least severe one — the fail-open this
                // patch closes. XCCDF 1.2 (NISTIR 7275r4 §6.4.4.2) defines the
                // Rule `severity` attribute as `unknown | info | low | medium
                // | high`, so `critical` is non-standard and reaches this only
                // from content or a wrapper that emits it; the volume is
                // therefore near zero, which is what makes the change safe in
                // a patch.
                //
                // As of #3306 an unrecognised token — `unknown` included,
                // XCCDF's default rule severity and the high-volume case on a
                // typical profile — fails closed at `High` instead of landing
                // at the `Info` floor where no severity-aware gate saw it.
                let severity = Severity::from_scanner_token(&f.severity);

                let source_url = f.references.first().cloned();

                RawFinding {
                    severity,
                    title: f.title.clone(),
                    description: f.description.clone(),
                    cve_id: None,
                    affected_component: Some(f.rule_id.clone()),
                    affected_version: None,
                    fixed_version: None,
                    source: Some("openscap".to_string()),
                    source_url,
                    // #3013: a failed XCCDF rule is a configuration /
                    // compliance violation, not a known weakness.
                    finding_class: crate::models::security::FindingClass::Policy,
                }
            })
            .collect()
    }
}

#[async_trait]
impl Scanner for OpenScapScanner {
    fn name(&self) -> &str {
        "openscap"
    }

    fn scan_type(&self) -> &str {
        "openscap"
    }

    /// Surface the inherent applicability check through the trait so the
    /// orchestrator can gate on it without creating a `scan_results` row
    /// (issues #961, #994).
    fn is_applicable(&self, artifact: &Artifact) -> bool {
        Self::is_applicable(artifact)
    }

    /// With the manifest body in hand, also require a runnable image, so a
    /// Helm chart, signature or SBOM stored as an OCI artifact is recorded
    /// not applicable instead of failing to unpack (#1971's gate).
    fn is_applicable_for_target(&self, target: &ScanTarget<'_>) -> bool {
        Self::is_applicable(target.artifact) && oci_target_is_scannable_image(target)
    }

    /// Probe the wrapper sidecar's `/health` endpoint once and cache the
    /// `oscap` version string. Returns `None` if the wrapper is unreachable
    /// or its response cannot be parsed.
    async fn version(&self) -> Option<String> {
        cached_cli_version(&self.cached_version, || async {
            self.probe_version().await
        })
        .await
    }

    /// The image's layers are read from repository storage, which only the
    /// target-aware entry point carries. A caller without it cannot unpack
    /// the image, so the scan is not applicable rather than a pass.
    async fn scan(
        &self,
        _artifact: &Artifact,
        _metadata: Option<&ArtifactMetadata>,
        _content: &Bytes,
    ) -> Result<ScanOutput> {
        Err(NotUnpackable::NoStorage.into())
    }

    async fn scan_target(
        &self,
        target: &ScanTarget<'_>,
        _metadata: Option<&ArtifactMetadata>,
        content: &Bytes,
    ) -> Result<ScanOutput> {
        let artifact = target.artifact;
        debug_assert!(
            Self::is_applicable(artifact),
            "OpenScapScanner::scan_target called on a non-applicable artifact; the orchestrator must gate on is_applicable first"
        );

        info!(
            "Starting OpenSCAP compliance scan for artifact: {} ({})",
            artifact.name, artifact.id
        );

        // Create the base first (idempotent) so a missing/unwritable shared
        // volume root surfaces as a clear, actionable error rather than a bare
        // "Permission denied (os error 13)" against the per-scan subdir
        // (issue #1563). The OpenSCAP sidecar reads this same volume read-only,
        // so the path must stay under the configured base; we do not silently
        // relocate it.
        if let Err(e) = tokio::fs::create_dir_all(&self.scan_workspace).await {
            return Err(workspace_create_error(&self.scan_workspace, &e));
        }
        // Per scan job, not per artifact (#4668). The guard removes the tree
        // on every exit, the wall-clock timeout included (#3565).
        let extractor = OciRootfsExtractor {
            db: target.db,
            storage: target.storage,
            repository_id: artifact.repository_id,
        };
        let mut prepared = ScanWorkspace::prepare_with(
            &self.scan_workspace,
            Some("openscap"),
            artifact,
            content,
            &extractor,
        )
        .await
        .inspect_err(|e| {
            if !matches!(e, AppError::ScannerEngineUnavailable(_)) {
                warn!("OpenSCAP could not unpack {}: {}", artifact.name, e);
            }
        })?;

        let findings = match self.evaluate_root(artifact, &prepared.scan_root).await {
            Ok(findings) => findings,
            Err(e @ AppError::ScannerEngineUnavailable(_)) => {
                prepared.guard.cleanup().await;
                return Err(e);
            }
            Err(e) => {
                return Err(
                    fail_scan("OpenSCAP scan", artifact, &e, Some(&mut prepared.guard)).await,
                );
            }
        };

        prepared.guard.cleanup().await;

        // OpenSCAP is a compliance scanner, not an inventory enumerator;
        // packages list intentionally empty.
        Ok(ScanOutput::findings_only(findings))
    }
}

#[cfg(ak_test_shard = "services-1")]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::scanner_service::test_helpers::make_test_artifact;

    /// #6000: a package is not an operating system root filesystem. RPM and
    /// DEB used to be applicable and were "scanned" by evaluating the
    /// sidecar's own filesystem; they are now recorded not applicable.
    #[test]
    fn test_not_applicable_rpm_6000() {
        let artifact = make_test_artifact(
            "nginx-1.24.0-1.el9.x86_64.rpm",
            "application/x-rpm",
            "rpm/nginx/nginx-1.24.0-1.el9.x86_64.rpm",
        );
        assert!(!OpenScapScanner::is_applicable(&artifact));
    }

    #[test]
    fn test_not_applicable_deb_6000() {
        let artifact = make_test_artifact(
            "nginx_1.24.0-1_amd64.deb",
            "application/vnd.debian.binary-package",
            "deb/nginx/nginx_1.24.0-1_amd64.deb",
        );
        assert!(!OpenScapScanner::is_applicable(&artifact));
    }

    /// A Helm chart pushed as an OCI artifact shares the manifest media type
    /// with an image; with the body in hand it is not applicable.
    #[test]
    fn test_not_applicable_helm_oci_chart_with_body() {
        let artifact = make_test_artifact(
            "chart",
            "application/vnd.oci.image.manifest.v1+json",
            "v2/charts/mychart/manifests/1.0.0",
        );
        let body = serde_json::json!({
            "schemaVersion": 2,
            "config": {"mediaType": "application/vnd.cncf.helm.config.v1+json",
                       "digest": format!("sha256:{}", "a".repeat(64)), "size": 1},
            "layers": [{"mediaType": "application/vnd.cncf.helm.chart.content.v1.tar+gzip",
                        "digest": format!("sha256:{}", "b".repeat(64)), "size": 1}]
        })
        .to_string();
        let target = ScanTarget {
            artifact: &artifact,
            repository_key: "charts",
            repository_type: "local",
            db: None,
            storage: None,
            manifest_body: Some(body.as_bytes()),
            expected_component: None,
            require_nonempty_catalog: false,
            repository_format: Some("docker"),
        };
        let scanner = OpenScapScanner::new(
            "http://localhost:0".into(),
            DEFAULT_OPENSCAP_PROFILE.into(),
            "/tmp".into(),
        );
        assert!(!scanner.is_applicable_for_target(&target));
    }

    #[test]
    fn test_is_applicable_container() {
        let artifact = make_test_artifact(
            "myapp",
            "application/vnd.oci.image.manifest.v1+json",
            "v2/myapp/manifests/latest",
        );
        assert!(OpenScapScanner::is_applicable(&artifact));
    }

    #[test]
    fn test_not_applicable_jar() {
        let artifact = make_test_artifact("app.jar", "application/java-archive", "maven/app.jar");
        assert!(!OpenScapScanner::is_applicable(&artifact));
    }

    #[test]
    fn test_not_applicable_npm() {
        let artifact = make_test_artifact(
            "prelaunch-test-0.1.0.tgz",
            "application/gzip",
            "npm/prelaunch-npm/prelaunch-test/-/prelaunch-test-0.1.0.tgz",
        );
        assert!(!OpenScapScanner::is_applicable(&artifact));
    }

    #[test]
    fn test_convert_findings() {
        let response = OpenScapResponse {
            findings: vec![
                OpenScapFinding {
                    rule_id: "xccdf_org.ssgproject.content_rule_no_empty_passwords".into(),
                    result: "fail".into(),
                    severity: "high".into(),
                    title: "Prevent Login to Accounts With Empty Password".into(),
                    description: Some("Accounts should not have empty passwords".into()),
                    references: vec!["CCE-27286-2".into()],
                },
                OpenScapFinding {
                    rule_id: "xccdf_org.ssgproject.content_rule_audit_enabled".into(),
                    result: "pass".into(),
                    severity: "medium".into(),
                    title: "Enable auditd Service".into(),
                    description: None,
                    references: vec![],
                },
                OpenScapFinding {
                    rule_id: "xccdf_org.ssgproject.content_rule_sshd_disable_root".into(),
                    result: "error".into(),
                    severity: "medium".into(),
                    title: "Disable SSH Root Login".into(),
                    description: None,
                    references: vec!["CCE-27445-4".into(), "NIST-800-53-IA-2".into()],
                },
            ],
            profile: Some("standard".into()),
            error: None,
            ..Default::default()
        };

        let findings = OpenScapScanner::convert_findings(&response);
        assert_eq!(findings.len(), 2); // only fail + error, not pass
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].source, Some("openscap".to_string()));
        assert_eq!(
            findings[0].affected_component,
            Some("xccdf_org.ssgproject.content_rule_no_empty_passwords".to_string())
        );
        assert_eq!(findings[0].source_url, Some("CCE-27286-2".to_string()));
        assert_eq!(findings[1].severity, Severity::Medium);
        // #3013: compliance rule failures are classed `policy`.
        assert!(findings
            .iter()
            .all(|f| f.finding_class == crate::models::security::FindingClass::Policy));
    }

    // -----------------------------------------------------------------------
    // #3294: severity classification through OpenSCAP's REAL parse path.
    //
    // Pre-fix this adapter had its own private match arm list
    // (`high | medium | moderate | low`, everything else `_ =>
    // Severity::Info`) with NO `critical` arm, so content emitting `critical`
    // had its most severe result filed as the least severe one. That is the
    // one behaviour change in this patch, and
    // `test_convert_findings_openscap_critical_is_not_downgraded` is the test
    // that gates it: restoring the private match turns that test — and only
    // that test — red.
    //
    // XCCDF 1.2 (NISTIR 7275r4, §6.4.4.2) defines the Rule `severity`
    // attribute as `unknown | info | low | medium | high`, so `critical` is
    // NOT in the spec's vocabulary and only non-standard content produces it —
    // which is exactly why closing it was safe in a patch. The spec's DEFAULT
    // value, `unknown`, is the high-volume case; as of #3306 it fails closed
    // at `High` (see `test_convert_findings_xccdf_unknown_fails_closed_3306`).
    // -----------------------------------------------------------------------

    fn openscap_response_with_severities(sevs: &[&str]) -> OpenScapResponse {
        OpenScapResponse {
            findings: sevs
                .iter()
                .enumerate()
                .map(|(i, s)| OpenScapFinding {
                    rule_id: format!("xccdf_org.ssgproject.content_rule_{i}"),
                    // `fail` so nothing is dropped by the result filter and
                    // the indices below line up with `sevs`.
                    result: "fail".into(),
                    severity: (*s).to_string(),
                    title: format!("rule {i}"),
                    description: None,
                    references: vec![],
                })
                .collect(),
            profile: Some("standard".into()),
            error: None,
            ..Default::default()
        }
    }

    /// Positive control: the XCCDF grades this adapter already understood must
    /// convert exactly as they do today.
    #[test]
    fn test_convert_findings_preserves_graded_xccdf_severities() {
        let response = openscap_response_with_severities(&["high", "medium", "moderate", "low"]);
        let findings = OpenScapScanner::convert_findings(&response);
        assert_eq!(findings.len(), 4);
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[1].severity, Severity::Medium);
        assert_eq!(findings[2].severity, Severity::Medium);
        assert_eq!(findings[3].severity, Severity::Low);
    }

    /// #3306: XCCDF's default rule severity, `unknown`, is an UNGRADED result
    /// and fails closed at `High`. This is the high-volume case (Artifact
    /// Keeper's own wrapper, `scripts/openscap-wrapper.py:211,231`, defaults a
    /// rule's severity to the literal `unknown`, so most rules on a typical
    /// profile arrive ungraded) — which is exactly why leaving it at the
    /// `Info` floor was a fail-open at every severity-aware gate. This is the
    /// deliberate rewrite of the stage-1a pinning test
    /// (`..._is_unchanged_pending_3306`).
    #[test]
    fn test_convert_findings_xccdf_unknown_fails_closed_3306() {
        let response = openscap_response_with_severities(&["unknown", "info", "low"]);
        let findings = OpenScapScanner::convert_findings(&response);
        assert_eq!(findings.len(), 3);

        assert_eq!(
            findings[0].severity,
            Severity::High,
            "XCCDF `unknown` is an ungraded result and must fail closed at \
             High (#3306)"
        );
        // An EXPLICIT `info` grade stays at the floor: the two are now
        // distinguishable, which is the point of #3306.
        assert_eq!(findings[1].severity, Severity::Info);

        // Positive control in the same fixture: a graded rule below High is
        // untouched, so the assertions above cannot be satisfied by a
        // converter that raises everything.
        assert_eq!(findings[2].severity, Severity::Low);
    }

    /// **The one behaviour change in this patch.** The private match this
    /// replaced had arms for `high | medium | moderate | low` only, so a
    /// `critical` result fell through its `_ => Severity::Info` catch-all and
    /// the adapter's MOST severe finding was filed as its least severe one.
    ///
    /// `critical` is not in XCCDF 1.2's `unknown | info | low | medium | high`
    /// vocabulary, so it reaches this adapter only from non-standard content —
    /// near-zero volume, unambiguously a fail-open when it does fire, which is
    /// why this half ships in a patch while #3306 does not.
    #[test]
    fn test_convert_findings_openscap_critical_is_not_downgraded() {
        let response = openscap_response_with_severities(&["critical", "high", "info"]);
        let findings = OpenScapScanner::convert_findings(&response);
        assert_eq!(findings.len(), 3);

        assert_eq!(
            findings[0].severity,
            Severity::Critical,
            "an OpenSCAP `critical` result must not be downgraded"
        );
        assert_ne!(
            findings[0].severity,
            Severity::Info,
            "the pre-#3294 private match had no `critical` arm, so this landed \
             in the lowest bucket"
        );

        // Positive controls in the same fixture, so the assertions above
        // cannot be satisfied by a change that raises every finding: a graded
        // `high` is unchanged, and an explicit `info` stays at the floor.
        assert_eq!(findings[1].severity, Severity::High);
        assert_eq!(findings[2].severity, Severity::Info);
    }

    // -----------------------------------------------------------------------
    // #6000: what a scan evaluates, and how the wrapper's answer is read
    // -----------------------------------------------------------------------

    const STIG: &str = "xccdf_org.ssgproject.content_profile_stig";

    fn image_artifact() -> Artifact {
        make_test_artifact(
            "myapp",
            "application/vnd.oci.image.manifest.v1+json",
            "v2/myapp/manifests/1.0",
        )
    }

    fn completed(profile: &str) -> OpenScapResponse {
        OpenScapResponse {
            status: Some("completed".into()),
            profile: Some(profile.into()),
            evaluated: Some(10),
            findings: vec![OpenScapFinding {
                rule_id: "xccdf_org.ssgproject.content_rule_accounts_umask_etc_profile".into(),
                result: "fail".into(),
                severity: "medium".into(),
                title: "Ensure the Default Umask is Set Correctly in /etc/profile".into(),
                description: None,
                references: vec![],
            }],
            ..Default::default()
        }
    }

    /// The backend default must be a profile the shipped wrapper also uses
    /// as its own default, and not the `standard` profile no shipped
    /// datastream defines.
    #[test]
    fn test_default_profile_matches_wrapper_6000() {
        let wrapper = include_str!("../../../scripts/openscap-wrapper.py");
        assert!(
            wrapper.contains(&format!("DEFAULT_PROFILE = \"{DEFAULT_OPENSCAP_PROFILE}\"")),
            "scripts/openscap-wrapper.py DEFAULT_PROFILE must equal {DEFAULT_OPENSCAP_PROFILE}"
        );
        assert!(!DEFAULT_OPENSCAP_PROFILE.ends_with("content_profile_standard"));
        assert_eq!(
            crate::config::Config::default().openscap_profile,
            DEFAULT_OPENSCAP_PROFILE
        );
    }

    #[test]
    fn test_completed_response_keeps_configured_profile() {
        let findings = OpenScapScanner::interpret_response(&completed(STIG), STIG).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    /// The old wrapper replaced an unknown profile with `profiles[0]`. A
    /// response for any other profile than the configured one is an error.
    #[test]
    fn test_substituted_profile_is_an_error_6000() {
        let resp = completed("xccdf_org.ssgproject.content_profile_anssi_bp28_enhanced");
        let err = OpenScapScanner::interpret_response(&resp, DEFAULT_OPENSCAP_PROFILE).unwrap_err();
        assert!(matches!(err, AppError::Internal(_)), "{err}");
        assert!(
            err.to_string().contains("instead of the configured"),
            "{err}"
        );
    }

    /// A wrapper error used to be logged and the scan completed with zero
    /// findings, which read as a clean pass.
    #[test]
    fn test_wrapper_error_fails_the_scan_6000() {
        let resp = OpenScapResponse {
            error: Some("oscap exited with code 1".into()),
            ..Default::default()
        };
        let err = OpenScapScanner::interpret_response(&resp, STIG).unwrap_err();
        assert!(matches!(err, AppError::Internal(_)), "{err}");
    }

    #[test]
    fn test_not_applicable_response_records_not_applicable_6000() {
        let resp = OpenScapResponse {
            status: Some("not_applicable".into()),
            reason: Some("no SCAP content for debian 12 in this sidecar".into()),
            ..Default::default()
        };
        match OpenScapScanner::interpret_response(&resp, STIG) {
            Err(AppError::ScannerEngineUnavailable(reason)) => {
                assert!(reason.contains("debian 12"), "{reason}")
            }
            other => panic!("expected not_applicable, got {other:?}"),
        }
    }

    /// A wrapper from before #6000 answers without a status, after
    /// evaluating its own filesystem. Its findings are not about the image.
    #[test]
    fn test_pre_fix_wrapper_response_is_refused_6000() {
        let resp = OpenScapResponse {
            profile: Some(STIG.into()),
            findings: completed(STIG).findings,
            ..Default::default()
        };
        let err = OpenScapScanner::interpret_response(&resp, STIG).unwrap_err();
        assert!(err.to_string().contains("predates"), "{err}");
    }

    /// Without repository storage the image cannot be unpacked: not
    /// applicable, and the job directory is gone afterwards. The base is
    /// still created first (#1563).
    #[tokio::test]
    async fn test_scan_without_storage_is_not_applicable_6000() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("nested").join("scan-workspace");
        let scanner = OpenScapScanner::new(
            "http://localhost:0".into(),
            STIG.into(),
            base.to_string_lossy().to_string(),
        );
        let artifact = image_artifact();
        let target = ScanTarget {
            artifact: &artifact,
            repository_key: "docker-local",
            repository_type: "local",
            db: None,
            storage: None,
            manifest_body: None,
            expected_component: None,
            require_nonempty_catalog: false,
            repository_format: Some("docker"),
        };
        let err = scanner
            .scan_target(&target, None, &Bytes::from_static(b"{}"))
            .await
            .unwrap_err();
        assert!(
            matches!(err, AppError::ScannerEngineUnavailable(_)),
            "{err}"
        );
        assert!(base.is_dir(), "the shared base is created first");
        assert_eq!(
            std::fs::read_dir(&base).unwrap().count(),
            0,
            "job dir removed"
        );

        // The legacy entry point has no storage either.
        let err = scanner
            .scan(&artifact, None, &Bytes::from_static(b"{}"))
            .await
            .unwrap_err();
        assert!(
            matches!(err, AppError::ScannerEngineUnavailable(_)),
            "{err}"
        );
    }

    /// End to end in process: two stored layers are unpacked in order into
    /// `<workspace>/rootfs`, and THAT directory (holding the image's
    /// os-release, not the raw manifest) is what the wrapper is asked to
    /// evaluate, under the configured base (#1466) and with the configured
    /// profile.
    #[tokio::test]
    async fn test_unpacked_rootfs_is_what_the_wrapper_evaluates_6000() {
        use crate::services::oci_rootfs::{unpack_layers, ImageLayer, LayerCoding};
        use crate::storage::StorageBackend;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, Request, ResponseTemplate};

        fn layer_tar(files: &[(&str, &[u8])]) -> Bytes {
            let mut b = tar::Builder::new(Vec::new());
            for (name, data) in files {
                let mut h = tar::Header::new_gnu();
                h.set_size(data.len() as u64);
                h.set_mode(0o644);
                h.set_cksum();
                b.append_data(&mut h, name, *data).unwrap();
            }
            Bytes::from(b.into_inner().unwrap())
        }

        let dir = tempfile::tempdir().unwrap();
        let storage = crate::storage::filesystem::FilesystemStorage::new(dir.path().join("store"));
        let l1 = layer_tar(&[
            ("etc/os-release", b"ID=rhel\nVERSION_ID=9.6\n"),
            ("etc/profile", b"umask 022\n"),
        ]);
        let l2 = layer_tar(&[("etc/profile", b"umask 077\n")]);
        let d1 = format!("sha256:{}", "1".repeat(64));
        let d2 = format!("sha256:{}", "2".repeat(64));
        storage.put("blobs/l1", l1.clone()).await.unwrap();
        storage.put("blobs/l2", l2.clone()).await.unwrap();
        let layers = vec![
            ImageLayer {
                digest: d1.clone(),
                coding: LayerCoding::Plain,
                size: l1.len() as u64,
            },
            ImageLayer {
                digest: d2.clone(),
                coding: LayerCoding::Plain,
                size: l2.len() as u64,
            },
        ];
        let keys = [(d1, "blobs/l1".to_string()), (d2, "blobs/l2".to_string())]
            .into_iter()
            .collect();
        let base = dir.path().join("ws");
        let job = base.join("openscap-x-job");
        std::fs::create_dir_all(&job).unwrap();
        let root = unpack_layers(
            &storage,
            &layers,
            &keys,
            &job,
            std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        )
        .await
        .unwrap();
        assert_eq!(root, job.join("rootfs"));
        assert_eq!(
            std::fs::read_to_string(root.join("etc/profile")).unwrap(),
            "umask 077\n"
        );
        assert!(root.join(".dockerenv").exists());
        assert!(!job.join("layers").exists(), "staged blobs are removed");

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/scan"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "status": "completed",
                "profile": STIG,
                "content": "rhel9",
                "target_os": "rhel 9.6",
                "evaluated": 12,
                "findings": [{
                    "rule_id": "xccdf_org.ssgproject.content_rule_accounts_umask_etc_bashrc",
                    "result": "fail",
                    "severity": "medium",
                    "title": "Ensure the Default Bash Umask is Set Correctly",
                    "references": []
                }]
            })))
            .expect(1)
            .mount(&server)
            .await;
        let scanner =
            OpenScapScanner::new(server.uri(), STIG.into(), base.to_string_lossy().into());
        let findings = scanner
            .evaluate_root(&image_artifact(), &root)
            .await
            .unwrap();
        assert_eq!(findings.len(), 1);

        let received: Vec<Request> = server.received_requests().await.unwrap_or_default();
        let body: serde_json::Value = serde_json::from_slice(&received[0].body).unwrap();
        let sent = body["path"].as_str().unwrap();
        assert_eq!(sent, root.to_string_lossy());
        assert!(
            Path::new(sent).starts_with(&base),
            "under the configured base (#1466)"
        );
        assert!(Path::new(sent).join("etc/os-release").is_file());
        assert_eq!(body["profile"].as_str(), Some(STIG));
    }

    /// When the wrapper rejects the path with HTTP 400 (the exact symptom
    /// in issue #1466), or the profile with HTTP 422 (#6000), the error
    /// carries the path and the wrapper's body.
    #[tokio::test]
    async fn test_scan_error_includes_rejected_path() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("openscap-x-job").join("rootfs");
        std::fs::create_dir_all(&root).unwrap();
        for (status, body) in [
            (400, "{\"error\": \"scan path not found or not allowed\"}"),
            (422, "{\"error\": \"profile x is not defined in any shipped SCAP datastream\", \"code\": \"unknown_profile\"}"),
        ] {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/scan"))
                .respond_with(ResponseTemplate::new(status).set_body_string(body))
                .mount(&server)
                .await;
            let scanner = OpenScapScanner::new(
                server.uri(),
                STIG.into(),
                dir.path().to_string_lossy().to_string(),
            );
            let err = scanner
                .evaluate_root(&image_artifact(), &root)
                .await
                .expect_err("scan must propagate the wrapper refusal");
            let msg = err.to_string();
            assert!(msg.contains("OpenSCAP scan failed"), "got: {}", msg);
            assert!(msg.contains(&*root.to_string_lossy()), "path missing: {msg}");
            assert!(msg.contains(&body[12..30]), "wrapper body missing: {msg}");
        }
    }

    /// When the OpenSCAP sidecar is unreachable, evaluation must return Err
    /// so the orchestrator records the scan as failed, never clean.
    #[tokio::test]
    async fn test_scan_returns_error_when_sidecar_unreachable() {
        let dir = tempfile::tempdir().unwrap();
        let scanner = OpenScapScanner::new(
            "http://localhost:0".to_string(),
            STIG.to_string(),
            dir.path().to_string_lossy().to_string(),
        );
        let err = scanner
            .evaluate_root(&image_artifact(), dir.path())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("OpenSCAP request failed"), "{err}");
    }

    /// Build an `OpenScapScanner` pointing at `url`, using a fresh tempdir
    /// for the scan workspace. The returned `_dir` guard must be kept
    /// in scope for the test's lifetime so the directory is not dropped.
    fn make_probe_scanner(url: String) -> (OpenScapScanner, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let scanner = OpenScapScanner::new(
            url,
            "standard".to_string(),
            dir.path().to_string_lossy().to_string(),
        );
        (scanner, dir)
    }

    /// Mount a `GET /health` mock on `server` that responds with `template`,
    /// matching the openscap wrapper sidecar's healthcheck route.
    async fn mount_health_mock(
        server: &wiremock::MockServer,
        template: wiremock::ResponseTemplate,
    ) {
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/health"))
            .respond_with(template)
            .mount(server)
            .await;
    }

    /// `probe_version` returns `Some("openscap-<ver>")` when the wrapper's
    /// `/health` endpoint responds 200 with a `version` field shaped like
    /// the real `oscap --version` first line. This is the happy path the
    /// orchestrator relies on for `scan_results.scanner_version`.
    #[tokio::test]
    async fn test_probe_version_success() {
        let server = wiremock::MockServer::start().await;
        mount_health_mock(
            &server,
            wiremock::ResponseTemplate::new(200).set_body_json(
                serde_json::json!({"version": "OpenSCAP command line tool (oscap) 1.4.0"}),
            ),
        )
        .await;

        let (scanner, _dir) = make_probe_scanner(server.uri());
        let v = scanner.version().await;
        assert_eq!(v, Some("openscap-1.4.0".to_string()));

        // Second call must hit the cache, not the server. Wiremock would
        // accept additional calls silently, so we instead assert the value
        // is stable across two awaits. The cache populated above must not
        // be re-run.
        let v2 = scanner.version().await;
        assert_eq!(v, v2);
    }

    /// `probe_version` returns `None` when the wrapper responds with a
    /// non-2xx status (e.g. 503 during sidecar startup). The scan must
    /// still proceed; the version field is metadata, not load-bearing.
    #[tokio::test]
    async fn test_probe_version_non_success_status_returns_none() {
        let server = wiremock::MockServer::start().await;
        mount_health_mock(&server, wiremock::ResponseTemplate::new(503)).await;

        let (scanner, _dir) = make_probe_scanner(server.uri());
        assert_eq!(scanner.version().await, None);
    }

    /// `probe_version` returns `None` when the response body cannot be
    /// parsed as the expected JSON shape. Defensive: a misconfigured
    /// reverse proxy might return HTML.
    #[tokio::test]
    async fn test_probe_version_malformed_body_returns_none() {
        let server = wiremock::MockServer::start().await;
        mount_health_mock(
            &server,
            wiremock::ResponseTemplate::new(200)
                .set_body_string("<html>not json</html>")
                .insert_header("content-type", "text/html"),
        )
        .await;

        let (scanner, _dir) = make_probe_scanner(server.uri());
        assert_eq!(scanner.version().await, None);
    }

    /// `probe_version` returns `None` when the JSON is well-formed but the
    /// `version` field is absent or null. The wrapper's health response
    /// schema explicitly defaults this field to None.
    #[tokio::test]
    async fn test_probe_version_missing_field_returns_none() {
        let server = wiremock::MockServer::start().await;
        mount_health_mock(
            &server,
            wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({})),
        )
        .await;

        let (scanner, _dir) = make_probe_scanner(server.uri());
        assert_eq!(scanner.version().await, None);
    }

    /// `probe_version` returns `None` when the version field is present
    /// but contains only whitespace. The token extraction
    /// (`split_whitespace().last()`) yields nothing, so the function
    /// short-circuits to None instead of producing `openscap-`.
    #[tokio::test]
    async fn test_probe_version_whitespace_only_field_returns_none() {
        let server = wiremock::MockServer::start().await;
        mount_health_mock(
            &server,
            wiremock::ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"version": "   "})),
        )
        .await;

        let (scanner, _dir) = make_probe_scanner(server.uri());
        assert_eq!(scanner.version().await, None);
    }

    /// `probe_version` returns `None` when the URL is unreachable
    /// (connection refused). This exercises the `.send().await.ok()?`
    /// short-circuit. Together with the success/error/missing tests above,
    /// every branch of `probe_version` is covered without requiring a real
    /// OpenSCAP wrapper sidecar.
    #[tokio::test]
    async fn test_probe_version_unreachable_returns_none() {
        // Port 0 is reserved and yields connection refused.
        let (scanner, _dir) = make_probe_scanner("http://127.0.0.1:0".to_string());
        assert_eq!(scanner.version().await, None);
    }

    /// `workspace_create_error` maps an EACCES (`PermissionDenied`) IO error to
    /// an actionable message that names the base path and points operators at
    /// the volume-ownership fix. This is the exact failure mode reported in
    /// issue #1563 (Podman/SELinux on Fedora).
    #[test]
    fn test_workspace_create_error_permission_denied_is_actionable() {
        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "Permission denied");
        let err = workspace_create_error("/scan-workspace", &io_err);
        let msg = err.to_string();
        assert!(
            msg.contains("/scan-workspace"),
            "error must name the base path, got: {msg}"
        );
        assert!(
            msg.contains("1001"),
            "permission-denied error must mention the backend UID, got: {msg}"
        );
        assert!(
            msg.to_lowercase().contains("volume"),
            "permission-denied error must point at the volume fix, got: {msg}"
        );
    }

    /// `workspace_create_error` for a non-permission IO error keeps a plain
    /// message (no spurious volume-ownership advice that would mislead).
    #[test]
    fn test_workspace_create_error_other_kind_is_plain() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "no such file");
        let err = workspace_create_error("/scan-workspace", &io_err);
        let msg = err.to_string();
        assert!(
            msg.contains("/scan-workspace") && msg.contains("no such file"),
            "error must include base and cause, got: {msg}"
        );
        assert!(
            !msg.contains("1001"),
            "non-permission error must not mention UID-ownership advice, got: {msg}"
        );
    }
}
