//! HTTP client for the scanner-adapter's filesystem-scan endpoint (#2363).
//!
//! The hardened runtime image ships no `trivy` CLI (#2059), so the filesystem
//! and incus scanners route their scans through the in-repo scanner-adapter
//! (`docker/scanner-adapter/`) over HTTP instead of spawning `trivy` locally:
//! the backend prepares (extracts + hardens) the scan workspace as before,
//! tars it, uploads the tar to `POST /api/v1/filesystem/scan`, and polls
//! `GET /api/v1/filesystem/scan/{id}/report` until the adapter has run
//! `trivy filesystem` over it. The adapter returns trivy's NATIVE JSON report
//! (with the `--list-all-pkgs` Packages blocks) plus trivy's stderr, so the
//! SBOM package inventory (#903) and the partial-scan classification (#1153)
//! flow through unchanged.
//!
//! ERROR-MAPPING CONTRACT — deliberately DIFFERENT from `ImageScanner`:
//!
//! * Adapter unreachable, not ready (`/probe/ready` 503), or a report that
//!   never becomes ready within the poll budget map to
//!   [`AppError::ScannerEngineUnavailable`]. The orchestrator records a
//!   terminal `not_applicable` row — the same graceful degrade the missing
//!   trivy CLI produced (#2323/#2324) — because grype still covers these
//!   artifacts and a down sidecar must not floor the repository grade to F.
//! * An adapter that IS up but reports a failed job (report 500), an unknown
//!   scan id, or an unparseable body maps to [`AppError::Internal`]: the scan
//!   engine ran and broke, so the scan fails closed (`failed`), never a
//!   silent zero-finding completion.
//!
//! `ImageScanner` (image_scanner.rs) keeps its own, stricter contract — every
//! adapter error is `BadGateway`/fail-closed (#2088) — because container-image
//! scans have no grype `dir:`-mode fallback covering the same surface.

use std::path::Path;

use crate::error::{AppError, Result};
use crate::services::image_scanner::TrivyReport;

/// Default cap on the tarred filesystem workspace uploaded to the adapter
/// (64 GiB), aligned with the incus extracted-tree budget. Overridable via
/// [`MAX_FS_SCAN_UPLOAD_BYTES_ENV`].
const DEFAULT_MAX_FS_UPLOAD_BYTES: u64 = 64 * 1024 * 1024 * 1024;

/// Env var overriding the filesystem-workspace upload cap (plain byte count).
const MAX_FS_SCAN_UPLOAD_BYTES_ENV: &str = "MAX_FS_SCAN_UPLOAD_BYTES";

/// Effective upload cap for tarred filesystem workspaces.
pub(crate) fn fs_upload_cap_bytes() -> u64 {
    std::env::var(MAX_FS_SCAN_UPLOAD_BYTES_ENV)
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .filter(|&v| v > 0)
        .unwrap_or(DEFAULT_MAX_FS_UPLOAD_BYTES)
}

/// Which engine a trivy-based filesystem scanner drives: the legacy local CLI
/// (back-compat for deployments that bundle `trivy` and set `TRIVY_URL`) or
/// the scanner-adapter's HTTP filesystem endpoint (#2363).
pub(crate) enum TrivyFsBackend {
    /// Spawn the local `trivy` CLI, trying `--server <url>` then standalone.
    Cli { trivy_url: String },
    /// Upload the prepared workspace to the scanner-adapter.
    Adapter(ScannerAdapterFsClient),
}

/// Engine selection + provenance shared by `TrivyFsScanner` and
/// `IncusScanner`, so both hold one field and the mode plumbing (backend
/// choice, adapter-reported version, tar-and-upload flow) lives in a single
/// place instead of being duplicated per scanner.
pub(crate) struct TrivyEngine {
    backend: TrivyFsBackend,
    /// Trivy version reported by the scanner-adapter on the most recent
    /// successful scan (adapter mode); there is no local binary to probe.
    adapter_version: std::sync::Mutex<Option<String>>,
}

impl TrivyEngine {
    /// Legacy CLI mode: the scanner spawns the bundled `trivy` binary.
    pub fn cli(trivy_url: String) -> Self {
        Self::with_backend(TrivyFsBackend::Cli { trivy_url })
    }

    /// Adapter mode (#2363): scans upload the workspace to the
    /// scanner-adapter; no local `trivy` binary needed.
    pub fn adapter(adapter_url: String) -> Self {
        Self::with_backend(TrivyFsBackend::Adapter(ScannerAdapterFsClient::new(
            adapter_url,
        )))
    }

    fn with_backend(backend: TrivyFsBackend) -> Self {
        Self {
            backend,
            adapter_version: std::sync::Mutex::new(None),
        }
    }

    pub fn backend(&self) -> &TrivyFsBackend {
        &self.backend
    }

    /// Scanner version for `scan_results.scanner_version`: the CLI probe in
    /// CLI mode (via the caller's [`VersionCache`]), or the version the
    /// adapter reported on the last successful scan (normalized to
    /// `trivy-<ver>`; `None` until one has run).
    pub async fn version(
        &self,
        cli_cache: &crate::services::scanner_service::VersionCache,
    ) -> Option<String> {
        match &self.backend {
            TrivyFsBackend::Cli { .. } => {
                crate::services::scanner_service::cached_trivy_cli_version(cli_cache).await
            }
            TrivyFsBackend::Adapter(_) => self.adapter_version.lock().ok().and_then(|g| g.clone()),
        }
    }

    /// Adapter-path scan: tar `dir` (bounded by `cap_bytes` — over-cap
    /// degrades to `not_applicable` via `ScannerEngineUnavailable`), upload
    /// it, and return trivy's native report + stderr, recording the
    /// adapter-reported scanner version for [`Self::version`].
    pub async fn scan_dir_via_adapter(
        &self,
        client: &ScannerAdapterFsClient,
        dir: &Path,
        cap_bytes: u64,
    ) -> Result<(TrivyReport, String)> {
        let tar = tar_workspace_capped_async(dir, cap_bytes).await?;
        let body = client.scan_workspace_tar(tar).await?;
        if let Some(ver) = body.scanner_version.filter(|v| !v.is_empty()) {
            let normalized = if ver.starts_with("trivy-") {
                ver
            } else {
                format!("trivy-{}", ver)
            };
            if let Ok(mut guard) = self.adapter_version.lock() {
                *guard = Some(normalized);
            }
        }
        Ok((body.report, body.stderr))
    }
}

/// Successful body of `GET /api/v1/filesystem/scan/{id}/report`.
#[derive(Debug, serde::Deserialize)]
pub(crate) struct FsScanReportBody {
    /// Trivy's native `--format json` document, verbatim.
    pub report: TrivyReport,
    /// Trivy's stderr text (partial-scan signal, #1153).
    #[serde(default)]
    pub stderr: String,
    /// Adapter-probed trivy version (e.g. `0.71.2`) for provenance.
    #[serde(default)]
    pub scanner_version: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
struct FsScanSubmitResponse {
    id: String,
}

/// Filesystem-scan client for the scanner-adapter. See the module docs for
/// the error-mapping contract.
pub(crate) struct ScannerAdapterFsClient {
    adapter_url: String,
    http: reqwest::Client,
    /// Redirects disabled so a `302 Found` "report not ready" is observed
    /// rather than followed.
    poll_http: reqwest::Client,
}

impl ScannerAdapterFsClient {
    /// Readiness probe attempts before declaring the adapter unavailable.
    const READY_ATTEMPTS: u32 = 3;
    const READY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
    const READY_BACKOFF: std::time::Duration = std::time::Duration::from_millis(500);

    /// Wall-clock budget for polling the filesystem report. Sized above the
    /// adapter's 10m trivy filesystem timeout so a slow-but-live scan is not
    /// abandoned client-side first.
    const POLL_BUDGET: std::time::Duration = std::time::Duration::from_secs(660);
    /// Poll delay when the adapter sends no `Refresh-After` header.
    const POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

    pub fn new(adapter_url: String) -> Self {
        Self {
            adapter_url,
            http: crate::services::http_client::internal_service_client_builder()
                // Generous: the body is the tarred workspace, potentially GBs
                // for an incus rootfs.
                .timeout(std::time::Duration::from_secs(900))
                .build()
                .unwrap_or_default(),
            poll_http: crate::services::http_client::internal_service_client_builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .unwrap_or_default(),
        }
    }

    /// Upload a tarred workspace and wait for trivy's native report.
    /// The single public entry point: readiness gate, submit, poll.
    pub async fn scan_workspace_tar(&self, tar: Vec<u8>) -> Result<FsScanReportBody> {
        self.ensure_ready().await?;
        let scan_id = self.submit(tar).await?;
        self.poll_report(&scan_id).await
    }

    /// Availability-class error: the sidecar is down/unready, which degrades
    /// the scan to `not_applicable` (#2324) instead of failing it closed.
    fn unavailable(&self, detail: impl std::fmt::Display) -> AppError {
        AppError::ScannerEngineUnavailable(format!(
            "Trivy scanner-adapter at {} is unavailable for filesystem scans: {}. \
             Grype continues to cover these artifacts.",
            self.adapter_url, detail
        ))
    }

    /// Gate on `/probe/ready` with bounded retries. Any failure here is an
    /// availability state, not a scan failure.
    async fn ensure_ready(&self) -> Result<()> {
        let url = format!("{}/probe/ready", self.adapter_url);
        let mut last: Option<String> = None;

        for attempt in 1..=Self::READY_ATTEMPTS {
            let outcome = self
                .http
                .get(&url)
                .timeout(Self::READY_TIMEOUT)
                .send()
                .await;
            match outcome {
                Ok(resp) if resp.status().is_success() => return Ok(()),
                Ok(resp) => last = Some(format!("not ready (HTTP {})", resp.status())),
                Err(e) => last = Some(format!("unreachable ({})", e)),
            }
            tracing::warn!(
                "scanner-adapter fs readiness attempt {}/{} failed: {}",
                attempt,
                Self::READY_ATTEMPTS,
                last.as_deref().unwrap_or("unknown")
            );
            if attempt < Self::READY_ATTEMPTS {
                tokio::time::sleep(Self::READY_BACKOFF).await;
            }
        }

        Err(self.unavailable(last.unwrap_or_else(|| "readiness probe failed".to_string())))
    }

    /// POST the tar body; returns the adapter-assigned job id. Transport
    /// errors and 503s are availability; any other adapter response that is
    /// not a valid accepted job is fail-closed `Internal`.
    async fn submit(&self, tar: Vec<u8>) -> Result<String> {
        let url = format!("{}/api/v1/filesystem/scan", self.adapter_url);
        let resp = self
            .http
            .post(&url)
            .header(reqwest::header::CONTENT_TYPE, "application/x-tar")
            .body(tar)
            .send()
            .await
            .map_err(|e| self.unavailable(format!("workspace upload failed: {}", e)))?;

        let status = resp.status();
        if status == reqwest::StatusCode::SERVICE_UNAVAILABLE {
            return Err(self.unavailable("adapter answered 503 on submit"));
        }
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(AppError::Internal(format!(
                "Scanner-adapter rejected the filesystem scan submit with {}: {}",
                status, text
            )));
        }

        let parsed: FsScanSubmitResponse = resp.json().await.map_err(|e| {
            AppError::Internal(format!(
                "Scanner-adapter filesystem submit response did not parse: {}",
                e
            ))
        })?;
        if parsed.id.trim().is_empty() {
            return Err(AppError::Internal(
                "Scanner-adapter returned an empty filesystem scan id".to_string(),
            ));
        }
        Ok(parsed.id)
    }

    /// Poll the report endpoint until terminal or the budget is exhausted.
    ///
    /// * 200 → parse `{report, stderr}` (parse failure is `Internal`).
    /// * 302 → pending; honor `Refresh-After`.
    /// * budget exhausted → `ScannerEngineUnavailable` (availability).
    /// * any other status (500 failed job, 404 unknown id) → `Internal`
    ///   (the engine ran and broke — fail closed).
    async fn poll_report(&self, scan_id: &str) -> Result<FsScanReportBody> {
        let url = format!(
            "{}/api/v1/filesystem/scan/{}/report",
            self.adapter_url, scan_id
        );
        let deadline = std::time::Instant::now() + Self::POLL_BUDGET;

        loop {
            let resp = self
                .poll_http
                .get(&url)
                .send()
                .await
                .map_err(|e| self.unavailable(format!("report poll failed: {}", e)))?;

            let status = resp.status();
            if status.is_success() {
                return resp.json::<FsScanReportBody>().await.map_err(|e| {
                    AppError::Internal(format!(
                        "Scanner-adapter filesystem report did not parse: {}",
                        e
                    ))
                });
            }
            if status != reqwest::StatusCode::FOUND {
                let text = resp.text().await.unwrap_or_default();
                return Err(AppError::Internal(format!(
                    "Scanner-adapter filesystem scan {} failed with {}: {}",
                    scan_id, status, text
                )));
            }

            let refresh_after = resp
                .headers()
                .get("Refresh-After")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.trim().parse::<u64>().ok())
                .map(std::time::Duration::from_secs)
                .unwrap_or(Self::POLL_INTERVAL);

            if std::time::Instant::now() + refresh_after >= deadline {
                return Err(self.unavailable(format!(
                    "report for scan {} not ready within the {}s budget",
                    scan_id,
                    Self::POLL_BUDGET.as_secs()
                )));
            }
            tokio::time::sleep(refresh_after).await;
        }
    }
}

/// Tar a prepared scan workspace into memory, enforcing `cap_bytes` over the
/// cumulative regular-file size. Symlinks are archived as links (never
/// followed), so an in-rootfs `var/run -> /run` cannot pull host content into
/// the upload.
///
/// Over-cap is an availability decision, not a scan failure: the artifact is
/// too large to ship to the sidecar, so the scan degrades to `not_applicable`
/// via [`AppError::ScannerEngineUnavailable`] rather than buffering an
/// unbounded tree in memory (availability/OOM guard).
pub(crate) fn tar_workspace_capped(dir: &Path, cap_bytes: u64) -> Result<Vec<u8>> {
    let mut builder = tar::Builder::new(Vec::new());
    builder.follow_symlinks(false);
    let mut total_bytes: u64 = 0;

    for entry in walkdir::WalkDir::new(dir).follow_links(false) {
        let entry = entry.map_err(|e| {
            AppError::Internal(format!("Failed to walk scan workspace for upload: {}", e))
        })?;
        let path = entry.path();
        if path == dir {
            continue;
        }
        let rel = path
            .strip_prefix(dir)
            .map_err(|e| AppError::Internal(format!("Workspace entry escaped its root: {}", e)))?;

        if entry.file_type().is_file() {
            total_bytes =
                total_bytes.saturating_add(entry.metadata().map(|m| m.len()).unwrap_or(0));
            if total_bytes > cap_bytes {
                return Err(AppError::ScannerEngineUnavailable(format!(
                    "Scan workspace exceeds the {} byte adapter upload budget; \
                     skipping the trivy filesystem scan for this artifact \
                     (grype still covers it).",
                    cap_bytes
                )));
            }
        }

        builder.append_path_with_name(path, rel).map_err(|e| {
            AppError::Internal(format!(
                "Failed to add {} to the workspace tar: {}",
                rel.display(),
                e
            ))
        })?;
    }

    builder
        .into_inner()
        .map_err(|e| AppError::Internal(format!("Failed to finish workspace tar: {}", e)))
}

/// Async wrapper for [`tar_workspace_capped`]: the walk + tar build is
/// blocking I/O, so it runs on the blocking pool.
pub(crate) async fn tar_workspace_capped_async(dir: &Path, cap_bytes: u64) -> Result<Vec<u8>> {
    let dir = dir.to_path_buf();
    tokio::task::spawn_blocking(move || tar_workspace_capped(&dir, cap_bytes))
        .await
        .map_err(|e| AppError::Internal(format!("Workspace tar task failed: {}", e)))?
}

/// Wiremock plumbing shared by the adapter-mode tests here and in
/// `trivy_fs_scanner` / `incus_scanner`, so each scan-flow test only declares
/// its report payload.
#[cfg(test)]
pub(crate) mod test_support {
    /// Mount the full happy path: ready probe (200), submit (202 + `scan_id`),
    /// and a 200 report with `report_body`.
    pub(crate) async fn mount_fs_scan_success(
        server: &wiremock::MockServer,
        scan_id: &str,
        report_body: serde_json::Value,
    ) {
        use wiremock::matchers::{method, path_regex};
        use wiremock::{Mock, ResponseTemplate};

        mount_fs_ready_and_submit(server, scan_id).await;
        Mock::given(method("GET"))
            .and(path_regex(r"^/api/v1/filesystem/scan/.+/report$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(report_body))
            .mount(server)
            .await;
    }

    /// Mount only the ready probe + submit, leaving the report endpoint to
    /// the test (pending / failed / garbled cases).
    pub(crate) async fn mount_fs_ready_and_submit(server: &wiremock::MockServer, scan_id: &str) {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};

        Mock::given(method("GET"))
            .and(path("/probe/ready"))
            .respond_with(ResponseTemplate::new(200))
            .mount(server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/v1/filesystem/scan"))
            .respond_with(
                ResponseTemplate::new(202).set_body_json(serde_json::json!({ "id": scan_id })),
            )
            .mount(server)
            .await;
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{mount_fs_ready_and_submit, mount_fs_scan_success};
    use super::*;
    use wiremock::matchers::{method, path, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn tiny_tar() -> Vec<u8> {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("composer.lock"), b"{}").unwrap();
        tar_workspace_capped(dir.path(), 1024 * 1024).unwrap()
    }

    /// A ready adapter + successful job round-trips trivy's NATIVE report:
    /// vulnerabilities AND the Packages block (#903) AND stderr (#1153).
    #[tokio::test]
    async fn test_fs_report_native_json_roundtrip() {
        let server = MockServer::start().await;
        let body = serde_json::json!({
            "report": {"Results": [{
                "Target": "composer.lock",
                "Class": "lang-pkgs",
                "Type": "composer",
                "Vulnerabilities": [{
                    "VulnerabilityID": "CVE-2024-1234",
                    "PkgName": "acme/lib",
                    "InstalledVersion": "1.0.0",
                    "FixedVersion": "1.0.1",
                    "Severity": "HIGH"
                }],
                "Packages": [{"Name": "acme/lib", "Version": "1.0.0"}]
            }]},
            "stderr": "WARN something skipped",
            "scanner_version": "0.71.2"
        });
        mount_fs_scan_success(&server, "fs-1", body).await;

        let client = ScannerAdapterFsClient::new(server.uri());
        let out = client
            .scan_workspace_tar(tiny_tar())
            .await
            .expect("fs scan should complete");

        assert_eq!(out.report.results.len(), 1);
        let result = &out.report.results[0];
        assert_eq!(result.vulnerabilities.as_ref().unwrap().len(), 1);
        // #903: the Packages block must survive the round-trip.
        assert_eq!(result.packages.as_ref().unwrap()[0].name, "acme/lib");
        // #1153: stderr must be carried for the partial-scan classifier.
        assert_eq!(out.stderr, "WARN something skipped");
        assert_eq!(out.scanner_version.as_deref(), Some("0.71.2"));
    }

    /// An unreachable adapter is an availability state: the scan must degrade
    /// (ScannerEngineUnavailable -> not_applicable, #2324), NOT fail closed.
    #[tokio::test]
    async fn test_unreachable_adapter_is_engine_unavailable() {
        let client = ScannerAdapterFsClient::new("http://127.0.0.1:1".to_string());
        let err = client.scan_workspace_tar(tiny_tar()).await.unwrap_err();
        assert!(
            matches!(err, AppError::ScannerEngineUnavailable(_)),
            "unreachable adapter must be ScannerEngineUnavailable, got {err:?}"
        );
    }

    /// A 503 from /probe/ready (adapter starting / DB not loaded) is also an
    /// availability state.
    #[tokio::test]
    async fn test_not_ready_503_is_engine_unavailable() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/probe/ready"))
            .respond_with(ResponseTemplate::new(503).set_body_string("scanner starting"))
            .mount(&server)
            .await;

        let client = ScannerAdapterFsClient::new(server.uri());
        let err = client.scan_workspace_tar(tiny_tar()).await.unwrap_err();
        assert!(
            matches!(err, AppError::ScannerEngineUnavailable(_)),
            "a 503 readiness probe must be ScannerEngineUnavailable, got {err:?}"
        );
    }

    /// A FAILED job (report 500) means the engine ran and broke: fail closed
    /// with Internal, NOT the graceful unavailable path.
    #[tokio::test]
    async fn test_job_failed_500_is_internal_fail_closed() {
        let server = MockServer::start().await;
        mount_fs_ready_and_submit(&server, "fs-fail").await;
        Mock::given(method("GET"))
            .and(path_regex(r"^/api/v1/filesystem/scan/.+/report$"))
            .respond_with(ResponseTemplate::new(500).set_body_string("scan failed: boom"))
            .mount(&server)
            .await;

        let client = ScannerAdapterFsClient::new(server.uri());
        let err = client.scan_workspace_tar(tiny_tar()).await.unwrap_err();
        assert!(
            matches!(err, AppError::Internal(_)),
            "a failed adapter job must fail the scan closed (Internal), got {err:?}"
        );
    }

    /// An unparseable 200 report body is fail-closed Internal too.
    #[tokio::test]
    async fn test_unparseable_report_is_internal() {
        let server = MockServer::start().await;
        mount_fs_ready_and_submit(&server, "fs-garbled").await;
        Mock::given(method("GET"))
            .and(path_regex(r"^/api/v1/filesystem/scan/.+/report$"))
            .respond_with(ResponseTemplate::new(200).set_body_string("not json"))
            .mount(&server)
            .await;

        let client = ScannerAdapterFsClient::new(server.uri());
        let err = client.scan_workspace_tar(tiny_tar()).await.unwrap_err();
        assert!(
            matches!(err, AppError::Internal(_)),
            "an unparseable report must fail closed, got {err:?}"
        );
    }

    /// A never-ready report exhausts the poll budget and degrades gracefully
    /// (availability), keeping #2324 semantics. The oversized Refresh-After
    /// trips the deadline on the first poll so the test stays fast.
    #[tokio::test]
    async fn test_pending_forever_times_out_as_engine_unavailable() {
        let server = MockServer::start().await;
        mount_fs_ready_and_submit(&server, "fs-pending").await;
        Mock::given(method("GET"))
            .and(path_regex(r"^/api/v1/filesystem/scan/.+/report$"))
            .respond_with(ResponseTemplate::new(302).insert_header("Refresh-After", "100000"))
            .mount(&server)
            .await;

        let client = ScannerAdapterFsClient::new(server.uri());
        let err = client.scan_workspace_tar(tiny_tar()).await.unwrap_err();
        assert!(
            matches!(err, AppError::ScannerEngineUnavailable(_)),
            "poll-budget exhaustion must degrade gracefully, got {err:?}"
        );
    }

    /// An empty scan id would produce a bogus poll URL; reject at submit.
    #[tokio::test]
    async fn test_empty_scan_id_is_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/probe/ready"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/v1/filesystem/scan"))
            .respond_with(ResponseTemplate::new(202).set_body_json(serde_json::json!({"id": ""})))
            .mount(&server)
            .await;

        let client = ScannerAdapterFsClient::new(server.uri());
        let err = client.scan_workspace_tar(tiny_tar()).await.unwrap_err();
        assert!(
            matches!(err, AppError::Internal(_)),
            "an empty scan id must be rejected, got {err:?}"
        );
    }

    // -------------------------------------------------------------------
    // tar_workspace_capped
    // -------------------------------------------------------------------

    /// The tar round-trips regular files under nested directories.
    #[test]
    fn test_tar_workspace_contains_files() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("nested")).unwrap();
        std::fs::write(dir.path().join("nested/go.sum"), b"example v1\n").unwrap();
        std::fs::write(dir.path().join("Cargo.lock"), b"[[package]]\n").unwrap();

        let tar_bytes = tar_workspace_capped(dir.path(), 1024 * 1024).unwrap();

        let mut archive = tar::Archive::new(std::io::Cursor::new(tar_bytes));
        let names: Vec<String> = archive
            .entries()
            .unwrap()
            .map(|e| e.unwrap().path().unwrap().to_string_lossy().to_string())
            .collect();
        assert!(names.iter().any(|n| n == "nested/go.sum"), "{names:?}");
        assert!(names.iter().any(|n| n == "Cargo.lock"), "{names:?}");
    }

    /// Over-cap workspaces degrade to `not_applicable` (availability guard):
    /// the tar is refused BEFORE buffering the tree, and the error variant is
    /// ScannerEngineUnavailable, never a hard failure.
    #[test]
    fn test_tar_workspace_over_cap_is_engine_unavailable() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("big.bin"), vec![0u8; 4096]).unwrap();

        let err = tar_workspace_capped(dir.path(), 1024).unwrap_err();
        assert!(
            matches!(err, AppError::ScannerEngineUnavailable(_)),
            "over-cap must map to ScannerEngineUnavailable, got {err:?}"
        );
    }

    /// Symlinks are archived as links (never followed), so a link pointing
    /// outside the workspace cannot pull host content into the upload.
    #[cfg(unix)]
    #[test]
    fn test_tar_workspace_does_not_follow_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("ok.txt"), b"fine").unwrap();
        std::os::unix::fs::symlink("/etc/hostname", dir.path().join("escape")).unwrap();

        let tar_bytes = tar_workspace_capped(dir.path(), 1024 * 1024).unwrap();

        let mut archive = tar::Archive::new(std::io::Cursor::new(tar_bytes));
        for entry in archive.entries().unwrap() {
            let entry = entry.unwrap();
            if entry.path().unwrap().to_string_lossy() == "escape" {
                assert!(
                    entry.header().entry_type().is_symlink(),
                    "symlink must be archived as a link, not its target"
                );
            }
        }
    }

    /// The env-tunable upload cap falls back to the 64 GiB default.
    #[test]
    fn test_fs_upload_cap_default() {
        // Not set in the test environment -> default.
        assert_eq!(fs_upload_cap_bytes(), DEFAULT_MAX_FS_UPLOAD_BYTES);
    }
}
