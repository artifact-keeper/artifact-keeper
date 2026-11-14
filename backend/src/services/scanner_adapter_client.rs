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
//! * Two of those failures are not the scan's fault and are submitted again
//!   first, up to [`ADAPTER_SCAN_ATTEMPTS`] in all (#5657): an unknown scan id
//!   (the adapter keeps jobs in memory, so a pod replaced mid-scan forgets
//!   them) and a job trivy failed on its cache lock (several image scans at
//!   once on an adapter before 1.7.0). Both clients share that rule
//!   ([`with_adapter_resubmits`]); only after the last attempt does the error
//!   above apply.
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

/// Why a failed scanner-adapter job is submitted again instead of failing the
/// scan (#5657). Shared by the image client (`ImageScanner`) and the
/// filesystem client below; scans only read the artifact, so a resubmission
/// is idempotent -- the adapter assigns a fresh job id and nothing else
/// changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AdapterResubmit {
    /// The report poll answered 404: the adapter no longer knows the job id.
    /// The adapter keeps jobs in memory, so a pod replaced mid-scan (a
    /// `helm upgrade`, an eviction) forgets every job it had accepted.
    UnknownScanId,
    /// The job failed because trivy's on-disk analysis cache was locked by a
    /// concurrent scan ("cache may be in use by another process"). Adapters
    /// before 1.7.0 fail every image scan but one when several run at once.
    CacheBusy,
}

/// What trivy prints when it cannot lock its analysis cache within its own
/// 5s timeout; the adapter passes it through in the failed job's error.
const TRIVY_CACHE_BUSY_MARKER: &str = "cache may be in use by another process";

/// Submissions per scan, the first included.
pub(crate) const ADAPTER_SCAN_ATTEMPTS: u32 = 3;

/// Base delay before resubmitting after a cache-lock failure, doubled per
/// attempt; the lock is held for as long as the other scan runs, so an
/// immediate retry would just collide again. (Tests run on milliseconds.)
#[cfg(not(test))]
const ADAPTER_CACHE_BUSY_BACKOFF: std::time::Duration = std::time::Duration::from_secs(10);
#[cfg(test)]
const ADAPTER_CACHE_BUSY_BACKOFF: std::time::Duration = std::time::Duration::from_millis(10);

/// Delay before resubmitting after an unknown scan id: a replacement pod
/// that answers is already up, so only a short pause.
#[cfg(not(test))]
const ADAPTER_UNKNOWN_ID_BACKOFF: std::time::Duration = std::time::Duration::from_secs(1);
#[cfg(test)]
const ADAPTER_UNKNOWN_ID_BACKOFF: std::time::Duration = std::time::Duration::from_millis(1);

impl AdapterResubmit {
    /// Classify a terminal (non-200, non-302) report response.
    pub(crate) fn classify(status: reqwest::StatusCode, body: &str) -> Option<Self> {
        if status == reqwest::StatusCode::NOT_FOUND {
            return Some(Self::UnknownScanId);
        }
        if status.is_server_error() && body.to_ascii_lowercase().contains(TRIVY_CACHE_BUSY_MARKER) {
            return Some(Self::CacheBusy);
        }
        None
    }

    /// Delay before submission `next_attempt` (2-based).
    fn delay(self, next_attempt: u32) -> std::time::Duration {
        match self {
            Self::UnknownScanId => ADAPTER_UNKNOWN_ID_BACKOFF,
            Self::CacheBusy => {
                ADAPTER_CACHE_BUSY_BACKOFF * 2u32.pow(next_attempt.saturating_sub(2))
            }
        }
    }

    fn describe(self) -> &'static str {
        match self {
            Self::UnknownScanId => {
                "the adapter no longer knows the scan id (restarted or replaced)"
            }
            Self::CacheBusy => "trivy's scan cache was locked by a concurrent scan",
        }
    }
}

/// One submit-and-poll round's failure: the error to surface, and whether
/// the round may be repeated ([`AdapterResubmit`]).
#[derive(Debug)]
pub(crate) struct AdapterAttemptError {
    pub error: AppError,
    pub resubmit: Option<AdapterResubmit>,
}

impl From<AppError> for AdapterAttemptError {
    fn from(error: AppError) -> Self {
        Self {
            error,
            resubmit: None,
        }
    }
}

/// Run `attempt` (readiness, submit, poll) up to [`ADAPTER_SCAN_ATTEMPTS`]
/// times, resubmitting only on an [`AdapterResubmit`] failure (#5657). Any
/// other error, or a resubmittable one on the last attempt, is returned as
/// is, so the error-mapping contracts of both clients are unchanged.
pub(crate) async fn with_adapter_resubmits<T, F, Fut>(label: &str, mut attempt: F) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = std::result::Result<T, AdapterAttemptError>>,
{
    let mut n = 1;
    loop {
        match attempt().await {
            Ok(value) => return Ok(value),
            Err(AdapterAttemptError {
                error,
                resubmit: Some(reason),
            }) if n < ADAPTER_SCAN_ATTEMPTS => {
                n += 1;
                let delay = reason.delay(n);
                tracing::warn!(
                    "{}: {}; resubmitting (attempt {}/{}) in {:?}: {}",
                    label,
                    reason.describe(),
                    n,
                    ADAPTER_SCAN_ATTEMPTS,
                    delay,
                    error
                );
                tokio::time::sleep(delay).await;
            }
            Err(e) => return Err(e.error),
        }
    }
}

/// Response header in which scanner-adapter 1.7.0 and later say where a
/// pending (302) job is (#5657): `Queued` while it waits for one of the
/// adapter's `SCANNER_MAX_CONCURRENT_SCANS` slots, `Running` once trivy runs.
/// Older adapters send no such header; their pending jobs count as running.
pub(crate) const ADAPTER_SCAN_STATUS_HEADER: &str = "X-Scan-Status";

/// Longest a job may wait in the adapter's queue on top of a client's own
/// poll budget. Time spent `Queued` is not charged to that budget, which is
/// sized for one trivy run, so a burst of scans waits for a slot instead of
/// timing out behind the scans ahead of it.
const ADAPTER_QUEUE_BUDGET: std::time::Duration = std::time::Duration::from_secs(30 * 60);

/// How long a report poll keeps retrying while the adapter cannot be reached
/// or answers 502/503/504 (#5657). A `helm upgrade` takes the old pod away
/// before the new one answers; once it does, it answers 404 for the old id
/// and the scan is resubmitted. Beyond this the poll fails as before.
#[cfg(not(test))]
const ADAPTER_RESTART_GRACE: std::time::Duration = std::time::Duration::from_secs(120);
#[cfg(test)]
const ADAPTER_RESTART_GRACE: std::time::Duration = std::time::Duration::from_millis(300);

/// Delay between report polls while the adapter is unreachable.
#[cfg(not(test))]
const ADAPTER_UNREACHABLE_POLL: std::time::Duration = std::time::Duration::from_secs(5);
#[cfg(test)]
const ADAPTER_UNREACHABLE_POLL: std::time::Duration = std::time::Duration::from_millis(20);

/// Whether a report-poll status means the adapter itself is momentarily
/// away (a pod being replaced, a Service with no ready endpoint) rather than
/// an answer about the job.
pub(crate) fn adapter_status_is_unreachable(status: reqwest::StatusCode) -> bool {
    matches!(
        status,
        reqwest::StatusCode::BAD_GATEWAY
            | reqwest::StatusCode::SERVICE_UNAVAILABLE
            | reqwest::StatusCode::GATEWAY_TIMEOUT
    )
}

/// The deadline bookkeeping shared by the image and filesystem report polls
/// (#5657): a run budget that queued time does not consume (bounded by
/// [`ADAPTER_QUEUE_BUDGET`]), and a bounded grace for an adapter that is
/// briefly unreachable.
pub(crate) struct AdapterPollClock {
    label: &'static str,
    run_deadline: std::time::Instant,
    hard_deadline: std::time::Instant,
    unreachable_since: Option<std::time::Instant>,
    queued_logged: bool,
}

impl AdapterPollClock {
    pub(crate) fn new(label: &'static str, budget: std::time::Duration) -> Self {
        let now = std::time::Instant::now();
        Self {
            label,
            run_deadline: now + budget,
            hard_deadline: now + budget + ADAPTER_QUEUE_BUDGET,
            unreachable_since: None,
            queued_logged: false,
        }
    }

    /// The adapter answered 302 with `headers`. Returns how long to wait
    /// before the next poll, or `None` when the budget is spent.
    pub(crate) fn pending(
        &mut self,
        scan_id: &str,
        headers: &reqwest::header::HeaderMap,
        default_wait: std::time::Duration,
    ) -> Option<std::time::Duration> {
        self.pending_at(std::time::Instant::now(), scan_id, headers, default_wait)
    }

    fn pending_at(
        &mut self,
        now: std::time::Instant,
        scan_id: &str,
        headers: &reqwest::header::HeaderMap,
        default_wait: std::time::Duration,
    ) -> Option<std::time::Duration> {
        self.unreachable_since = None;
        let wait = headers
            .get("Refresh-After")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse::<u64>().ok())
            .map(std::time::Duration::from_secs)
            .unwrap_or(default_wait);
        let queued = headers
            .get(ADAPTER_SCAN_STATUS_HEADER)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.trim().eq_ignore_ascii_case("queued"));
        if queued {
            if !self.queued_logged {
                self.queued_logged = true;
                tracing::info!(
                    "{} {} is queued in the scanner-adapter behind other scans",
                    self.label,
                    scan_id
                );
            }
            self.run_deadline = (self.run_deadline + wait).min(self.hard_deadline);
        }
        (now + wait < self.run_deadline).then_some(wait)
    }

    /// The poll could not reach the adapter, or it answered 502/503/504.
    /// Returns how long to wait before polling again, or `None` once the
    /// restart grace or the budget is spent.
    pub(crate) fn unreachable(
        &mut self,
        scan_id: &str,
        detail: &str,
    ) -> Option<std::time::Duration> {
        let now = std::time::Instant::now();
        let since = *self.unreachable_since.get_or_insert(now);
        if now.duration_since(since) >= ADAPTER_RESTART_GRACE
            || now + ADAPTER_UNREACHABLE_POLL >= self.run_deadline
        {
            return None;
        }
        tracing::warn!(
            "{} {}: scanner-adapter unreachable ({}); polling again",
            self.label,
            scan_id,
            detail
        );
        Some(ADAPTER_UNREACHABLE_POLL)
    }
}

/// Env var naming the bearer token the backend sends on every
/// scanner-adapter request (#5948), image and filesystem alike; also read as
/// `TRIVY_ADAPTER_TOKEN_FILE` (a mounted secret, #4142). It matches the
/// adapter's `SCANNER_SCAN_TOKEN` (or one line of its
/// `SCANNER_SCAN_TOKENS_FILE`). The Harbor request body's
/// `registry.authorization` stays the separate image-pull credential.
pub(crate) const ADAPTER_TOKEN_ENV: &str = "TRIVY_ADAPTER_TOKEN";

/// How the backend authenticates to the scanner-adapter. The token is held
/// only as a sensitive header value: `Debug` never prints it, and it is never
/// put in a log line or an error message.
#[derive(Clone)]
pub(crate) enum AdapterAuth {
    /// No token configured: requests carry no `Authorization` header.
    None,
    /// `Authorization: Bearer <token>` on every request.
    Bearer(reqwest::header::HeaderValue),
    /// A token was configured but cannot be used (an unreadable or empty
    /// `TRIVY_ADAPTER_TOKEN_FILE`, or characters a header cannot carry).
    /// Every scan fails at the readiness gate with this reason rather than
    /// going out unauthenticated. The text names the variable and the path,
    /// never the value.
    Unusable(String),
}

impl std::fmt::Debug for AdapterAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => f.write_str("AdapterAuth::None"),
            Self::Bearer(_) => f.write_str("AdapterAuth::Bearer([redacted])"),
            Self::Unusable(why) => write!(f, "AdapterAuth::Unusable({why})"),
        }
    }
}

impl AdapterAuth {
    /// A bearer token. Surrounding whitespace is trimmed; an empty token
    /// means no token.
    pub(crate) fn bearer(token: &str) -> Self {
        let token = token.trim();
        if token.is_empty() {
            return Self::None;
        }
        match reqwest::header::HeaderValue::from_str(&format!("Bearer {token}")) {
            Ok(mut value) => {
                value.set_sensitive(true);
                Self::Bearer(value)
            }
            Err(_) => Self::Unusable(format!(
                "{ADAPTER_TOKEN_ENV} contains characters an HTTP header cannot carry"
            )),
        }
    }

    /// Resolve [`ADAPTER_TOKEN_ENV`] / `TRIVY_ADAPTER_TOKEN_FILE`.
    pub(crate) fn from_env() -> Self {
        Self::resolve(crate::config::secret_or_env(ADAPTER_TOKEN_ENV))
    }

    fn resolve(found: std::result::Result<Option<String>, String>) -> Self {
        let auth = match found {
            Ok(Some(token)) => Self::bearer(&token),
            Ok(None) => Self::None,
            Err(why) => Self::Unusable(why),
        };
        if let Self::Unusable(why) = &auth {
            tracing::error!("scanner-adapter token unusable; adapter scans will fail: {why}");
        }
        auth
    }

    /// Add the header to every request a client built from `builder` sends.
    pub(crate) fn apply(&self, builder: reqwest::ClientBuilder) -> reqwest::ClientBuilder {
        match self {
            Self::Bearer(value) => {
                let mut headers = reqwest::header::HeaderMap::new();
                headers.insert(reqwest::header::AUTHORIZATION, value.clone());
                builder.default_headers(headers)
            }
            Self::None | Self::Unusable(_) => builder,
        }
    }

    /// The reason scans cannot be sent, if a configured token is unusable.
    pub(crate) fn unusable(&self) -> Option<&str> {
        match self {
            Self::Unusable(why) => Some(why),
            _ => None,
        }
    }
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

/// One completed adapter filesystem scan: trivy's native report, its stderr
/// (partial-scan signal, #1153) and the vulnerability DB the adapter says
/// this very scan ran against (#3014). The DB travels with the report it
/// describes rather than through a shared slot, so concurrent scans cannot
/// be stamped with each other's DB vintage.
pub(crate) struct AdapterFsScan {
    pub report: TrivyReport,
    pub stderr: String,
    pub vuln_db: Option<crate::models::security::VulnDbProvenance>,
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
    /// adapter-reported scanner version for [`Self::version`]. The
    /// vulnerability DB is returned with the report (#3014).
    pub async fn scan_dir_via_adapter(
        &self,
        client: &ScannerAdapterFsClient,
        dir: &Path,
        cap_bytes: u64,
    ) -> Result<AdapterFsScan> {
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
        let vuln_db = crate::services::scanner_service::AdapterVulnDb::lenient(
            body.vulnerability_db.as_ref(),
        );
        Ok(AdapterFsScan {
            report: body.report,
            stderr: body.stderr,
            vuln_db,
        })
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
    /// Trivy vulnerability-DB metadata the scan ran against (#3014); absent
    /// from adapters older than this field. Kept as raw JSON and parsed
    /// leniently: best-effort provenance must never fail the scan.
    #[serde(default)]
    pub vulnerability_db: Option<serde_json::Value>,
}

#[derive(Debug, serde::Deserialize)]
struct FsScanSubmitResponse {
    id: String,
}

/// Filesystem-scan client for the scanner-adapter. See the module docs for
/// the error-mapping contract.
pub(crate) struct ScannerAdapterFsClient {
    adapter_url: String,
    /// Bearer token sent on every request (#5948).
    auth: AdapterAuth,
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
        Self::with_auth(adapter_url, AdapterAuth::from_env())
    }

    /// Build a client that authenticates with `auth` (#5948).
    pub(crate) fn with_auth(adapter_url: String, auth: AdapterAuth) -> Self {
        Self {
            adapter_url,
            http: auth
                .apply(crate::services::http_client::internal_service_client_builder())
                // Generous: the body is the tarred workspace, potentially GBs
                // for an incus rootfs.
                .timeout(std::time::Duration::from_secs(900))
                .build()
                .unwrap_or_default(),
            poll_http: auth
                .apply(crate::services::http_client::internal_service_client_builder())
                .redirect(reqwest::redirect::Policy::none())
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .unwrap_or_default(),
            auth,
        }
    }

    /// Upload a tarred workspace and wait for trivy's native report.
    /// The single public entry point: readiness gate, submit, poll -- again,
    /// with the same tar, when the adapter lost the job or trivy's cache
    /// lock failed it (#5657).
    pub async fn scan_workspace_tar(&self, tar: Vec<u8>) -> Result<FsScanReportBody> {
        let tar = bytes::Bytes::from(tar);
        let (this, tar) = (self, &tar);
        with_adapter_resubmits("Scanner-adapter filesystem scan", move || async move {
            this.ensure_ready().await?;
            let scan_id = this.submit(tar.clone()).await?;
            this.poll_report(&scan_id).await
        })
        .await
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
        if let Some(why) = self.auth.unusable() {
            return Err(self.unavailable(why));
        }
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
    async fn submit(&self, tar: bytes::Bytes) -> Result<String> {
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
    /// * 302 → pending; honor `Refresh-After`. Time the adapter reports the
    ///   job `Queued` is not charged to the budget ([`AdapterPollClock`]).
    /// * transport error or 502/503/504 → polled again for a bounded grace
    ///   (an adapter being replaced, #5657), then `ScannerEngineUnavailable`.
    /// * budget exhausted → `ScannerEngineUnavailable` (availability).
    /// * any other status (500 failed job, 404 unknown id) → `Internal`
    ///   (the engine ran and broke — fail closed), marked resubmittable when
    ///   it is an unknown id or a cache-lock failure ([`AdapterResubmit`]).
    async fn poll_report(
        &self,
        scan_id: &str,
    ) -> std::result::Result<FsScanReportBody, AdapterAttemptError> {
        let url = format!(
            "{}/api/v1/filesystem/scan/{}/report",
            self.adapter_url, scan_id
        );
        let mut clock = AdapterPollClock::new("Scanner-adapter filesystem scan", Self::POLL_BUDGET);

        loop {
            let resp = match self.poll_http.get(&url).send().await {
                Ok(resp) if !adapter_status_is_unreachable(resp.status()) => resp,
                outcome => {
                    let detail = match outcome {
                        Ok(resp) => format!("report poll answered {}", resp.status()),
                        Err(e) => format!("report poll failed: {}", e),
                    };
                    match clock.unreachable(scan_id, &detail) {
                        Some(wait) => {
                            tokio::time::sleep(wait).await;
                            continue;
                        }
                        None => return Err(self.unavailable(detail).into()),
                    }
                }
            };

            let status = resp.status();
            if status.is_success() {
                return resp.json::<FsScanReportBody>().await.map_err(|e| {
                    AppError::Internal(format!(
                        "Scanner-adapter filesystem report did not parse: {}",
                        e
                    ))
                    .into()
                });
            }
            if status != reqwest::StatusCode::FOUND {
                let text = resp.text().await.unwrap_or_default();
                return Err(AdapterAttemptError {
                    resubmit: AdapterResubmit::classify(status, &text),
                    error: AppError::Internal(format!(
                        "Scanner-adapter filesystem scan {} failed with {}: {}",
                        scan_id, status, text
                    )),
                });
            }

            match clock.pending(scan_id, resp.headers(), Self::POLL_INTERVAL) {
                Some(wait) => tokio::time::sleep(wait).await,
                None => {
                    return Err(self
                        .unavailable(format!(
                            "report for scan {} not ready within the {}s budget",
                            scan_id,
                            Self::POLL_BUDGET.as_secs()
                        ))
                        .into())
                }
            }
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

#[cfg(ak_test_shard = "services-2")]
#[cfg(test)]
mod tests {
    use super::test_support::{mount_fs_ready_and_submit, mount_fs_scan_success};
    use super::*;
    use wiremock::matchers::{method, path, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    // ---- adapter bearer token (#5948) ---------------------------------

    const FS_TOKEN_5948: &str = "tok-5948-fs-9876543210";

    #[test]
    fn test_adapter_auth_resolution_and_redaction() {
        assert!(matches!(AdapterAuth::resolve(Ok(None)), AdapterAuth::None));
        assert!(matches!(AdapterAuth::bearer("   "), AdapterAuth::None));
        let auth = AdapterAuth::resolve(Ok(Some(format!("  {FS_TOKEN_5948}\n"))));
        match &auth {
            AdapterAuth::Bearer(v) => {
                assert!(v.is_sensitive());
                assert_eq!(v.to_str().unwrap(), format!("Bearer {FS_TOKEN_5948}"));
            }
            other => panic!("expected Bearer, got {other:?}"),
        }
        assert!(!format!("{auth:?}").contains(FS_TOKEN_5948));
        let broken = AdapterAuth::resolve(Err(
            "TRIVY_ADAPTER_TOKEN_FILE points at /nope, but the file could not be read".into(),
        ));
        assert!(broken.unusable().unwrap().contains("/nope"));
        let bad = AdapterAuth::bearer("line\nbreak");
        assert!(bad.unusable().is_some());
        assert!(!format!("{bad:?}").contains("break"));
    }

    /// The `_FILE` form (#4142) reaches the header.
    #[test]
    fn test_adapter_token_file_is_read() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("adapter-token");
        std::fs::write(&file, format!("{FS_TOKEN_5948}\n")).unwrap();
        let var = "TEST_ADAPTER_TOKEN_5948";
        // A variable name no other test uses.
        std::env::remove_var(var);
        std::env::set_var(format!("{var}_FILE"), &file);
        let auth = AdapterAuth::resolve(crate::config::secret_or_env(var));
        std::env::remove_var(format!("{var}_FILE"));
        match auth {
            AdapterAuth::Bearer(v) => {
                assert_eq!(v.to_str().unwrap(), format!("Bearer {FS_TOKEN_5948}"))
            }
            other => panic!("expected Bearer, got {other:?}"),
        }
    }

    /// Filesystem scans send the token on the probe, the upload and the
    /// polls; a refused token fails the scan and stays out of the error.
    #[tokio::test]
    async fn test_fs_requests_carry_bearer_token() {
        use wiremock::matchers::header;
        let bearer = format!("Bearer {FS_TOKEN_5948}");
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/probe/ready"))
            .and(header("authorization", bearer.as_str()))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/v1/filesystem/scan"))
            .and(header("authorization", bearer.as_str()))
            .respond_with(ResponseTemplate::new(202).set_body_json(serde_json::json!({"id": "f1"})))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path_regex(r"^/api/v1/filesystem/scan/.+/report$"))
            .and(header("authorization", bearer.as_str()))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"report": {"Results": []}, "stderr": ""})),
            )
            .mount(&server)
            .await;
        ScannerAdapterFsClient::with_auth(server.uri(), AdapterAuth::bearer(FS_TOKEN_5948))
            .scan_workspace_tar(tiny_tar())
            .await
            .expect("an authenticated fs scan must complete");
        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 3);
        for r in &requests {
            assert_eq!(
                r.headers.get("authorization").and_then(|v| v.to_str().ok()),
                Some(bearer.as_str())
            );
        }

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/probe/ready"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/v1/filesystem/scan"))
            .respond_with(ResponseTemplate::new(401).set_body_string("invalid bearer token"))
            .mount(&server)
            .await;
        let err = ScannerAdapterFsClient::with_auth(server.uri(), AdapterAuth::bearer("wrong-one"))
            .scan_workspace_tar(tiny_tar())
            .await
            .expect_err("a refused token fails the fs scan");
        let msg = err.to_string();
        assert!(msg.contains("401"), "{msg}");
        assert!(!msg.contains("wrong-one"), "{msg}");

        let err = ScannerAdapterFsClient::with_auth(
            server.uri(),
            AdapterAuth::Unusable(
                "TRIVY_ADAPTER_TOKEN_FILE points at /x, but the file is empty".into(),
            ),
        )
        .scan_workspace_tar(tiny_tar())
        .await
        .expect_err("an unusable token fails before any request");
        assert!(
            matches!(err, AppError::ScannerEngineUnavailable(_)),
            "{err:?}"
        );
    }

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
            "scanner_version": "0.71.2",
            "vulnerability_db": {"version": 2, "updated_at": "2026-10-04T19:39:34Z"}
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
        // #3014: the wire field name the adapter emits.
        assert_eq!(
            crate::services::scanner_service::AdapterVulnDb::lenient(out.vulnerability_db.as_ref())
                .map(|p| p.version),
            Some("trivy-db-v2".to_string())
        );
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
        // An ordinary failed job is not resubmitted (#5657).
        assert_eq!(fs_posts(&server).await, 1);
    }

    async fn fs_posts(server: &MockServer) -> usize {
        server
            .received_requests()
            .await
            .unwrap_or_default()
            .iter()
            .filter(|r| r.method == wiremock::http::Method::POST)
            .count()
    }

    /// Ready probe + a submit endpoint that hands out `first` once, then
    /// `then` for every later submission.
    async fn mount_fs_two_jobs(server: &MockServer, first: &str, then: &str) {
        Mock::given(method("GET"))
            .and(path("/probe/ready"))
            .respond_with(ResponseTemplate::new(200))
            .mount(server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/v1/filesystem/scan"))
            .respond_with(
                ResponseTemplate::new(202).set_body_json(serde_json::json!({"id": first})),
            )
            .up_to_n_times(1)
            .mount(server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/v1/filesystem/scan"))
            .respond_with(ResponseTemplate::new(202).set_body_json(serde_json::json!({"id": then})))
            .mount(server)
            .await;
    }

    async fn mount_fs_report(server: &MockServer, id: &str, resp: ResponseTemplate) {
        Mock::given(method("GET"))
            .and(path(format!("/api/v1/filesystem/scan/{id}/report")))
            .respond_with(resp)
            .mount(server)
            .await;
    }

    fn ok_fs_report() -> ResponseTemplate {
        ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "report": {"Results": []}, "stderr": ""
        }))
    }

    /// #5657: an adapter replaced mid-scan answers 404 for the id its
    /// predecessor issued; the workspace is uploaded again and the scan
    /// completes.
    #[tokio::test]
    async fn test_unknown_scan_id_is_resubmitted() {
        let server = MockServer::start().await;
        mount_fs_two_jobs(&server, "fs-lost", "fs-new").await;
        mount_fs_report(
            &server,
            "fs-lost",
            ResponseTemplate::new(404).set_body_string("unknown scan id"),
        )
        .await;
        mount_fs_report(&server, "fs-new", ok_fs_report()).await;

        let client = ScannerAdapterFsClient::new(server.uri());
        client
            .scan_workspace_tar(tiny_tar())
            .await
            .expect("a lost scan id must be resubmitted");
        assert_eq!(fs_posts(&server).await, 2);
        // The same workspace both times.
        let bodies: Vec<Vec<u8>> = server
            .received_requests()
            .await
            .unwrap()
            .into_iter()
            .filter(|r| r.method == wiremock::http::Method::POST)
            .map(|r| r.body)
            .collect();
        assert_eq!(bodies[0], bodies[1]);
    }

    /// #5657: a job failed by trivy's cache lock is resubmitted; one that
    /// keeps losing its id gives up after the bounded number of attempts.
    #[tokio::test]
    async fn test_cache_lock_resubmitted_and_attempts_bounded() {
        let server = MockServer::start().await;
        mount_fs_two_jobs(&server, "fs-locked", "fs-ok").await;
        mount_fs_report(
            &server,
            "fs-locked",
            ResponseTemplate::new(500).set_body_string(
                "scan failed: trivy filesystem scan failed: exit status 1: \
                 cache may be in use by another process: timeout",
            ),
        )
        .await;
        mount_fs_report(&server, "fs-ok", ok_fs_report()).await;
        ScannerAdapterFsClient::new(server.uri())
            .scan_workspace_tar(tiny_tar())
            .await
            .expect("a cache-lock failure must be resubmitted");
        assert_eq!(fs_posts(&server).await, 2);

        let server = MockServer::start().await;
        mount_fs_ready_and_submit(&server, "fs-gone").await;
        Mock::given(method("GET"))
            .and(path_regex(r"^/api/v1/filesystem/scan/.+/report$"))
            .respond_with(ResponseTemplate::new(404).set_body_string("unknown scan id"))
            .mount(&server)
            .await;
        let err = ScannerAdapterFsClient::new(server.uri())
            .scan_workspace_tar(tiny_tar())
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::Internal(_)), "{err:?}");
        assert_eq!(fs_posts(&server).await, ADAPTER_SCAN_ATTEMPTS as usize);
    }

    /// #5657: time the adapter reports a job `Queued` is not charged to the
    /// run budget (bounded by the queue budget); a `Running` or unlabelled
    /// pending answer is.
    #[test]
    fn test_poll_clock_does_not_charge_queued_time() {
        use reqwest::header::{HeaderMap, HeaderValue};
        use std::time::{Duration, Instant};
        let headers = |refresh: &str, state: Option<&str>| {
            let mut h = HeaderMap::new();
            h.insert("Refresh-After", HeaderValue::from_str(refresh).unwrap());
            if let Some(state) = state {
                h.insert(
                    ADAPTER_SCAN_STATUS_HEADER,
                    HeaderValue::from_str(state).unwrap(),
                );
            }
            h
        };
        let budget = Duration::from_secs(10);
        let fallback = Duration::from_secs(5);
        // Polls `clock` with `h` on a simulated wall clock that advances by
        // each granted wait; returns how many waits were granted.
        let granted = |clock: &mut AdapterPollClock, h: &HeaderMap, limit: usize| {
            let mut now = Instant::now();
            let mut n = 0;
            while let Some(wait) = clock.pending_at(now, "id", h, fallback) {
                now += wait;
                n += 1;
                if n == limit {
                    break;
                }
            }
            n
        };

        // A 60s wait overruns a 10s budget for a running job...
        let mut clock = AdapterPollClock::new("t", budget);
        assert_eq!(granted(&mut clock, &headers("60", Some("Running")), 100), 0);
        let mut clock = AdapterPollClock::new("t", budget);
        assert_eq!(granted(&mut clock, &headers("60", None), 100), 0);
        // ...but a queued job is granted 60s waits until the 30-minute queue
        // budget is spent: 30 of them, not one more.
        let mut clock = AdapterPollClock::new("t", budget);
        assert_eq!(granted(&mut clock, &headers("60", Some("queued")), 100), 30);
        // Without a Refresh-After the client's own 5s interval applies; a
        // second wait would end on the 10s deadline, so only one.
        let mut clock = AdapterPollClock::new("t", budget);
        assert_eq!(granted(&mut clock, &HeaderMap::new(), 100), 1);
    }

    /// #5657: a `helm upgrade` takes the adapter away mid-scan (its Service
    /// answers 503), then the replacement pod answers 404 for the old id. The
    /// poll rides out the gap, the scan is resubmitted, and it completes.
    #[tokio::test]
    async fn test_adapter_replaced_mid_scan_is_polled_through_and_resubmitted() {
        let server = MockServer::start().await;
        mount_fs_two_jobs(&server, "fs-old-pod", "fs-new-pod").await;
        Mock::given(method("GET"))
            .and(path("/api/v1/filesystem/scan/fs-old-pod/report"))
            .respond_with(ResponseTemplate::new(503))
            .up_to_n_times(3)
            .mount(&server)
            .await;
        mount_fs_report(
            &server,
            "fs-old-pod",
            ResponseTemplate::new(404).set_body_string("unknown scan id"),
        )
        .await;
        mount_fs_report(&server, "fs-new-pod", ok_fs_report()).await;

        ScannerAdapterFsClient::new(server.uri())
            .scan_workspace_tar(tiny_tar())
            .await
            .expect("an adapter replaced mid-scan must not fail the scan");
        assert_eq!(fs_posts(&server).await, 2);
    }

    /// An adapter that stays away past the restart grace still fails the
    /// scan as unavailable, with no resubmission.
    #[tokio::test]
    async fn test_adapter_unreachable_past_grace_is_unavailable() {
        let server = MockServer::start().await;
        mount_fs_ready_and_submit(&server, "fs-gone").await;
        Mock::given(method("GET"))
            .and(path_regex(r"^/api/v1/filesystem/scan/.+/report$"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;
        let err = ScannerAdapterFsClient::new(server.uri())
            .scan_workspace_tar(tiny_tar())
            .await
            .unwrap_err();
        assert!(
            matches!(err, AppError::ScannerEngineUnavailable(_)),
            "{err:?}"
        );
        assert_eq!(fs_posts(&server).await, 1);
    }

    #[test]
    fn test_adapter_resubmit_classification() {
        use reqwest::StatusCode;
        assert_eq!(
            AdapterResubmit::classify(StatusCode::NOT_FOUND, "unknown scan id"),
            Some(AdapterResubmit::UnknownScanId)
        );
        assert_eq!(
            AdapterResubmit::classify(
                StatusCode::INTERNAL_SERVER_ERROR,
                "scan failed: ... Cache may be in use by another process: timeout"
            ),
            Some(AdapterResubmit::CacheBusy)
        );
        assert_eq!(
            AdapterResubmit::classify(StatusCode::INTERNAL_SERVER_ERROR, "scan failed: boom"),
            None
        );
        assert_eq!(
            AdapterResubmit::classify(
                StatusCode::BAD_REQUEST,
                "cache may be in use by another process"
            ),
            None
        );
        // Backoff grows for the lock, stays short for a lost id.
        assert!(AdapterResubmit::CacheBusy.delay(3) > AdapterResubmit::CacheBusy.delay(2));
        assert_eq!(
            AdapterResubmit::UnknownScanId.delay(3),
            AdapterResubmit::UnknownScanId.delay(2)
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
