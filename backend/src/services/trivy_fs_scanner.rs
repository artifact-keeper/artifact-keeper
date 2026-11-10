//! Trivy filesystem scanner for non-container artifacts.
//!
//! Writes artifact content to a scan workspace directory, optionally extracts
//! archives, and runs `trivy filesystem` over the prepared workspace — either
//! by spawning the local CLI (legacy `TRIVY_URL` deployments that bundle the
//! binary) or, on the hardened CLI-free image, by tarring the workspace and
//! uploading it to the scanner-adapter's filesystem endpoint (#2363).

use async_trait::async_trait;
use bytes::Bytes;
use std::path::Path;
use tracing::{info, warn};

use crate::error::{AppError, Result};
use crate::models::artifact::{Artifact, ArtifactMetadata};
use crate::services::image_scanner::TrivyReport;
use crate::services::scanner_adapter_client::{fs_upload_cap_bytes, TrivyEngine, TrivyFsBackend};
use crate::services::scanner_service::{
    fail_scan, ExpectedComponent, ScanOutput, ScanTarget, ScanWorkspace, Scanner, VersionCache,
};
// `ScanCompleteness` is used via `output.scan_completeness.as_str()` in the
// info!() log line below.

/// Filesystem-based Trivy scanner for packages, libraries, and archives.
pub struct TrivyFsScanner {
    engine: TrivyEngine,
    scan_workspace: String,
    /// Lazily-probed version string from `trivy --version`, e.g.
    /// `trivy-0.62.1`. Successful probes are cached for an hour so each scan
    /// does not pay an extra subprocess; failed probes expire after 60s so
    /// the field starts populating once the binary becomes available. Only
    /// meaningful in CLI mode.
    cached_version: VersionCache,
}

impl TrivyFsScanner {
    /// Legacy CLI mode: spawn the bundled `trivy` binary, trying
    /// `--server <trivy_url>` then standalone.
    pub fn new(trivy_url: String, scan_workspace: String) -> Self {
        Self {
            engine: TrivyEngine::cli(trivy_url),
            scan_workspace,
            cached_version: VersionCache::new(),
        }
    }

    /// Adapter mode (#2363): tar the prepared workspace and upload it to the
    /// scanner-adapter at `adapter_url`. No local `trivy` binary needed.
    pub fn new_with_adapter(adapter_url: String, scan_workspace: String) -> Self {
        Self {
            engine: TrivyEngine::adapter(adapter_url),
            scan_workspace,
            cached_version: VersionCache::new(),
        }
    }

    /// Returns true if this scanner is applicable to the given artifact.
    /// Container image manifests are handled by `ImageScanner`; everything
    /// else that looks like a scannable package is handled here.
    pub fn is_applicable(artifact: &Artifact) -> bool {
        // Skip OCI / Docker image manifests — those belong to ImageScanner.
        if crate::services::scanner_service::is_oci_image_artifact(artifact) {
            return false;
        }

        // Use the original filename from the path for extension detection
        let original_filename = artifact.path.rsplit('/').next().unwrap_or(&artifact.name);
        let name_lower = original_filename.to_lowercase();
        let scannable_extensions = [
            ".tar.gz", ".tgz", ".whl", ".jar", ".war", ".ear", ".gem", ".crate", ".nupkg", ".zip",
            ".deb", ".rpm", ".apk", ".egg", ".pex",
            // Lock files and manifests that Trivy can parse directly
            ".lock", ".toml", ".json", ".xml", ".txt", ".cfg", ".ini",
        ];

        scannable_extensions
            .iter()
            .any(|ext| name_lower.ends_with(ext))
    }

    /// Run Trivy filesystem scan, optionally connecting to a server.
    /// When `server_url` is Some, `--server <url>` is added to the command.
    ///
    /// Returns `(report, stderr_text)`. Trivy's stderr is captured even on
    /// success so the caller can detect the partial-scan signal (#1153):
    /// a malformed lockfile makes Trivy log a warning and skip the target
    /// without failing the process, and the empty Packages block that
    /// results is indistinguishable from "no lockfile present" without
    /// the stderr text.
    async fn run_trivy(
        &self,
        workspace: &Path,
        server_url: Option<&str>,
    ) -> Result<(TrivyReport, String)> {
        let ws = workspace.to_string_lossy();
        // #903: `--list-all-pkgs` enumerates every package the scanner saw
        // (not just CVE-bearing rows) so SBOM generation reflects the
        // complete dependency tree; `convert_trivy_packages` reads the
        // `Packages` block it adds to the JSON report.
        let args = trivy_filesystem_args(&ws, server_url, "5m", true);

        let mode_label = if server_url.is_some() {
            "server"
        } else {
            "standalone"
        };

        let output = trivy_cli_command()
            .args(&args)
            .output()
            .await
            .map_err(|e| crate::services::scanner_service::classify_trivy_spawn_error(&e))?;

        let stderr_text = String::from_utf8_lossy(&output.stderr).to_string();

        if !output.status.success() {
            if server_url.is_some()
                && (stderr_text.contains("not found") || stderr_text.contains("No such file"))
            {
                return Err(AppError::Internal("Trivy CLI not available".to_string()));
            }
            return Err(AppError::Internal(format!(
                "Trivy {} scan failed (exit {}): {}",
                mode_label, output.status, stderr_text
            )));
        }

        let report: TrivyReport = serde_json::from_slice(&output.stdout)
            .map_err(|e| AppError::Internal(format!("Failed to parse Trivy output: {}", e)))?;
        Ok((report, stderr_text))
    }

    /// CLI path: try server mode against `trivy_url`, then standalone.
    async fn run_cli(
        &self,
        workspace: &Path,
        trivy_url: &str,
        artifact_name: &str,
    ) -> Result<(TrivyReport, String)> {
        match self.run_trivy(workspace, Some(trivy_url)).await {
            Ok(out) => Ok(out),
            Err(e) => {
                warn!(
                    "Trivy server-mode CLI failed for {}: {}. Trying standalone mode.",
                    artifact_name, e
                );
                self.run_trivy(workspace, None).await
            }
        }
    }
}

/// Lockfile / manifest basenames that Trivy parses when invoked with
/// `filesystem` mode. If one of these is present in the scan workspace
/// but absent from the Trivy report's `results[].target` list, the scan
/// is treated as partial (#1153). The list mirrors the file types Trivy
/// claims to handle in `pkg/dependency/parser/`.
const TRIVY_KNOWN_TARGETS: &[&str] = &[
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "requirements.txt",
    "Pipfile.lock",
    "poetry.lock",
    "Gemfile.lock",
    "go.mod",
    "go.sum",
    "Cargo.lock",
    "composer.lock",
    "packages.lock.json",
    "pubspec.lock",
    "mix.lock",
    "conan.lock",
    "pom.xml",
];

/// List the basenames of lockfile/manifest files present in the workspace.
/// Used to feed [`ScanOutput::from_trivy_report_with_context`]'s
/// known-targets check (#1153). Errors are swallowed — an unreadable
/// directory simply yields an empty list, which collapses the partial-
/// scan check to "use stderr only".
fn workspace_known_targets(workspace: &Path) -> Vec<&'static str> {
    let mut hits: Vec<&'static str> = Vec::new();
    let walker = walkdir::WalkDir::new(workspace)
        .max_depth(8)
        .into_iter()
        .filter_map(|e| e.ok());
    for entry in walker {
        if !entry.file_type().is_file() {
            continue;
        }
        if let Some(name) = entry.file_name().to_str() {
            if let Some(known) = TRIVY_KNOWN_TARGETS.iter().find(|k| **k == name) {
                if !hits.contains(known) {
                    hits.push(*known);
                }
            }
        }
    }
    hits
}

/// Environment for every local `trivy` CLI run (#5666). Without it each run
/// calls `check.trivy.dev` for a version check and sends an anonymous
/// telemetry header set, whatever else the scan is told about the network.
/// Environment rather than `--skip-version-check` / `--disable-telemetry`
/// because the legacy CLI path runs whatever trivy the operator installed:
/// a release older than those flags ignores an unknown `TRIVY_*` variable
/// but rejects an unknown flag and would fail every scan.
pub(crate) const TRIVY_CLI_NO_PHONE_HOME_ENV: &[(&str, &str)] = &[
    ("TRIVY_SKIP_VERSION_CHECK", "true"),
    ("TRIVY_DISABLE_TELEMETRY", "true"),
];

/// A `trivy` command with the #5666 environment applied and `kill_on_drop`
/// set. `tokio::process::Command` defaults `kill_on_drop` to `false`; these
/// scans run inside the caller's inline-proxy-gate timeout, and when that
/// fires it drops the future -- without the flag the trivy child is
/// ORPHANED and keeps running unsupervised (#3455, same as the grype spawn).
pub(crate) fn trivy_cli_command() -> tokio::process::Command {
    let mut command = tokio::process::Command::new("trivy");
    command.kill_on_drop(true);
    command.envs(TRIVY_CLI_NO_PHONE_HOME_ENV.iter().copied());
    command
}

/// Arguments for a local `trivy filesystem` scan of `target`, shared by this
/// scanner and the Incus rootfs scanner.
///
/// `--offline-scan` is unconditional (#5666). Without it trivy's `pom.xml`
/// parser fetches parent POMs and unpinned dependency versions from
/// `repo.maven.apache.org` for every POM in the workspace -- every extracted
/// jar carries one under `META-INF/maven/` -- so a scan failed outright on
/// an air-gapped install, bypassed AK's own proxy, and disclosed the
/// artifact's dependency coordinates to Maven Central. What the remote
/// lookup recovered was the version a parent or BOM *manages*, not the one
/// the archive bundles; the bundled versions are cataloged offline from the
/// jars' own `pom.properties` ([`write_embedded_jar_inventory`]).
pub(crate) fn trivy_filesystem_args<'a>(
    target: &'a str,
    server_url: Option<&'a str>,
    timeout: &'a str,
    list_all_pkgs: bool,
) -> Vec<&'a str> {
    let mut args = vec!["filesystem"];
    if let Some(url) = server_url {
        args.push("--server");
        args.push(url);
    }
    args.extend_from_slice(&[
        "--format",
        "json",
        // #3296: the shared allowlist includes UNKNOWN so ungraded CVEs
        // reach the report instead of being dropped at the CLI.
        "--severity",
        crate::services::scanner_service::TRIVY_FS_SEVERITY_LIST,
    ]);
    if list_all_pkgs {
        args.push("--list-all-pkgs");
    }
    args.extend_from_slice(&["--offline-scan", "--quiet", "--timeout", timeout, target]);
    args
}

/// Workspace subdirectory holding the synthesized Maven inventory (#5666).
/// Dot-prefixed and fixed, like the component-pin directory, so an archive
/// entry cannot be mistaken for it: the walk that builds the inventory skips
/// it, and a shipped file at the same path is overwritten.
pub(crate) const JAR_INVENTORY_SUBDIR: &str = ".ak-scan-jar-inventory";

/// The inventory POM's own coordinate. trivy reports it as the `root`
/// package of the inventory target; it names nothing real, so it is removed
/// from the report before conversion ([`strip_jar_inventory_root`]).
const JAR_INVENTORY_ROOT_GROUP: &str = "artifact-keeper.scan";
const JAR_INVENTORY_ROOT_ARTIFACT: &str = "embedded-jars";

/// Bounds for the inventory walk. A fat jar bundles a few hundred libraries;
/// the ceilings exist so a hostile archive cannot turn the walk into a
/// resource sink, and hitting one only truncates the inventory.
const JAR_INVENTORY_MAX_DEPTH: usize = 16;
const JAR_INVENTORY_MAX_ARCHIVES: usize = 10_000;
const JAR_INVENTORY_MAX_COORDINATES: usize = 10_000;
/// Entries per archive whose names are examined.
const JAR_INVENTORY_MAX_ENTRIES: usize = 1_000_000;
/// A `pom.properties` is a few hundred bytes.
const JAR_INVENTORY_POM_PROPERTIES_MAX_BYTES: u64 = 64 * 1024;
/// A jar nested inside a jar on disk is read into memory, one level deep,
/// when it is no larger than this; the total read that way is capped too.
const JAR_INVENTORY_NESTED_MAX_BYTES: u64 = 64 * 1024 * 1024;
const JAR_INVENTORY_NESTED_TOTAL_BYTES: u64 = 1024 * 1024 * 1024;

/// One Maven coordinate read from a bundled `pom.properties`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct MavenCoordinate {
    pub(crate) group_id: String,
    pub(crate) artifact_id: String,
    pub(crate) version: String,
}

/// Maven-legal identifier characters. Anything else -- including the XML
/// metacharacters the inventory POM would otherwise have to escape, and a
/// `${...}` property reference -- disqualifies the coordinate.
fn is_maven_token(value: &str, extra: &[char]) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.chars().all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') || extra.contains(&c)
        })
}

impl MavenCoordinate {
    fn from_pom_properties(body: &[u8]) -> Option<Self> {
        let text = std::str::from_utf8(body).ok()?;
        let (group_id, artifact_id, version) =
            crate::services::scanner_service::parse_pom_properties(text)?;
        (is_maven_token(&group_id, &[])
            && is_maven_token(&artifact_id, &[])
            && is_maven_token(&version, &['+']))
        .then_some(Self {
            group_id,
            artifact_id,
            version,
        })
    }
}

/// Whether `name` is a `META-INF/maven/<groupId>/<artifactId>/pom.properties`
/// path, the file Maven's archiver writes for each packaged project.
fn is_pom_properties_path(name: &str) -> bool {
    let parts: Vec<&str> = name.split('/').collect();
    matches!(
        parts.as_slice(),
        ["META-INF", "maven", g, a, "pom.properties"] if !g.is_empty() && !a.is_empty()
    )
}

fn is_jvm_archive_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.ends_with(".jar") || lower.ends_with(".war") || lower.ends_with(".ear")
}

/// Accumulates coordinates under the walk's ceilings.
#[derive(Default)]
struct JarInventory {
    coordinates: std::collections::BTreeSet<MavenCoordinate>,
    archives_seen: usize,
    nested_bytes: u64,
}

impl JarInventory {
    fn full(&self) -> bool {
        self.coordinates.len() >= JAR_INVENTORY_MAX_COORDINATES
    }

    fn add(&mut self, body: &[u8]) {
        if self.full() {
            return;
        }
        if let Some(coordinate) = MavenCoordinate::from_pom_properties(body) {
            self.coordinates.insert(coordinate);
        }
    }

    /// Read every `pom.properties` in a JVM archive and, when `nested` is
    /// set, in each JVM archive stored inside it. Unreadable archives and
    /// entries are skipped: the inventory is best-effort.
    fn read_archive<R: std::io::Read + std::io::Seek>(&mut self, reader: R, nested: bool) {
        use std::io::Read as _;

        if self.archives_seen >= JAR_INVENTORY_MAX_ARCHIVES {
            return;
        }
        self.archives_seen += 1;
        let Ok(mut archive) = zip::ZipArchive::new(reader) else {
            return;
        };
        for i in 0..archive.len().min(JAR_INVENTORY_MAX_ENTRIES) {
            if self.full() {
                return;
            }
            // Match on the central-directory name before opening the entry,
            // so unmatched entries are never inflated.
            let Some(Ok(name)) = archive.name_for_index(i) else {
                continue;
            };
            let is_props = is_pom_properties_path(&name);
            let is_nested = nested && is_jvm_archive_name(&name);
            if !is_props && !is_nested {
                continue;
            }
            let Ok(entry) = archive.by_index(i) else {
                continue;
            };
            if !entry.is_file() {
                continue;
            }
            let cap = if is_props {
                JAR_INVENTORY_POM_PROPERTIES_MAX_BYTES
            } else {
                JAR_INVENTORY_NESTED_MAX_BYTES
                    .min(JAR_INVENTORY_NESTED_TOTAL_BYTES.saturating_sub(self.nested_bytes))
            };
            if entry.size() > cap {
                continue;
            }
            let mut body = Vec::new();
            if entry.take(cap + 1).read_to_end(&mut body).is_err() || body.len() as u64 > cap {
                continue;
            }
            if is_props {
                self.add(&body);
            } else {
                self.nested_bytes += body.len() as u64;
                self.read_archive(std::io::Cursor::new(body), false);
            }
        }
    }
}

/// The Maven coordinates a JVM archive held in memory carries (#5666): every
/// `pom.properties` entry in it, and in each `.jar`/`.war`/`.ear` stored
/// inside it one level down (a fat jar's `BOOT-INF/lib/`, a war's
/// `WEB-INF/lib/`). Same validation and ceilings as the workspace walk; an
/// unreadable archive yields nothing. Used by the dependency scanner, which
/// sees the artifact's bytes rather than an extracted workspace.
pub(crate) fn maven_coordinates_in_archive(content: &[u8]) -> Vec<MavenCoordinate> {
    let mut inventory = JarInventory::default();
    inventory.read_archive(std::io::Cursor::new(content), true);
    inventory.coordinates.into_iter().collect()
}

/// Collect the Maven coordinates bundled under `root`: loose
/// `META-INF/maven/*/*/pom.properties` files (an extracted archive) and the
/// `pom.properties` entries of every `.jar`/`.war`/`.ear` on disk, plus the
/// jars nested one level inside those (a fat jar the workspace could not
/// extract). Symlinks are not followed.
fn collect_embedded_maven_coordinates(root: &Path) -> Vec<MavenCoordinate> {
    let mut inventory = JarInventory::default();
    let walker = walkdir::WalkDir::new(root)
        .max_depth(JAR_INVENTORY_MAX_DEPTH)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| e.depth() != 1 || e.file_name() != JAR_INVENTORY_SUBDIR)
        .filter_map(|e| e.ok());
    for entry in walker {
        if inventory.full() {
            break;
        }
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        let rel = path
            .strip_prefix(root)
            .ok()
            .and_then(|p| p.to_str())
            .unwrap_or_default();
        let name = entry.file_name().to_string_lossy();
        if rel.ends_with("pom.properties")
            && rel
                .match_indices("META-INF/maven/")
                .any(|(i, _)| is_pom_properties_path(&rel[i..]))
        {
            let mut body = Vec::new();
            if std::fs::File::open(path)
                .and_then(|f| {
                    std::io::Read::read_to_end(
                        &mut std::io::Read::take(f, JAR_INVENTORY_POM_PROPERTIES_MAX_BYTES + 1),
                        &mut body,
                    )
                })
                .is_ok()
                && body.len() as u64 <= JAR_INVENTORY_POM_PROPERTIES_MAX_BYTES
            {
                inventory.add(&body);
            }
        } else if is_jvm_archive_name(&name) {
            if let Ok(file) = std::fs::File::open(path) {
                inventory.read_archive(std::io::BufReader::new(file), true);
            }
        }
    }
    inventory.coordinates.into_iter().collect()
}

/// The inventory POM: one `<dependency>` per bundled coordinate, each with a
/// literal version, so trivy's `pom.xml` analyzer catalogs and grades them
/// with no remote resolution at all. Every value has passed
/// [`is_maven_token`], so nothing in it needs XML escaping.
fn render_jar_inventory_pom(coordinates: &[MavenCoordinate]) -> String {
    let mut pom = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!-- Synthesized by Artifact Keeper from the pom.properties of the \
         archives bundled in this artifact (#5666). -->\n\
         <project xmlns=\"http://maven.apache.org/POM/4.0.0\">\n  \
         <modelVersion>4.0.0</modelVersion>\n  \
         <groupId>{JAR_INVENTORY_ROOT_GROUP}</groupId>\n  \
         <artifactId>{JAR_INVENTORY_ROOT_ARTIFACT}</artifactId>\n  \
         <version>0</version>\n  <packaging>pom</packaging>\n  <dependencies>\n"
    );
    for c in coordinates {
        pom.push_str(&format!(
            "    <dependency><groupId>{}</groupId><artifactId>{}</artifactId>\
             <version>{}</version></dependency>\n",
            c.group_id, c.artifact_id, c.version
        ));
    }
    pom.push_str("  </dependencies>\n</project>\n");
    pom
}

/// Write `<workspace>/.ak-scan-jar-inventory/pom.xml` naming every Maven
/// coordinate bundled in the workspace (#5666), and return how many it names
/// (0 writes nothing).
///
/// `trivy filesystem` does not open `.jar` files at all -- its jar analyzer
/// runs only for image and rootfs targets, and needs the Java DB there -- so
/// a fat jar's `BOOT-INF/lib/*.jar` (or a war's `WEB-INF/lib/*.jar`) was
/// never cataloged, and the only Java input trivy saw was the outer
/// project's `pom.xml`, resolved against Maven Central. This file hands the
/// bundled libraries to the analyzer trivy does run on a filesystem, with
/// the versions the archive actually ships. Best-effort: a failure is
/// logged and the scan proceeds as it did before.
pub(crate) async fn write_embedded_jar_inventory(workspace: &Path) -> usize {
    let root = workspace.to_path_buf();
    let coordinates = match tokio::task::spawn_blocking(move || {
        collect_embedded_maven_coordinates(&root)
    })
    .await
    {
        Ok(c) => c,
        Err(e) => {
            warn!("Embedded jar inventory walk failed: {}", e);
            return 0;
        }
    };
    if coordinates.is_empty() {
        return 0;
    }
    let dir = workspace.join(JAR_INVENTORY_SUBDIR);
    let pom = dir.join("pom.xml");
    // A shipped entry at the inventory path (a file or link where the
    // directory goes, a directory or link where the pom goes, a decoy pom) is
    // removed, never written through or trusted.
    if tokio::fs::symlink_metadata(&dir)
        .await
        .is_ok_and(|m| !m.is_dir())
    {
        let _ = tokio::fs::remove_file(&dir).await;
    }
    match tokio::fs::symlink_metadata(&pom).await {
        Ok(m) if m.is_dir() => {
            let _ = tokio::fs::remove_dir_all(&pom).await;
        }
        Ok(_) => {
            let _ = tokio::fs::remove_file(&pom).await;
        }
        Err(_) => {}
    }
    let written = async {
        tokio::fs::create_dir_all(&dir).await?;
        tokio::fs::write(&pom, render_jar_inventory_pom(&coordinates)).await
    }
    .await;
    match written {
        Ok(()) => coordinates.len(),
        Err(e) => {
            warn!(
                "Could not write the embedded jar inventory into {}: {}",
                dir.display(),
                e
            );
            0
        }
    }
}

/// Remove the inventory POM's own `root` package from the report: it names
/// no real component, and leaving it would put a fabricated package in the
/// SBOM inventory.
fn strip_jar_inventory_root(report: &mut TrivyReport) {
    let root = format!("{JAR_INVENTORY_ROOT_GROUP}:{JAR_INVENTORY_ROOT_ARTIFACT}");
    for result in &mut report.results {
        if !result.target.starts_with(JAR_INVENTORY_SUBDIR) {
            continue;
        }
        if let Some(packages) = result.packages.as_mut() {
            packages.retain(|p| p.name != root);
        }
        if let Some(vulns) = result.vulnerabilities.as_mut() {
            vulns.retain(|v| v.pkg_name != root);
        }
    }
}

#[async_trait]
impl Scanner for TrivyFsScanner {
    fn name(&self) -> &str {
        "trivy-filesystem"
    }

    fn scan_type(&self) -> &str {
        "filesystem"
    }

    /// Surface the inherent applicability check through the trait so the
    /// orchestrator can gate on it without creating a `scan_results` row
    /// (issues #961, #994).
    fn is_applicable(&self, artifact: &Artifact) -> bool {
        Self::is_applicable(artifact)
    }

    /// CLI mode: probe `trivy --version` once and cache the parsed version
    /// string (`None` if the binary is missing). Adapter mode: return the
    /// version the adapter reported on the last successful scan (`None`
    /// until one has run) — there is no local binary to probe.
    async fn version(&self) -> Option<String> {
        self.engine.version(&self.cached_version).await
    }

    async fn scan(
        &self,
        artifact: &Artifact,
        _metadata: Option<&ArtifactMetadata>,
        content: &Bytes,
    ) -> Result<ScanOutput> {
        self.scan_file_pinned(artifact, content, None).await
    }

    /// Forward the caller's component PIN into the workspace (#3603).
    ///
    /// The trait default drops `ScanTarget` and calls [`Self::scan`], so this
    /// scanner used to build an UNPINNED workspace no matter what the
    /// orchestrator had derived. Grype overrode `scan_target` and Trivy did
    /// not, which meant #3442's npm fix — and this issue's four formats —
    /// were inert on exactly the deployments the Helm chart produces, where
    /// Trivy is the engine. Same pin, same workspace layout; the orchestrator
    /// applies the same pin-scoped `dedupe_findings` to whatever any scanner
    /// returns, so no double counting follows from this.
    async fn scan_target(
        &self,
        target: &ScanTarget<'_>,
        _metadata: Option<&ArtifactMetadata>,
        content: &Bytes,
    ) -> Result<ScanOutput> {
        self.scan_file_pinned(target.artifact, content, target.expected_component)
            .await
    }
}

impl TrivyFsScanner {
    /// Filesystem scan with an optional component PIN materialized into the
    /// workspace (#3003/#3442/#3603), mirroring `GrypeScanner::scan_file_pinned`.
    ///
    /// `pin: None` (legacy callers, unit tests, formats with no pin) writes no
    /// control files and keeps the previous flat workspace exactly.
    async fn scan_file_pinned(
        &self,
        artifact: &Artifact,
        content: &Bytes,
        pin: Option<&ExpectedComponent>,
    ) -> Result<ScanOutput> {
        // The orchestrator gates on `is_applicable` (issues #961, #994), so
        // by the time we get here the artifact should match. Keep a
        // defensive assertion so a future caller bypassing the orchestrator
        // does not silently smuggle a non-applicable artifact through.
        debug_assert!(
            Self::is_applicable(artifact),
            "TrivyFsScanner::scan called on a non-applicable artifact; the orchestrator must gate on is_applicable first"
        );

        info!(
            "Starting Trivy filesystem scan for artifact: {} ({})",
            artifact.name, artifact.id
        );

        let mut workspace =
            ScanWorkspace::prepare_pinned(&self.scan_workspace, None, artifact, content, pin)
                .await?;

        // #5666: name the libraries bundled in any JVM archive in the
        // workspace, so trivy grades them offline (it never opens a jar).
        let bundled = write_embedded_jar_inventory(&workspace).await;
        if bundled > 0 {
            info!(
                "Cataloged {} bundled Maven coordinates for {} from their pom.properties",
                bundled, artifact.name
            );
        }

        // Run the scan engine: legacy CLI (server-then-standalone) or the
        // scanner-adapter upload path (#2363). Both yield (report, stderr);
        // errors flow through `fail_scan`, which preserves the
        // `ScannerEngineUnavailable` variant so an absent engine degrades to
        // `not_applicable` (#2324) instead of flooring the grade to F.
        let scan_result = match self.engine.backend() {
            TrivyFsBackend::Cli { trivy_url } => self
                .run_cli(&workspace, trivy_url, &artifact.name)
                .await
                .map(|(report, stderr)| (report, stderr, None)),
            TrivyFsBackend::Adapter(client) => self
                .engine
                .scan_dir_via_adapter(client, &workspace, fs_upload_cap_bytes())
                .await
                .map(|scan| (scan.report, scan.stderr, scan.vuln_db)),
        };
        let (mut report, stderr, vuln_db) = match scan_result {
            Ok(out) => out,
            Err(e) => {
                return Err(
                    fail_scan("Trivy filesystem scan", artifact, &e, Some(&mut workspace)).await,
                );
            }
        };
        strip_jar_inventory_root(&mut report);

        // #1153: enumerate lockfile/manifest files in the workspace so the
        // partial-scan classifier can flag a target Trivy silently skipped.
        // The workspace listing happens after the scan so it is read-only
        // and cannot perturb scanner behaviour.
        let known_targets = workspace_known_targets(&workspace);
        let known_target_refs: Vec<&str> = known_targets.iter().map(|s| *s as &str).collect();
        let mut output = ScanOutput::from_trivy_report_with_context(
            &report,
            "trivy-filesystem",
            &stderr,
            &known_target_refs,
        );
        // #3014: the adapter's DB for this scan (None in CLI mode).
        output.vuln_db = vuln_db;

        info!(
            "Trivy filesystem scan complete for {}: {} vulnerabilities, {} packages, completeness={}",
            artifact.name,
            output.findings.len(),
            output.packages.len(),
            output.scan_completeness.as_str(),
        );

        workspace.cleanup().await;

        Ok(output)
    }
}

#[cfg(ak_test_shard = "services-2")]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::security::Severity;
    use crate::services::scanner_service::test_helpers::make_test_artifact;
    use crate::services::scanner_service::{
        convert_trivy_findings, ComponentEcosystem, GEMFILE_LOCK_NAME, SCAN_PIN_SUBDIR,
    };

    /// #3603: `TrivyFsScanner` must materialize the caller's component pin.
    ///
    /// It inherited the trait's default `scan_target`, which drops
    /// `ScanTarget` and calls `scan`, so it built an UNPINNED workspace no
    /// matter what pin the orchestrator had derived. Only `GrypeScanner`
    /// overrode it — and the Helm chart deploys Trivy as the engine, so
    /// #3442's npm fix and this issue's four formats were inert exactly where
    /// they were needed.
    ///
    /// Asserted without an engine by OBSTRUCTING the pin path: a pinned
    /// workspace has to write `.ak-scan-pin/Gemfile.lock`, and writing onto a
    /// directory fails, so the pinned call aborts at the pin write with a
    /// message naming it. The unpinned control never touches that path and
    /// therefore cannot produce that error — which is precisely the
    /// difference the regression erased. (`prepare_pinned` treats a pin-write
    /// failure as a hard error by design, #3004: silently skipping the pin
    /// would hand back a zero-finding scan of nothing.)
    #[tokio::test]
    async fn test_trivy_scan_target_materializes_the_component_pin() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let base = tmp.path().join("ws-base");
        let artifact = make_test_artifact(
            "rack-2.0.7.gem",
            "application/octet-stream",
            "rack-2.0.7.gem",
        );
        let content = Bytes::from_static(b"not a real gem");

        // Obstruct exactly the path the RubyGems pin wants. The job directory
        // is unique per scan (#4668), so fix this thread's job suffix first.
        crate::services::scanner_service::test_scan_job_suffix::fix("pinned-job");
        let obstruction = ScanWorkspace::job_workspace_dir(base.to_str().unwrap(), None, &artifact)
            .join(SCAN_PIN_SUBDIR)
            .join(GEMFILE_LOCK_NAME);
        std::fs::create_dir_all(&obstruction).expect("obstruct the pin path");

        let scanner = TrivyFsScanner::new(
            "http://127.0.0.1:1".to_string(),
            base.to_string_lossy().into_owned(),
        );
        let pin = ExpectedComponent::new(ComponentEcosystem::RubyGems, "rack", "2.0.7");
        let target = ScanTarget {
            artifact: &artifact,
            repository_key: "gems",
            repository_type: "local",
            db: None,
            storage: None,
            manifest_body: None,
            expected_component: Some(&pin),
            require_nonempty_catalog: false,
            repository_format: None,
        };

        let err = scanner
            .scan_target(&target, None, &content)
            .await
            .expect_err("the obstructed pin write must fail the scan");
        assert!(
            err.to_string()
                .contains("Failed to write scan component pin"),
            "scan_target must route the pin into prepare_pinned; got: {err}"
        );

        // Control: the same bytes with NO pin never write a control file, so
        // the obstruction is irrelevant and the failure comes from elsewhere.
        let err = scanner
            .scan(&artifact, None, &content)
            .await
            .expect_err("no trivy engine is available in the test environment");
        assert!(
            !err.to_string().contains("component pin"),
            "an unpinned scan must fabricate nothing; got: {err}"
        );
    }

    #[test]
    fn test_is_applicable() {
        // Scannable archive formats
        let applicable = [
            (
                "my-lib-1.0.0.tar.gz",
                "application/gzip",
                "pypi/my-lib/1.0.0/my-lib-1.0.0.tar.gz",
            ),
            (
                "my_lib-1.0.0-py3-none-any.whl",
                "application/zip",
                "pypi/my-lib/1.0.0/my_lib-1.0.0-py3-none-any.whl",
            ),
            (
                "myapp-1.0.0.jar",
                "application/java-archive",
                "maven/com/example/myapp/1.0.0/myapp-1.0.0.jar",
            ),
            (
                "my-crate-1.0.0.crate",
                "application/gzip",
                "crates/my-crate/1.0.0/my-crate-1.0.0.crate",
            ),
        ];
        for (name, ct, path) in applicable {
            let a = make_test_artifact(name, ct, path);
            assert!(
                TrivyFsScanner::is_applicable(&a),
                "expected applicable: {}",
                name
            );
        }

        // Container manifests are scanned by the image scanner, not trivy-fs
        let not_applicable = [
            (
                "myapp",
                "application/vnd.oci.image.manifest.v1+json",
                "v2/myapp/manifests/latest",
            ),
            (
                "myapp",
                "application/vnd.docker.distribution.manifest.v2+json",
                "v2/myapp/manifests/v1.0.0",
            ),
        ];
        for (name, ct, path) in not_applicable {
            let a = make_test_artifact(name, ct, path);
            assert!(
                !TrivyFsScanner::is_applicable(&a),
                "expected not applicable: {}",
                name
            );
        }
    }

    #[test]
    fn test_convert_findings() {
        let report = TrivyReport {
            results: vec![crate::services::image_scanner::TrivyResult {
                target: "requirements.txt".to_string(),
                class: "lang-pkgs".to_string(),
                result_type: "pip".to_string(),
                vulnerabilities: Some(vec![crate::services::image_scanner::TrivyVulnerability {
                    vulnerability_id: "CVE-2023-12345".to_string(),
                    pkg_name: "requests".to_string(),
                    installed_version: "2.28.0".to_string(),
                    fixed_version: Some("2.31.0".to_string()),
                    severity: "HIGH".to_string(),
                    title: Some("SSRF in requests".to_string()),
                    description: Some("A vulnerability in requests allows SSRF".to_string()),
                    primary_url: Some("https://avd.aquasec.com/nvd/cve-2023-12345".to_string()),
                }]),
                packages: None,
            }],
        };

        let findings = convert_trivy_findings(&report, "trivy-filesystem");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].cve_id, Some("CVE-2023-12345".to_string()));
        assert_eq!(findings[0].source, Some("trivy-filesystem".to_string()));
        assert!(findings[0]
            .affected_component
            .as_ref()
            .unwrap()
            .contains("requests"));
    }

    /// Scan failures (workspace creation, missing Trivy binary) must
    /// propagate as Err, never as Ok(vec![]).
    #[tokio::test]
    async fn test_scan_propagates_errors() {
        let artifact = make_test_artifact(
            "my-lib-1.0.0.tar.gz",
            "application/gzip",
            "pypi/my-lib/1.0.0/my-lib-1.0.0.tar.gz",
        );
        let content = bytes::Bytes::from_static(b"not a real archive");

        // Impossible workspace path: /dev/null cannot contain subdirectories
        let bad_ws = TrivyFsScanner::new(
            "http://localhost:0".to_string(),
            "/dev/null/impossible-workspace".to_string(),
        );
        assert!(
            bad_ws.scan(&artifact, None, &content).await.is_err(),
            "scan() must return Err when workspace creation fails"
        );

        // Missing trivy binary (skip if trivy is installed)
        if std::process::Command::new("trivy")
            .arg("--version")
            .output()
            .is_ok()
        {
            eprintln!("trivy is installed, skipping unavailable-trivy test");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let no_trivy = TrivyFsScanner::new(
            "http://localhost:0".to_string(),
            dir.path().to_string_lossy().to_string(),
        );
        // A missing trivy CLI must surface as `ScannerEngineUnavailable`
        // (which the orchestrator maps to a terminal `not_applicable` row), NOT
        // a hard scan failure — otherwise fail-closed scoring floors the repo to
        // grade F. Both server and standalone modes spawn-fail with NotFound and
        // `fail_scan` preserves the variant.
        let err = no_trivy
            .scan(&artifact, None, &content)
            .await
            .expect_err("scan() must return Err when the trivy CLI is absent");
        assert!(
            matches!(err, crate::error::AppError::ScannerEngineUnavailable(_)),
            "missing trivy CLI must surface as ScannerEngineUnavailable, got: {err:?}"
        );
    }

    /// Adapter mode end-to-end against a mocked scanner-adapter (#2363): the
    /// scan must surface trivy findings AND a non-empty package inventory
    /// (#903) from the native-JSON round trip, with completeness classified
    /// (#1153) — proving the adapter path does not regress the SBOM data the
    /// Harbor image report would have dropped.
    #[tokio::test]
    async fn test_adapter_scan_yields_findings_and_package_inventory() {
        let server = wiremock::MockServer::start().await;
        crate::services::scanner_adapter_client::test_support::mount_fs_scan_success(
            &server,
            "fs-42",
            serde_json::json!({
                "report": {"Results": [{
                    "Target": "requirements.txt",
                    "Class": "lang-pkgs",
                    "Type": "pip",
                    "Vulnerabilities": [{
                        "VulnerabilityID": "CVE-2023-12345",
                        "PkgName": "requests",
                        "InstalledVersion": "2.28.0",
                        "FixedVersion": "2.31.0",
                        "Severity": "HIGH"
                    }],
                    "Packages": [
                        {"Name": "requests", "Version": "2.28.0"},
                        {"Name": "urllib3", "Version": "1.26.0"}
                    ]
                }]},
                "stderr": "",
                "scanner_version": "0.71.2",
                "vulnerability_db": {
                    "version": 2,
                    "updated_at": "2026-10-04T19:39:34.715623444Z"
                }
            }),
        )
        .await;

        let dir = tempfile::tempdir().unwrap();
        let scanner = TrivyFsScanner::new_with_adapter(
            server.uri(),
            dir.path().to_string_lossy().to_string(),
        );
        let artifact = make_test_artifact(
            "requirements.txt",
            "text/plain",
            "pypi/proj/1.0.0/requirements.txt",
        );
        let content = bytes::Bytes::from_static(b"requests==2.28.0\n");

        let output = scanner
            .scan(&artifact, None, &content)
            .await
            .expect("adapter-backed scan should complete");

        assert_eq!(output.findings.len(), 1, "trivy findings must surface");
        assert_eq!(
            output.findings[0].cve_id,
            Some("CVE-2023-12345".to_string())
        );
        assert_eq!(
            output.findings[0].source,
            Some("trivy-filesystem".to_string())
        );
        // #903: the Packages block must land in the package inventory.
        assert_eq!(output.packages.len(), 2, "SBOM package inventory lost");
        // #1153: the completeness classifier ran over report + stderr.
        assert_eq!(
            output.scan_completeness,
            crate::services::scanner_service::ScanCompleteness::Complete
        );
        // Provenance: version comes from the adapter, not a CLI probe.
        assert_eq!(scanner.version().await, Some("trivy-0.71.2".to_string()));
        // #3014: the adapter's DB rides on THIS scan's output.
        let db = output.vuln_db.expect("adapter-reported DB provenance");
        assert_eq!(db.version, "trivy-db-v2");
        assert_eq!(
            db.published_at.map(|t| t.to_rfc3339()),
            Some("2026-10-04T19:39:34.715623444+00:00".to_string())
        );
    }

    /// Adapter mode with the sidecar down must degrade gracefully: the
    /// orchestrator maps `ScannerEngineUnavailable` to a terminal
    /// `not_applicable` row (#2324), never a grade-F-flooring failure.
    #[tokio::test]
    async fn test_adapter_unavailable_degrades_to_engine_unavailable() {
        let dir = tempfile::tempdir().unwrap();
        let scanner = TrivyFsScanner::new_with_adapter(
            "http://127.0.0.1:1".to_string(),
            dir.path().to_string_lossy().to_string(),
        );
        let artifact = make_test_artifact(
            "requirements.txt",
            "text/plain",
            "pypi/proj/1.0.0/requirements.txt",
        );
        let content = bytes::Bytes::from_static(b"requests==2.28.0\n");

        let err = scanner
            .scan(&artifact, None, &content)
            .await
            .expect_err("a down adapter must not complete the scan");
        assert!(
            matches!(err, crate::error::AppError::ScannerEngineUnavailable(_)),
            "a down adapter must be ScannerEngineUnavailable, got {err:?}"
        );
    }

    // -------------------------------------------------------------------
    // #5666: no Maven Central, no phone-home, bundled jars cataloged
    // -------------------------------------------------------------------

    fn zip_of(entries: &[(&str, Vec<u8>)]) -> Vec<u8> {
        use std::io::Write;
        use zip::write::SimpleFileOptions;

        let mut zw = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        for (path, body) in entries {
            zw.start_file(*path, SimpleFileOptions::default()).unwrap();
            zw.write_all(body).unwrap();
        }
        zw.finish().unwrap().into_inner()
    }

    /// A library jar as Maven packages it: its own `pom.properties` and a
    /// `pom.xml` whose parent only Maven Central could resolve.
    fn library_jar(group: &str, artifact: &str, version: &str) -> Vec<u8> {
        let base = format!("META-INF/maven/{group}/{artifact}");
        zip_of(&[
            (
                &format!("{base}/pom.properties"),
                format!("#Generated by Maven\ngroupId={group}\nartifactId={artifact}\nversion={version}\n")
                    .into_bytes(),
            ),
            (
                &format!("{base}/pom.xml"),
                format!(
                    "<project><parent><groupId>{group}</groupId><artifactId>parent</artifactId>\
                     <version>{version}</version></parent><artifactId>{artifact}</artifactId></project>"
                )
                .into_bytes(),
            ),
            ("x/Lib.class", b"\xca\xfe\xba\xbe".to_vec()),
        ])
    }

    /// A Spring Boot style fat jar bundling three vulnerable libraries under
    /// `BOOT-INF/lib/`, with the outer project's POM inheriting from a
    /// remote parent (what sent trivy to Maven Central in #5666).
    fn fat_jar() -> Bytes {
        Bytes::from(zip_of(&[
            (
                "META-INF/maven/com.example/fatapp/pom.properties",
                b"groupId=com.example\nartifactId=fatapp\nversion=1.0.0\n".to_vec(),
            ),
            (
                "META-INF/maven/com.example/fatapp/pom.xml",
                b"<project><parent><groupId>org.springframework.boot</groupId>\
                  <artifactId>spring-boot-starter-parent</artifactId><version>2.1.0.RELEASE</version>\
                  </parent><artifactId>fatapp</artifactId></project>"
                    .to_vec(),
            ),
            (
                "BOOT-INF/lib/jackson-databind-2.9.10.jar",
                library_jar("com.fasterxml.jackson.core", "jackson-databind", "2.9.10"),
            ),
            (
                "BOOT-INF/lib/log4j-core-2.14.1.jar",
                library_jar("org.apache.logging.log4j", "log4j-core", "2.14.1"),
            ),
            (
                "BOOT-INF/lib/commons-collections-3.2.1.jar",
                library_jar("commons-collections", "commons-collections", "3.2.1"),
            ),
        ]))
    }

    const BUNDLED: &[(&str, &str, &str)] = &[
        ("com.fasterxml.jackson.core", "jackson-databind", "2.9.10"),
        ("org.apache.logging.log4j", "log4j-core", "2.14.1"),
        ("commons-collections", "commons-collections", "3.2.1"),
    ];

    fn assert_inventory_names_bundled(pom: &str) {
        for (g, a, v) in BUNDLED {
            let dep = format!(
                "<dependency><groupId>{g}</groupId><artifactId>{a}</artifactId>\
                 <version>{v}</version></dependency>"
            );
            assert!(
                pom.contains(&dep),
                "inventory must name {g}:{a}:{v}:\n{pom}"
            );
        }
    }

    /// #5666: every local trivy filesystem scan (this scanner and the Incus
    /// rootfs scanner share the builder) runs with `--offline-scan`, so its
    /// POM parser never fetches parents or versions from Maven Central.
    #[test]
    fn test_trivy_filesystem_args_are_offline() {
        for (server, list_all) in [(None, true), (Some("http://trivy:4954"), false)] {
            let args = trivy_filesystem_args("/ws", server, "5m", list_all);
            assert!(
                args.contains(&"--offline-scan"),
                "trivy filesystem must never resolve POMs remotely: {args:?}"
            );
            assert_eq!(args.first(), Some(&"filesystem"));
            assert_eq!(args.last(), Some(&"/ws"), "target stays last: {args:?}");
            assert_eq!(args.contains(&"--list-all-pkgs"), list_all, "{args:?}");
            assert_eq!(
                args.windows(2)
                    .any(|w| w == ["--server", "http://trivy:4954"]),
                server.is_some(),
                "{args:?}"
            );
            assert!(args.windows(2).any(|w| w == ["--timeout", "5m"]));
        }
    }

    /// #5666: the trivy child gets the environment that switches off its
    /// per-run version check and telemetry call to `check.trivy.dev`, and
    /// keeps `kill_on_drop` (#3455).
    #[test]
    fn test_trivy_cli_command_disables_phone_home() {
        let command = trivy_cli_command();
        let envs: Vec<(String, Option<String>)> = command
            .as_std()
            .get_envs()
            .map(|(k, v)| {
                (
                    k.to_string_lossy().into_owned(),
                    v.map(|v| v.to_string_lossy().into_owned()),
                )
            })
            .collect();
        for key in ["TRIVY_SKIP_VERSION_CHECK", "TRIVY_DISABLE_TELEMETRY"] {
            assert!(
                envs.contains(&(key.to_string(), Some("true".to_string()))),
                "{key}=true missing from the trivy environment: {envs:?}"
            );
        }
        assert_eq!(command.as_std().get_program(), "trivy");
    }

    /// #5666: a fat jar staged as the scan workspace stages it (archive +
    /// extracted tree) yields an inventory naming each bundled library at
    /// the version it ships, read from the nested jars' own
    /// `pom.properties` -- no network involved.
    #[tokio::test]
    async fn test_jar_inventory_catalogs_fat_jar_bundled_libraries() {
        let tmp = tempfile::tempdir().unwrap();
        let artifact = make_test_artifact(
            "fatapp-1.0.0.jar",
            "application/java-archive",
            "maven/com/example/fatapp/1.0.0/fatapp-1.0.0.jar",
        );
        let ws = ScanWorkspace::prepare_pinned(
            tmp.path().to_str().unwrap(),
            None,
            &artifact,
            &fat_jar(),
            None,
        )
        .await
        .unwrap();
        assert!(
            ws.join("BOOT-INF/lib/log4j-core-2.14.1.jar").is_file(),
            "the workspace extracts the fat jar"
        );

        // The outer project's own coordinate is named too.
        assert_eq!(write_embedded_jar_inventory(&ws).await, BUNDLED.len() + 1);
        let pom = std::fs::read_to_string(ws.join(JAR_INVENTORY_SUBDIR).join("pom.xml")).unwrap();
        assert_inventory_names_bundled(&pom);
        assert!(pom.contains("<artifactId>fatapp</artifactId><version>1.0.0</version>"));
        assert!(!pom.contains("<parent>"), "nothing to resolve remotely");

        // Idempotent: a second pass does not read its own output.
        assert_eq!(write_embedded_jar_inventory(&ws).await, BUNDLED.len() + 1);
    }

    /// #5666: when the workspace could not extract the fat jar (extraction
    /// budget, raw-file fallback) the nested jars are read from inside it.
    #[tokio::test]
    async fn test_jar_inventory_reads_jars_nested_in_an_unextracted_archive() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("fatapp-1.0.0.jar"), fat_jar()).unwrap();
        assert_eq!(
            write_embedded_jar_inventory(tmp.path()).await,
            BUNDLED.len() + 1
        );
        let pom =
            std::fs::read_to_string(tmp.path().join(JAR_INVENTORY_SUBDIR).join("pom.xml")).unwrap();
        assert_inventory_names_bundled(&pom);
    }

    /// Coordinates are interpolated into XML, so anything outside Maven's
    /// identifier alphabet (markup, a `${...}` reference) is dropped, and a
    /// workspace with no JVM archive gets no inventory at all.
    #[tokio::test]
    async fn test_jar_inventory_drops_hostile_coordinates() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("evil.jar"),
            zip_of(&[
                (
                    "META-INF/maven/a/b/pom.properties",
                    b"groupId=a</groupId><x>\nartifactId=b\nversion=1\n".to_vec(),
                ),
                (
                    "META-INF/maven/c/d/pom.properties",
                    b"groupId=c\nartifactId=d\nversion=${revision}\n".to_vec(),
                ),
                // Not at META-INF/maven/<g>/<a>/: ignored.
                (
                    "META-INF/maven/pom.properties",
                    b"groupId=e\nartifactId=f\nversion=1\n".to_vec(),
                ),
            ]),
        )
        .unwrap();
        assert_eq!(write_embedded_jar_inventory(tmp.path()).await, 0);
        assert!(!tmp.path().join(JAR_INVENTORY_SUBDIR).exists());

        let plain = tempfile::tempdir().unwrap();
        std::fs::write(plain.path().join("requirements.txt"), b"requests==2.28.0\n").unwrap();
        assert_eq!(write_embedded_jar_inventory(plain.path()).await, 0);
        assert!(!plain.path().join(JAR_INVENTORY_SUBDIR).exists());
    }

    /// A shipped entry at the inventory path cannot block it or redirect the
    /// write: a directory where the pom goes is removed, and a symlink is
    /// replaced rather than written through.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_jar_inventory_replaces_shipped_decoys() {
        let outside = tempfile::tempdir().unwrap();
        let target = outside.path().join("victim");
        std::fs::write(&target, b"untouched").unwrap();
        for decoy_is_dir in [true, false] {
            let tmp = tempfile::tempdir().unwrap();
            std::fs::write(tmp.path().join("fatapp-1.0.0.jar"), fat_jar()).unwrap();
            let pom = tmp.path().join(JAR_INVENTORY_SUBDIR).join("pom.xml");
            std::fs::create_dir_all(pom.parent().unwrap()).unwrap();
            if decoy_is_dir {
                std::fs::create_dir_all(pom.join("blocker")).unwrap();
            } else {
                std::os::unix::fs::symlink(&target, &pom).unwrap();
            }
            assert_eq!(
                write_embedded_jar_inventory(tmp.path()).await,
                BUNDLED.len() + 1
            );
            assert!(std::fs::symlink_metadata(&pom).unwrap().is_file());
            assert_inventory_names_bundled(&std::fs::read_to_string(&pom).unwrap());
        }
        assert_eq!(std::fs::read(&target).unwrap(), b"untouched");
    }

    #[test]
    fn test_maven_coordinate_validation() {
        let ok = MavenCoordinate::from_pom_properties(
            b"#c\ngroupId = org.example\nartifactId: my_lib-x\nversion=1.0.0+build.1\n",
        )
        .expect("valid coordinate");
        assert_eq!(ok.group_id, "org.example");
        assert_eq!(ok.artifact_id, "my_lib-x");
        assert_eq!(ok.version, "1.0.0+build.1");
        assert!(MavenCoordinate::from_pom_properties(b"groupId=a\nartifactId=b\n").is_none());
        assert!(
            MavenCoordinate::from_pom_properties(b"groupId=a&b\nartifactId=b\nversion=1\n")
                .is_none()
        );
        assert!(MavenCoordinate::from_pom_properties(&[0xff, 0xfe]).is_none());
        assert!(is_pom_properties_path("META-INF/maven/g/a/pom.properties"));
        assert!(!is_pom_properties_path("META-INF/maven/g/pom.properties"));
        assert!(!is_pom_properties_path(
            "x/META-INF/maven/g/a/pom.properties"
        ));
    }

    /// The inventory's own root coordinate never reaches the package
    /// inventory; the real packages in the same target do.
    #[test]
    fn test_strip_jar_inventory_root() {
        let mut report: TrivyReport = serde_json::from_value(serde_json::json!({"Results": [
            {"Target": ".ak-scan-jar-inventory/pom.xml", "Class": "lang-pkgs", "Type": "pom",
             "Packages": [
                {"Name": "artifact-keeper.scan:embedded-jars", "Version": "0"},
                {"Name": "org.apache.logging.log4j:log4j-core", "Version": "2.14.1"}
             ]},
            {"Target": "pom.xml", "Class": "lang-pkgs", "Type": "pom",
             "Packages": [{"Name": "artifact-keeper.scan:embedded-jars", "Version": "0"}]}
        ]}))
        .unwrap();
        strip_jar_inventory_root(&mut report);
        let names = |i: usize| -> Vec<String> {
            report.results[i]
                .packages
                .as_ref()
                .unwrap()
                .iter()
                .map(|p| p.name.clone())
                .collect()
        };
        assert_eq!(names(0), vec!["org.apache.logging.log4j:log4j-core"]);
        // Only the inventory target is touched.
        assert_eq!(names(1), vec!["artifact-keeper.scan:embedded-jars"]);
    }

    /// #5666 end to end in adapter mode: a fat jar's scan uploads the
    /// inventory naming its bundled libraries (so the adapter's trivy grades
    /// them without contacting Maven Central), and the inventory's root
    /// coordinate is kept out of the package list the adapter reports back.
    #[tokio::test]
    async fn test_adapter_scan_of_fat_jar_uploads_bundled_inventory() {
        let server = wiremock::MockServer::start().await;
        crate::services::scanner_adapter_client::test_support::mount_fs_scan_success(
            &server,
            "fs-fat",
            serde_json::json!({
                "report": {"Results": [{
                    "Target": ".ak-scan-jar-inventory/pom.xml",
                    "Class": "lang-pkgs",
                    "Type": "pom",
                    "Packages": [
                        {"Name": "artifact-keeper.scan:embedded-jars", "Version": "0"},
                        {"Name": "org.apache.logging.log4j:log4j-core", "Version": "2.14.1"}
                    ]
                }]},
                "stderr": ""
            }),
        )
        .await;

        let dir = tempfile::tempdir().unwrap();
        let scanner = TrivyFsScanner::new_with_adapter(
            server.uri(),
            dir.path().to_string_lossy().to_string(),
        );
        let artifact = make_test_artifact(
            "fatapp-1.0.0.jar",
            "application/java-archive",
            "maven/com/example/fatapp/1.0.0/fatapp-1.0.0.jar",
        );
        let output = scanner
            .scan(&artifact, None, &fat_jar())
            .await
            .expect("adapter-backed scan should complete");
        let names: Vec<&str> = output.packages.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, vec!["org.apache.logging.log4j:log4j-core"]);

        let upload = server
            .received_requests()
            .await
            .unwrap()
            .into_iter()
            .find(|r| r.method == wiremock::http::Method::POST)
            .expect("workspace upload");
        let mut archive = tar::Archive::new(std::io::Cursor::new(upload.body));
        let mut pom = None;
        for entry in archive.entries().unwrap() {
            let mut entry = entry.unwrap();
            if entry.path().unwrap() == Path::new(JAR_INVENTORY_SUBDIR).join("pom.xml") {
                let mut s = String::new();
                std::io::Read::read_to_string(&mut entry, &mut s).unwrap();
                pom = Some(s);
            }
        }
        assert_inventory_names_bundled(&pom.expect("the upload must carry the jar inventory"));
    }

    /// `version()` exercises the TTL-backed cached probe path. We do not
    /// require `trivy` to be installed: the test only asserts the call
    /// returns deterministically (`Some("trivy-...")` when installed,
    /// `None` otherwise) and that subsequent calls return the same value
    /// from cache. The point is to cover the per-scanner override body so
    /// the new-code coverage gate sees these lines as executed.
    #[tokio::test]
    async fn test_version_is_cached_and_deterministic() {
        let dir = tempfile::tempdir().unwrap();
        let scanner = TrivyFsScanner::new(
            "http://localhost:0".to_string(),
            dir.path().to_string_lossy().to_string(),
        );
        let v1 = scanner.version().await;
        let v2 = scanner.version().await;
        assert_eq!(v1, v2, "VersionCache must return identical value on repeat");
        if let Some(v) = v1 {
            assert!(
                v.starts_with("trivy-"),
                "trivy version probe must be normalized to 'trivy-<ver>'; got {}",
                v
            );
        }
    }
}
