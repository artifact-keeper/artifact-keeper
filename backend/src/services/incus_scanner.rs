//! Incus/LXC container image vulnerability scanner.
//!
//! Extracts rootfs contents from Incus images (unified tarballs, squashfs)
//! and scans them with `trivy filesystem` to discover OS-level package
//! vulnerabilities (e.g. .deb packages in Ubuntu LXC containers).
//!
//! Supports:
//!   - Unified tarballs (.tar.xz / .tar.gz) containing rootfs + metadata
//!   - Split metadata tarballs (metadata.tar.xz) — skipped (no rootfs)
//!   - SquashFS rootfs images — extracted with `unsquashfs`
//!   - QCOW2/IMG VM disk images — skipped (requires mounting)

use async_trait::async_trait;
use bytes::Bytes;
use std::path::{Path, PathBuf};
use tracing::{info, warn};

use crate::error::{AppError, Result};
use crate::formats::incus::{IncusFileType, IncusHandler};
use crate::models::artifact::{Artifact, ArtifactMetadata};
use crate::services::image_scanner::TrivyReport;
use crate::services::scanner_service::{
    cached_trivy_cli_version, fail_scan_path, ScanOutput, ScanWorkspace, Scanner, VersionCache,
};

/// Default ceiling on compressed input size we will attempt to extract
/// (16 GiB). Untrusted archives can be decompression bombs; refuse anything
/// larger than this before writing it to disk. The uncompressed tree is
/// further bounded by [`max_extracted_bytes`] / [`MAX_EXTRACTED_ENTRIES`]
/// after extraction.
///
/// #1492: a real `incus export` OS image is several GiB compressed, so the
/// prior 2 GiB cap rejected legitimate images before extraction even started.
/// The default is now sized for real OS images and is overridable via
/// [`MAX_INCUS_SCAN_COMPRESSED_BYTES_ENV`] for sites with larger images, while
/// the bomb guard stays in force at whatever ceiling is configured.
const DEFAULT_MAX_COMPRESSED_INPUT_BYTES: u64 = 16 * 1024 * 1024 * 1024;

/// Default ceiling on total uncompressed bytes we tolerate in an extracted
/// rootfs (64 GiB). Bounds decompression bombs that expand a small archive
/// into a PVC-filling tree. Checked by walking the extracted tree after `tar`
/// finishes. Overridable via [`MAX_INCUS_SCAN_EXTRACTED_BYTES_ENV`].
const DEFAULT_MAX_EXTRACTED_BYTES: u64 = 64 * 1024 * 1024 * 1024;

/// Maximum number of filesystem entries we tolerate in an extracted rootfs.
/// Bounds inode-exhaustion bombs (millions of tiny files).
const MAX_EXTRACTED_ENTRIES: u64 = 2_000_000;

/// Env var overriding the compressed-input ceiling (plain byte count).
const MAX_INCUS_SCAN_COMPRESSED_BYTES_ENV: &str = "MAX_INCUS_SCAN_COMPRESSED_BYTES";

/// Env var overriding the extracted-tree byte ceiling (plain byte count).
const MAX_INCUS_SCAN_EXTRACTED_BYTES_ENV: &str = "MAX_INCUS_SCAN_EXTRACTED_BYTES";

/// Resolve a byte-size cap from an optional override string, falling back to
/// `default` when the value is absent, blank, non-numeric, or zero. A zero cap
/// would reject every image, so it is treated as "unset" rather than honoured.
/// The override is a plain decimal byte count (e.g. `17179869184` for 16 GiB).
fn resolve_byte_cap(raw: Option<String>, default: u64) -> u64 {
    raw.and_then(|s| s.trim().parse::<u64>().ok())
        .filter(|&v| v > 0)
        .unwrap_or(default)
}

/// Effective compressed-input ceiling, honouring
/// [`MAX_INCUS_SCAN_COMPRESSED_BYTES_ENV`] over
/// [`DEFAULT_MAX_COMPRESSED_INPUT_BYTES`].
fn max_compressed_input_bytes() -> u64 {
    resolve_byte_cap(
        std::env::var(MAX_INCUS_SCAN_COMPRESSED_BYTES_ENV).ok(),
        DEFAULT_MAX_COMPRESSED_INPUT_BYTES,
    )
}

/// Effective extracted-tree byte ceiling, honouring
/// [`MAX_INCUS_SCAN_EXTRACTED_BYTES_ENV`] over [`DEFAULT_MAX_EXTRACTED_BYTES`].
fn max_extracted_bytes() -> u64 {
    resolve_byte_cap(
        std::env::var(MAX_INCUS_SCAN_EXTRACTED_BYTES_ENV).ok(),
        DEFAULT_MAX_EXTRACTED_BYTES,
    )
}

/// Write content to a temporary file in the workspace, returning an error with the given label.
async fn write_temp_file(path: &Path, content: &Bytes, label: &str) -> Result<()> {
    tokio::fs::write(path, content)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to write {} to workspace: {}", label, e)))
}

/// Normalise a path lexically, collapsing `.` and `..` components without
/// touching the filesystem. Used by the symlink-traversal guard so dangling
/// targets (e.g. `a -> ../../etc/passwd`) are still resolved and checked.
///
/// This is purely textual: it does not resolve intermediate symlinks. The
/// guard pairs it with a `canonicalize` fallback for targets that exist.
fn normalize_lexically(path: &Path) -> PathBuf {
    use std::path::Component;
    let mut prefix: Option<Component> = None;
    let mut has_root = false;
    // Stack of resolved components. Entries are either ".." (only when not
    // rooted and nothing left to pop) or normal path segments.
    let mut parts: Vec<std::ffi::OsString> = Vec::new();

    for component in path.components() {
        match component {
            Component::Prefix(p) => prefix = Some(Component::Prefix(p)),
            Component::RootDir => has_root = true,
            Component::CurDir => {}
            Component::ParentDir => {
                match parts.last() {
                    // Pop a real segment.
                    Some(last) if last != ".." => {
                        parts.pop();
                    }
                    // Past the root is a no-op (cannot escape `/`).
                    _ if has_root && parts.is_empty() => {}
                    // Relative path with no segment to pop: preserve a leading
                    // `..` so a relative escape survives and later fails the
                    // starts_with(root) check.
                    _ => parts.push(std::ffi::OsString::from("..")),
                }
            }
            Component::Normal(seg) => parts.push(seg.to_os_string()),
        }
    }

    let mut out = PathBuf::new();
    if let Some(p) = prefix {
        out.push(p.as_os_str());
    }
    if has_root {
        out.push(std::path::MAIN_SEPARATOR_STR);
    }
    for part in parts {
        out.push(part);
    }
    out
}

/// Run an external command, returning an error with the given label on failure.
async fn run_command(program: &str, args: &[&str], label: &str) -> Result<()> {
    let output = tokio::process::Command::new(program)
        .args(args)
        .output()
        .await
        .map_err(|e| AppError::Internal(format!("Failed to execute {}: {}", program, e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(AppError::Internal(format!("{} failed: {}", label, stderr)));
    }

    Ok(())
}

/// Run a Trivy filesystem scan, optionally in server mode. The `label` is used in error messages.
async fn run_trivy_scan(
    rootfs: &Path,
    server_url: Option<&str>,
    label: &str,
) -> Result<TrivyReport> {
    let rootfs_str = rootfs.to_string_lossy();
    let mut args = vec!["filesystem"];
    if let Some(url) = server_url {
        args.push("--server");
        args.push(url);
    }
    args.extend_from_slice(&[
        "--format",
        "json",
        "--severity",
        "CRITICAL,HIGH,MEDIUM,LOW",
        "--quiet",
        "--timeout",
        "10m",
        &rootfs_str,
    ]);

    let output = tokio::process::Command::new("trivy")
        .args(&args)
        .output()
        .await
        .map_err(|e| crate::services::scanner_service::classify_trivy_spawn_error(&e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(AppError::Internal(format!(
            "{} failed (exit {}): {}",
            label, output.status, stderr
        )));
    }

    serde_json::from_slice(&output.stdout)
        .map_err(|e| AppError::Internal(format!("Failed to parse Trivy output: {}", e)))
}

/// Vulnerability scanner for Incus/LXC container images.
///
/// Extracts the filesystem contents from container images and runs
/// `trivy filesystem` to find OS package vulnerabilities.
pub struct IncusScanner {
    trivy_url: String,
    scan_workspace: String,
    /// Lazily-probed version string from `trivy --version`, e.g.
    /// `trivy-0.62.1`. Successful probes are cached for an hour so each scan
    /// does not pay an extra subprocess; failed probes expire after 60s so
    /// the field starts populating once the binary becomes available.
    cached_version: VersionCache,
}

impl IncusScanner {
    pub fn new(trivy_url: String, scan_workspace: String) -> Self {
        Self {
            trivy_url,
            scan_workspace,
            cached_version: VersionCache::new(),
        }
    }

    /// Check if this scanner is applicable to the given artifact.
    pub fn is_applicable(artifact: &Artifact) -> bool {
        let path = &artifact.path;
        // Only scan Incus image files (not SimpleStreams index files)
        IncusHandler::parse_path(path)
            .map(|info| {
                matches!(
                    info.file_type,
                    IncusFileType::UnifiedTarball
                        | IncusFileType::RootfsSquashfs
                        | IncusFileType::RootfsQcow2
                )
            })
            .unwrap_or(false)
    }

    /// Build the base workspace directory path for a given artifact
    /// (`<base>/incus-<artifact.id>`). The actual per-scan workspace appends a
    /// random suffix to this; see [`Self::scan_workspace_dir`].
    fn workspace_dir(&self, artifact: &Artifact) -> PathBuf {
        ScanWorkspace::workspace_dir(&self.scan_workspace, Some("incus"), artifact)
    }

    /// Build a per-scan-unique workspace directory
    /// (`<base>/incus-<artifact.id>-<uuid>`).
    ///
    /// Concurrent scans of the *same* artifact (re-scan triggered while a prior
    /// scan is still extracting, repository-wide rescan, ...) would otherwise
    /// share `incus-<artifact.id>` and the top-of-`prepare_workspace`
    /// `remove_dir_all` of one scan would delete the tree the other is mid-way
    /// through extracting. A random suffix isolates each scan's tree.
    fn scan_workspace_dir(&self, artifact: &Artifact) -> PathBuf {
        let mut dir = self.workspace_dir(artifact).into_os_string();
        dir.push("-");
        dir.push(uuid::Uuid::new_v4().to_string());
        PathBuf::from(dir)
    }

    /// Prepare the scan workspace by extracting rootfs from the image.
    ///
    /// Returns `(rootfs_path, workspace_root)`. The caller cleans up
    /// `workspace_root` (the per-scan-unique directory) on both success and
    /// failure.
    async fn prepare_workspace(
        &self,
        artifact: &Artifact,
        content: &Bytes,
    ) -> Result<(PathBuf, PathBuf)> {
        let workspace = self.scan_workspace_dir(artifact);

        // Wipe any partial tree left by a previous failed scan (OOM, disk-full,
        // janitor reap, ...) so extraction below starts from a clean slate.
        // Best-effort: a missing path is fine; anything else surfaces. With the
        // per-scan UUID suffix this is effectively always a no-op, but it keeps
        // extraction robust against a UUID collision or a partially-written tree.
        if let Err(e) = tokio::fs::remove_dir_all(&workspace).await {
            if e.kind() != std::io::ErrorKind::NotFound {
                return Err(AppError::Internal(format!(
                    "Failed to clear stale scan workspace {}: {}",
                    workspace.display(),
                    e
                )));
            }
        }

        let rootfs_dir = workspace.join("rootfs");
        tokio::fs::create_dir_all(&rootfs_dir)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to create scan workspace: {}", e)))?;

        // From here on the workspace dir exists; clean it up before returning any
        // error so a half-built tree (or the QCOW2 reject path) never lingers on
        // the PVC. On success the caller owns cleanup of `workspace`.
        let result = self
            .prepare_workspace_inner(artifact, content, &workspace, &rootfs_dir)
            .await;
        match result {
            Ok(rootfs) => Ok((rootfs, workspace)),
            Err(e) => {
                ScanWorkspace::cleanup_path(&workspace).await;
                Err(e)
            }
        }
    }

    /// Extraction body for [`Self::prepare_workspace`]. Split out so the outer
    /// function can guarantee workspace cleanup on every error path.
    async fn prepare_workspace_inner(
        &self,
        artifact: &Artifact,
        content: &Bytes,
        workspace: &Path,
        rootfs_dir: &Path,
    ) -> Result<PathBuf> {
        let info = IncusHandler::parse_path(&artifact.path)
            .map_err(|e| AppError::Internal(format!("Invalid Incus path: {}", e)))?;

        match info.file_type {
            IncusFileType::UnifiedTarball => {
                // Extract into the workspace root: `incus image export` archives
                // unpack to `rootfs/…`, while `incus export` container backups
                // unpack to `backup/container/rootfs/…`. `find_rootfs` then locates
                // whichever layout this archive used; fall back to `rootfs/` so a
                // marker-less archive still scans (with a warning) rather than fails.
                self.extract_tarball(content, workspace).await?;
                Ok(Self::find_rootfs(workspace)
                    .await
                    .unwrap_or_else(|| rootfs_dir.to_path_buf()))
            }
            IncusFileType::RootfsSquashfs => {
                self.extract_squashfs(content, workspace, rootfs_dir)
                    .await?;
                Ok(rootfs_dir.to_path_buf())
            }
            IncusFileType::RootfsQcow2 => {
                // QCOW2/IMG disk images require mounting — not feasible in a scanner context.
                warn!(
                    "Skipping QCOW2/IMG scan for {} — disk images cannot be extracted without mounting",
                    artifact.name
                );
                Err(AppError::Internal(
                    "QCOW2 disk images are not scannable without mounting".to_string(),
                ))
            }
            _ => Err(AppError::Internal(format!(
                "Unsupported Incus file type for scanning: {}",
                info.file_type.as_str()
            ))),
        }
    }

    /// Reject a compressed input larger than the effective compressed cap
    /// ([`max_compressed_input_bytes`]). Checked before the archive is written
    /// to disk so an oversized upload never lands on the PVC.
    fn check_compressed_input_size(input_len: u64) -> Result<()> {
        let cap = max_compressed_input_bytes();
        if input_len > cap {
            return Err(AppError::Internal(format!(
                "Incus archive too large to scan: {} bytes exceeds limit of {} bytes",
                input_len, cap
            )));
        }
        Ok(())
    }

    /// Extract a unified tarball (tar.xz or tar.gz) into `dest`.
    ///
    /// Hardened against malicious archives and against state/modes the runtime
    /// UID can't later traverse or delete:
    ///   * input size is capped at [`max_compressed_input_bytes`] *before*
    ///     writing the archive, and the extracted tree is bounded by
    ///     [`max_extracted_bytes`] / [`MAX_EXTRACTED_ENTRIES`] afterwards, so a
    ///     decompression bomb can't fill the PVC;
    ///   * `--overwrite` is intentionally NOT passed: it disables GNU tar's
    ///     in-archive symlink-overwrite protection, which a crafted archive uses
    ///     to plant `rootfs -> /etc` then write through it. The per-scan-unique
    ///     workspace + the `remove_dir_all` wipe above already guarantee a clean
    ///     target dir, so `--overwrite` is redundant as well as dangerous;
    ///   * `--absolute-names` is NOT passed, so tar strips leading `/` and `..`
    ///     from member paths (the default, safe behaviour);
    ///   * after extraction, [`Self::reject_escaping_symlinks`] walks the tree
    ///     and aborts if any symlink resolves outside the workspace root;
    ///   * `--no-same-owner` so tar doesn't try (and silently fail) to chown to
    ///     the archive's UIDs as a non-root pod;
    ///   * `--mode=u=rwX,go=rX` so special bits never survive — e.g. a setgid
    ///     `2755` kernel-module dir would otherwise land as `d--x--S---` and
    ///     break the later recursive cleanup. `--no-same-permissions` alone is
    ///     not enough: the umask doesn't mask the setuid/setgid/sticky bits.
    async fn extract_tarball(&self, content: &Bytes, dest: &Path) -> Result<()> {
        // Decompression-bomb guard #1: bound the compressed input before it ever
        // touches disk. A 2 GiB archive is already far larger than any real
        // container image; anything bigger is almost certainly hostile.
        Self::check_compressed_input_size(content.len() as u64)?;

        let tarball_path = dest.join("image.tar.xz");
        write_temp_file(&tarball_path, content, "tarball").await?;

        // Detect compression by magic bytes: XZ (FD 37 7A 58 5A), zstd
        // (28 B5 2F FD), else assume gzip. `incus image export` ships .tar.xz;
        // `incus export` container backups and zstd-compressed exports
        // (`--compression=zstd`) ship .tar.zst, so zstd must be handled
        // explicitly — `tar -xzf` (gzip) on a zstd archive
        // fails extraction. zstd support requires the `zstd` binary in the
        // runtime image (installed in Dockerfile.backend).
        let is_xz = content.len() >= 5 && content[..5] == [0xFD, 0x37, 0x7A, 0x58, 0x5A];
        let is_zstd = content.len() >= 4 && content[..4] == [0x28, 0xB5, 0x2F, 0xFD];

        let tarball_arg = tarball_path.to_string_lossy();
        let dest_arg = dest.to_string_lossy();
        // GNU tar only treats a bare option bundle (`xzf`) as options when it is
        // the FIRST argument; here it follows `--no-same-owner`/`--mode=...`, so
        // the leading `-` is required. zstd has no single-letter bundle, so it
        // goes in as the long `--zstd` option plus a plain `-xf` extract bundle.
        let mut args: Vec<&str> = vec!["--no-same-owner", "--mode=u=rwX,go=rX"];
        if is_zstd {
            args.push("--zstd");
            args.push("-xf");
        } else if is_xz {
            args.push("-xJf");
        } else {
            args.push("-xzf");
        }
        args.push(tarball_arg.as_ref());
        args.push("-C");
        args.push(dest_arg.as_ref());

        run_command("tar", &args, "tar extraction").await?;

        // Drop the source archive before walking the tree so it isn't counted
        // toward the extracted-size budget (and to free the disk early).
        let _ = tokio::fs::remove_file(&tarball_path).await;

        // Post-extraction hardening: reject escaping symlinks + enforce the
        // bomb caps over the extracted tree. The squashfs path runs the exact
        // same guard (see `extract_squashfs`).
        Self::run_extraction_guard(dest).await?;

        Ok(())
    }

    /// Run the post-extraction hardening guard over `root` on a blocking thread.
    /// Shared by both the tarball and squashfs extraction paths so the defense
    /// posture (symlink-traversal rejection + decompression-bomb caps) is
    /// identical regardless of image format.
    ///
    ///   1. make the tree owner-traversable so the non-root scanner UID can
    ///      walk it and trivy can read the package DBs (#1492),
    ///   2. reject any symlink that escapes the workspace root (traversal),
    ///   3. enforce the uncompressed-size / entry-count bomb caps.
    async fn run_extraction_guard(root: &Path) -> Result<()> {
        let root = root.to_path_buf();
        tokio::task::spawn_blocking(move || {
            // Open the tree up to the owner first: a real OS rootfs ships
            // restrictive modes (0700 dirs, 0600 files), and `--no-same-owner`
            // extraction plus tar's implicitly-created parent dirs leave parts
            // of the tree untraversable by the non-root scanner UID. Without
            // this the symlink/bomb walk below (and later trivy) EACCES on the
            // first locked dir. Done in-process (not `chmod -R`) so we never
            // chase a symlink target out of the workspace (#1492).
            Self::make_tree_owner_traversable(&root)?;
            Self::enforce_extraction_limits(&root)
        })
        .await
        .map_err(|e| AppError::Internal(format!("Extraction guard task failed: {}", e)))?
    }

    /// Recursively add owner read/write/traverse bits (`u+rwX`) to every real
    /// directory and file under `root` so the non-root scanner UID can walk the
    /// tree and trivy can read its package databases. Walks top-down so a
    /// `0o000` directory is opened before we descend into it.
    ///
    /// Symlinks are skipped via `symlink_metadata` and never followed, so an
    /// in-tree `var/run -> /run` (or any absolute link) cannot cause us to
    /// chmod a path outside the workspace — the property `chmod -R` cannot
    /// guarantee. Only owner bits are added; group/other are never widened.
    ///
    /// Unix-only: Windows has no POSIX permission bits and incus images are a
    /// Linux concept, so the Windows lib build gets a no-op stub below (#1525)
    /// to keep the crate cross-compiling cleanly for the Windows CLI target.
    /// The Windows scanner code path is never reached in practice; the stub
    /// just lets `extract_tarball_to_dir` stay platform-agnostic at the call
    /// site.
    #[cfg(unix)]
    fn make_tree_owner_traversable(root: &Path) -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let mut stack: Vec<PathBuf> = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            // Ensure this directory is traversable/readable before we list it.
            // Owners may always chmod their own inode regardless of its current
            // mode, so a 0o000 dir is recoverable here.
            if let Ok(meta) = std::fs::symlink_metadata(&dir) {
                if meta.file_type().is_dir() {
                    let mode = meta.permissions().mode();
                    let mut perms = meta.permissions();
                    perms.set_mode(mode | 0o700);
                    let _ = std::fs::set_permissions(&dir, perms);
                }
            }

            let entries = std::fs::read_dir(&dir).map_err(|e| {
                AppError::Internal(format!(
                    "Failed to read {} while opening tree: {}",
                    dir.display(),
                    e
                ))
            })?;
            for entry in entries {
                let entry = entry.map_err(|e| {
                    AppError::Internal(format!(
                        "Failed to read dir entry while opening tree: {}",
                        e
                    ))
                })?;
                let path = entry.path();
                let meta = std::fs::symlink_metadata(&path).map_err(|e| {
                    AppError::Internal(format!(
                        "Failed to stat {} while opening tree: {}",
                        path.display(),
                        e
                    ))
                })?;
                let file_type = meta.file_type();
                if file_type.is_symlink() {
                    // Never chmod through a link; the traversal guard checks it.
                    continue;
                }
                if file_type.is_dir() {
                    stack.push(path);
                } else if file_type.is_file() {
                    let mode = meta.permissions().mode();
                    let mut perms = meta.permissions();
                    perms.set_mode(mode | 0o600);
                    let _ = std::fs::set_permissions(&path, perms);
                }
            }
        }
        Ok(())
    }

    /// Windows no-op stub for `make_tree_owner_traversable` (see #1525). Windows
    /// has no POSIX mode bits, the incus scanner is never invoked on Windows in
    /// practice, and the lib must still cross-compile cleanly for the Windows
    /// CLI build. Returns `Ok(())` so the platform-agnostic call site at
    /// `extract_tarball_to_dir` continues to work.
    #[cfg(not(unix))]
    fn make_tree_owner_traversable(_root: &Path) -> Result<()> {
        Ok(())
    }

    /// Walk the extracted tree (synchronously) and abort if it contains a
    /// symlink whose canonicalized target escapes `root`, or if its total size /
    /// entry count exceeds the decompression-bomb caps.
    ///
    /// Symlinks are checked without following them (`symlink_metadata`); a link
    /// is rejected when its resolved target is not inside `root`. Targets that
    /// don't yet exist (dangling) are resolved lexically against the link's
    /// parent so an `a -> ../../etc` style escape is still caught.
    fn enforce_extraction_limits(root: &Path) -> Result<()> {
        let canonical_root = std::fs::canonicalize(root).map_err(|e| {
            AppError::Internal(format!(
                "Failed to canonicalize workspace root {}: {}",
                root.display(),
                e
            ))
        })?;

        let max_bytes = max_extracted_bytes();
        let mut total_bytes: u64 = 0;
        let mut total_entries: u64 = 0;
        let mut stack: Vec<PathBuf> = vec![root.to_path_buf()];

        while let Some(dir) = stack.pop() {
            let entries = std::fs::read_dir(&dir).map_err(|e| {
                AppError::Internal(format!(
                    "Failed to read {} during guard: {}",
                    dir.display(),
                    e
                ))
            })?;
            for entry in entries {
                let entry = entry.map_err(|e| {
                    AppError::Internal(format!("Failed to read dir entry during guard: {}", e))
                })?;
                let path = entry.path();
                let meta = std::fs::symlink_metadata(&path).map_err(|e| {
                    AppError::Internal(format!(
                        "Failed to stat {} during guard: {}",
                        path.display(),
                        e
                    ))
                })?;
                let file_type = meta.file_type();

                total_entries += 1;
                if total_entries > MAX_EXTRACTED_ENTRIES {
                    return Err(AppError::Internal(format!(
                        "Incus archive contains too many entries (> {}); refusing to scan suspected decompression bomb",
                        MAX_EXTRACTED_ENTRIES
                    )));
                }

                if file_type.is_symlink() {
                    Self::reject_escaping_symlink(&path, &canonical_root)?;
                    // Do not follow the link; nothing more to do for it.
                    continue;
                }

                if file_type.is_dir() {
                    stack.push(path);
                } else if file_type.is_file() {
                    total_bytes += meta.len();
                    if total_bytes > max_bytes {
                        return Err(AppError::Internal(format!(
                            "Incus archive expands to more than {} bytes; refusing to scan suspected decompression bomb",
                            max_bytes
                        )));
                    }
                }
            }
        }

        Ok(())
    }

    /// Reject a symlink at `link` whose target resolves outside `canonical_root`.
    fn reject_escaping_symlink(link: &Path, canonical_root: &Path) -> Result<()> {
        let target = std::fs::read_link(link).map_err(|e| {
            AppError::Internal(format!(
                "Failed to read symlink {} during guard: {}",
                link.display(),
                e
            ))
        })?;

        // Resolve the target, then normalise lexically (collapsing `.` / `..`)
        // so dangling targets are still checked. We deliberately avoid
        // `canonicalize` on the joined path because it fails on dangling links.
        //
        // #1492: an absolute target inside a container rootfs points at the
        // *image* root, not the host root. Every real OS rootfs ships absolute
        // intra-image links like `/var/run -> /run`; resolving them against the
        // host (the prior behaviour) flagged them as escaping and made it
        // impossible to scan any real image. Re-root absolute targets under the
        // workspace (chroot semantics) by stripping the leading `/` and joining
        // onto `canonical_root`. Any `..` components survive the strip and are
        // collapsed by `normalize_lexically`, so an absolute link that climbs
        // out of the re-rooted workspace still fails the `starts_with` check
        // below. Relative targets resolve against the link's parent as before.
        let raw_parent = link.parent().unwrap_or(canonical_root);
        let parent = std::fs::canonicalize(raw_parent).unwrap_or_else(|_| raw_parent.to_path_buf());
        let joined = if target.is_absolute() {
            // Strip the root/prefix so the target is re-anchored under the
            // workspace; `..` components are preserved and checked.
            use std::path::Component;
            let rerooted: PathBuf = target
                .components()
                .filter(|c| !matches!(c, Component::RootDir | Component::Prefix(_)))
                .collect();
            canonical_root.join(rerooted)
        } else {
            parent.join(&target)
        };
        let resolved = normalize_lexically(&joined);

        // Compare against the canonical root. A symlink is allowed only if its
        // resolved target stays within the workspace.
        let within = resolved.starts_with(canonical_root) || {
            // For targets that exist, also accept when the resolved path
            // canonicalizes inside the root (covers intermediate symlinks).
            std::fs::canonicalize(&resolved)
                .map(|c| c.starts_with(canonical_root))
                .unwrap_or(false)
        };

        if !within {
            return Err(AppError::Internal(format!(
                "Incus archive contains symlink {} -> {} escaping the workspace; refusing extraction (path traversal)",
                link.display(),
                target.display()
            )));
        }
        Ok(())
    }

    /// Locate the actual rootfs inside an extracted incus archive by probing
    /// known package-DB markers. `incus image export` archives put it at
    /// `rootfs/`; `incus export` container backups put it at
    /// `backup/container/rootfs/`. Returns the first candidate that contains a
    /// recognised marker, or `None` (the caller falls back to `rootfs/` + warns).
    async fn find_rootfs(workspace: &Path) -> Option<PathBuf> {
        const MARKERS: &[&str] = &[
            "var/lib/dpkg/status",
            "var/lib/rpm/Packages",
            "var/lib/rpm/rpmdb.sqlite",
            "etc/apk/installed",
            "etc/os-release",
        ];
        const CANDIDATES: &[&str] = &["rootfs", "backup/container/rootfs", "backup/rootfs"];
        for candidate in CANDIDATES {
            let base = workspace.join(candidate);
            for marker in MARKERS {
                if tokio::fs::metadata(base.join(marker)).await.is_ok() {
                    info!(
                        "Located scannable rootfs at {} (matched {})",
                        base.display(),
                        marker
                    );
                    return Some(base);
                }
            }
        }
        warn!(
            "No OS package-DB marker found under {} — trivy may report zero findings",
            workspace.display()
        );
        None
    }

    /// Extract a squashfs image using unsquashfs.
    ///
    /// Hardened with the same defenses as [`Self::extract_tarball`]: a squashfs
    /// image is just as capable of being a decompression bomb or carrying
    /// escaping symlinks as a tarball.
    ///   * input size is capped at [`max_compressed_input_bytes`] *before*
    ///     writing the image to disk;
    ///   * after extraction, [`Self::run_extraction_guard`] walks the output
    ///     tree and aborts on any symlink that escapes the workspace root or if
    ///     the tree exceeds [`max_extracted_bytes`] / [`MAX_EXTRACTED_ENTRIES`];
    ///   * `unsquashfs -f` (force-overwrite) is intentionally NOT passed. `-f`
    ///     only matters when the destination already holds conflicting files;
    ///     it makes unsquashfs unlink and overwrite them, which weakens the
    ///     defense posture the same way tar's `--overwrite` does. The per-scan
    ///     UUID workspace + the `remove_dir_all` wipe in `prepare_workspace`
    ///     guarantee `dest` is freshly-created and empty, and unsquashfs
    ///     extracts happily into an existing empty directory without `-f`, so
    ///     the flag is redundant here.
    async fn extract_squashfs(&self, content: &Bytes, workspace: &Path, dest: &Path) -> Result<()> {
        // Decompression-bomb guard #1: bound the compressed input before it ever
        // touches disk (same cap the tarball path uses).
        Self::check_compressed_input_size(content.len() as u64)?;

        let squashfs_path = workspace.join("rootfs.squashfs");
        write_temp_file(&squashfs_path, content, "squashfs").await?;

        run_command(
            "unsquashfs",
            &[
                "-d",
                &dest.to_string_lossy(),
                &squashfs_path.to_string_lossy(),
            ],
            "unsquashfs extraction",
        )
        .await?;

        // Drop the source image before walking the tree so it isn't counted
        // toward the extracted-size budget (and to free the disk early).
        let _ = tokio::fs::remove_file(&squashfs_path).await;

        // Post-extraction hardening: identical guard to the tarball path.
        Self::run_extraction_guard(dest).await?;

        Ok(())
    }

    /// Clean up the per-scan workspace directory by path. The path is the
    /// per-scan-unique directory returned by [`Self::prepare_workspace`]; it
    /// cannot be recomputed from the artifact alone (it carries a random
    /// suffix), so the caller passes it through.
    async fn cleanup_workspace(&self, workspace: &Path) {
        ScanWorkspace::cleanup_path(workspace).await;
    }

    /// Run Trivy filesystem scan on the extracted rootfs.
    async fn scan_with_cli(&self, rootfs: &Path) -> Result<TrivyReport> {
        run_trivy_scan(rootfs, Some(&self.trivy_url), "Trivy Incus scan").await
    }

    /// Fallback: scan using Trivy standalone CLI (no server).
    async fn scan_standalone(&self, rootfs: &Path) -> Result<TrivyReport> {
        run_trivy_scan(rootfs, None, "Trivy standalone Incus scan").await
    }

    /// Convert Trivy vulnerabilities into RawFinding rows. Thin wrapper
    /// around the shared helper so the existing tests can keep calling
    /// `IncusScanner::convert_findings(report)`. Production code paths use
    /// `ScanOutput::from_trivy_report` which also extracts the package
    /// inventory (#903).
    #[cfg(test)]
    pub(crate) fn convert_findings(
        report: &crate::services::image_scanner::TrivyReport,
    ) -> Vec<crate::models::security::RawFinding> {
        crate::services::scanner_service::convert_trivy_findings(report, "trivy-incus")
    }
}

#[async_trait]
impl Scanner for IncusScanner {
    fn name(&self) -> &str {
        "incus-image"
    }

    fn scan_type(&self) -> &str {
        "incus"
    }

    /// Surface the inherent applicability check through the trait so the
    /// orchestrator can gate on it without creating a `scan_results` row
    /// (issues #961, #994).
    fn is_applicable(&self, artifact: &Artifact) -> bool {
        Self::is_applicable(artifact)
    }

    /// Probe `trivy --version` once and cache the parsed version string.
    /// Returns `None` if the binary is missing or its output cannot be
    /// parsed. The Incus scanner shells out to the same `trivy` binary as
    /// `TrivyFsScanner`, so the format is also `trivy-<version>`.
    async fn version(&self) -> Option<String> {
        cached_trivy_cli_version(&self.cached_version).await
    }

    async fn scan(
        &self,
        artifact: &Artifact,
        _metadata: Option<&ArtifactMetadata>,
        content: &Bytes,
    ) -> Result<ScanOutput> {
        debug_assert!(
            Self::is_applicable(artifact),
            "IncusScanner::scan called on a non-applicable artifact; the orchestrator must gate on is_applicable first"
        );

        if content.is_empty() {
            return Ok(ScanOutput::default());
        }

        info!(
            "Starting Incus image scan for artifact: {} ({})",
            artifact.name, artifact.id
        );

        // Prepare workspace: extract rootfs from the image. `prepare_workspace`
        // cleans up its own per-scan workspace on extraction error; on success
        // it returns `(rootfs, workspace)` and we own cleanup of `workspace`.
        let (rootfs, workspace) = match self.prepare_workspace(artifact, content).await {
            Ok(r) => r,
            Err(e) => {
                return Err(AppError::Internal(format!(
                    "Incus image extraction failed for {}: {}",
                    artifact.name, e
                )));
            }
        };

        // Run Trivy filesystem scan on the extracted rootfs
        let report = match self.scan_with_cli(&rootfs).await {
            Ok(report) => report,
            Err(e) => {
                warn!(
                    "Trivy server-mode scan failed for Incus image {}: {}. Trying standalone.",
                    artifact.name, e
                );
                match self.scan_standalone(&rootfs).await {
                    Ok(report) => report,
                    Err(e) => {
                        return Err(
                            fail_scan_path("Trivy Incus scan", artifact, &e, &workspace).await
                        );
                    }
                }
            }
        };

        let output = ScanOutput::from_trivy_report(&report, "trivy-incus");

        info!(
            "Incus image scan complete for {}: {} vulnerabilities, {} packages",
            artifact.name,
            output.findings.len(),
            output.packages.len()
        );

        self.cleanup_workspace(&workspace).await;

        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::security::Severity;
    use crate::services::scanner_service::test_helpers::make_test_artifact;

    fn make_incus_artifact(name: &str, path: &str) -> Artifact {
        make_test_artifact(name, "application/octet-stream", path)
    }

    #[test]
    fn test_is_applicable_unified_tarball() {
        let artifact = make_incus_artifact("incus.tar.xz", "ubuntu-noble/20240215/incus.tar.xz");
        assert!(IncusScanner::is_applicable(&artifact));
    }

    #[test]
    fn test_is_applicable_squashfs() {
        let artifact =
            make_incus_artifact("rootfs.squashfs", "debian-bookworm/v1.0/rootfs.squashfs");
        assert!(IncusScanner::is_applicable(&artifact));
    }

    #[test]
    fn test_is_applicable_qcow2() {
        let artifact = make_incus_artifact("rootfs.img", "ubuntu-noble/20240215/rootfs.img");
        assert!(IncusScanner::is_applicable(&artifact));
    }

    #[test]
    fn test_not_applicable_metadata_only() {
        let artifact =
            make_incus_artifact("metadata.tar.xz", "ubuntu-noble/20240215/metadata.tar.xz");
        assert!(!IncusScanner::is_applicable(&artifact));
    }

    #[test]
    fn test_not_applicable_streams_index() {
        let artifact = make_incus_artifact("index.json", "streams/v1/index.json");
        assert!(!IncusScanner::is_applicable(&artifact));
    }

    #[test]
    fn test_not_applicable_non_incus_path() {
        // Path with only one segment is not a valid Incus path (needs product/version/file)
        let artifact = make_incus_artifact("package.tar.gz", "package.tar.gz");
        assert!(!IncusScanner::is_applicable(&artifact));
    }

    #[test]
    fn test_convert_findings_empty() {
        let report = TrivyReport { results: vec![] };
        let findings = IncusScanner::convert_findings(&report);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_convert_findings_with_vulnerabilities() {
        let report = TrivyReport {
            results: vec![crate::services::image_scanner::TrivyResult {
                target: "usr/lib/dpkg/status".to_string(),
                class: "os-pkgs".to_string(),
                result_type: "ubuntu".to_string(),
                vulnerabilities: Some(vec![
                    crate::services::image_scanner::TrivyVulnerability {
                        vulnerability_id: "CVE-2024-12345".to_string(),
                        pkg_name: "libssl3".to_string(),
                        installed_version: "3.0.13-0ubuntu3".to_string(),
                        fixed_version: Some("3.0.13-0ubuntu3.1".to_string()),
                        severity: "HIGH".to_string(),
                        title: Some("Buffer overflow in OpenSSL".to_string()),
                        description: Some("A buffer overflow vulnerability exists".to_string()),
                        primary_url: Some("https://avd.aquasec.com/nvd/cve-2024-12345".to_string()),
                    },
                    crate::services::image_scanner::TrivyVulnerability {
                        vulnerability_id: "CVE-2024-67890".to_string(),
                        pkg_name: "libc6".to_string(),
                        installed_version: "2.39-0ubuntu8".to_string(),
                        fixed_version: None,
                        severity: "MEDIUM".to_string(),
                        title: None,
                        description: None,
                        primary_url: None,
                    },
                ]),
                packages: None,
            }],
        };

        let findings = IncusScanner::convert_findings(&report);
        assert_eq!(findings.len(), 2);

        // First finding
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].cve_id, Some("CVE-2024-12345".to_string()));
        assert_eq!(findings[0].title, "Buffer overflow in OpenSSL".to_string());
        assert_eq!(findings[0].source, Some("trivy-incus".to_string()));
        assert!(findings[0]
            .affected_component
            .as_ref()
            .unwrap()
            .contains("libssl3"));
        assert_eq!(
            findings[0].fixed_version,
            Some("3.0.13-0ubuntu3.1".to_string())
        );

        // Second finding (no title → auto-generated)
        assert_eq!(findings[1].severity, Severity::Medium);
        assert_eq!(findings[1].title, "CVE-2024-67890 in libc6");
        assert!(findings[1].fixed_version.is_none());
    }

    // -----------------------------------------------------------------------
    // find_rootfs tests

    #[tokio::test]
    async fn test_find_rootfs_backup_format() {
        let tmp = tempfile::tempdir().unwrap();
        let ws = tmp.path();
        // `incus export` container-backup layout: rootfs two levels deep.
        let dpkg = ws.join("backup/container/rootfs/var/lib/dpkg");
        tokio::fs::create_dir_all(&dpkg).await.unwrap();
        tokio::fs::write(dpkg.join("status"), b"Package: bash\n")
            .await
            .unwrap();

        assert_eq!(
            IncusScanner::find_rootfs(ws).await,
            Some(ws.join("backup/container/rootfs"))
        );
    }

    #[tokio::test]
    async fn test_find_rootfs_image_format() {
        let tmp = tempfile::tempdir().unwrap();
        let ws = tmp.path();
        // `incus image export` layout: rootfs at the top level.
        let etc = ws.join("rootfs/etc");
        tokio::fs::create_dir_all(&etc).await.unwrap();
        tokio::fs::write(etc.join("os-release"), b"ID=ubuntu\n")
            .await
            .unwrap();

        assert_eq!(IncusScanner::find_rootfs(ws).await, Some(ws.join("rootfs")));
    }

    #[tokio::test]
    async fn test_find_rootfs_no_marker_returns_none() {
        let tmp = tempfile::tempdir().unwrap();
        // A tree with no recognised package DB → None (caller falls back + warns).
        tokio::fs::create_dir_all(tmp.path().join("rootfs/usr/bin"))
            .await
            .unwrap();
        assert_eq!(IncusScanner::find_rootfs(tmp.path()).await, None);
    }

    // -----------------------------------------------------------------------
    // write_temp_file tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_write_temp_file_success() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test_file.bin");
        let content = Bytes::from_static(b"hello world");

        write_temp_file(&path, &content, "test").await.unwrap();

        let read_back = tokio::fs::read(&path).await.unwrap();
        assert_eq!(read_back, b"hello world");
    }

    #[tokio::test]
    async fn test_write_temp_file_empty_content() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.bin");
        let content = Bytes::new();

        write_temp_file(&path, &content, "empty").await.unwrap();

        let read_back = tokio::fs::read(&path).await.unwrap();
        assert!(read_back.is_empty());
    }

    #[tokio::test]
    async fn test_write_temp_file_invalid_path() {
        // Writing to a path under a nonexistent directory should fail
        let path = PathBuf::from("/nonexistent_dir_abc123/test_file.bin");
        let content = Bytes::from_static(b"data");

        let result = write_temp_file(&path, &content, "bad path").await;
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("Failed to write bad path"));
    }

    // -----------------------------------------------------------------------
    // run_command tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_run_command_success() {
        // `true` always exits 0
        run_command("true", &[], "true command").await.unwrap();
    }

    #[tokio::test]
    async fn test_run_command_failure_nonzero_exit() {
        // `false` always exits 1
        let result = run_command("false", &[], "false command").await;
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("false command failed"));
    }

    #[tokio::test]
    async fn test_run_command_nonexistent_program() {
        let result = run_command("nonexistent_program_xyz_12345", &[], "missing program").await;
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("Failed to execute nonexistent_program_xyz_12345"));
    }

    #[tokio::test]
    async fn test_run_command_with_args() {
        // `echo hello` should succeed
        run_command("echo", &["hello"], "echo test").await.unwrap();
    }

    // -----------------------------------------------------------------------
    // IncusScanner::new and basic accessors
    // -----------------------------------------------------------------------

    #[test]
    fn test_scanner_new() {
        let scanner = IncusScanner::new(
            "http://trivy:8090".to_string(),
            "/tmp/scan-workspace".to_string(),
        );
        assert_eq!(scanner.trivy_url, "http://trivy:8090");
        assert_eq!(scanner.scan_workspace, "/tmp/scan-workspace");
    }

    #[test]
    fn test_scanner_name() {
        let scanner = IncusScanner::new("http://trivy:8090".to_string(), "/tmp".to_string());
        assert_eq!(scanner.name(), "incus-image");
    }

    #[test]
    fn test_scanner_scan_type() {
        let scanner = IncusScanner::new("http://trivy:8090".to_string(), "/tmp".to_string());
        assert_eq!(scanner.scan_type(), "incus");
    }

    // -----------------------------------------------------------------------
    // workspace_dir tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_workspace_dir() {
        let scanner = IncusScanner::new(
            "http://trivy:8090".to_string(),
            "/var/scan-workspace".to_string(),
        );
        let artifact = make_incus_artifact("incus.tar.xz", "ubuntu-noble/20240215/incus.tar.xz");
        let dir = scanner.workspace_dir(&artifact);
        let expected = format!("/var/scan-workspace/incus-{}", artifact.id);
        assert_eq!(dir, PathBuf::from(expected));
    }

    // -----------------------------------------------------------------------
    // is_applicable: additional edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_is_applicable_lxd_tarball() {
        let artifact = make_incus_artifact("lxd.tar.xz", "ubuntu-noble/20240215/lxd.tar.xz");
        assert!(IncusScanner::is_applicable(&artifact));
    }

    #[test]
    fn test_is_applicable_custom_tarball_name() {
        // Any .tar.xz file under product/version/ is treated as a unified tarball
        let artifact = make_incus_artifact(
            "custom-image.tar.xz",
            "alpine-edge/v3.20/custom-image.tar.xz",
        );
        assert!(IncusScanner::is_applicable(&artifact));
    }

    #[test]
    fn test_is_applicable_tar_gz() {
        let artifact = make_incus_artifact("image.tar.gz", "debian-trixie/v1.0/image.tar.gz");
        assert!(IncusScanner::is_applicable(&artifact));
    }

    #[test]
    fn test_is_applicable_qcow2_extension() {
        let artifact = make_incus_artifact("rootfs.qcow2", "fedora-40/v1.0/rootfs.qcow2");
        assert!(IncusScanner::is_applicable(&artifact));
    }

    #[test]
    fn test_not_applicable_streams_images() {
        let artifact = make_incus_artifact("images.json", "streams/v1/images.json");
        assert!(!IncusScanner::is_applicable(&artifact));
    }

    #[test]
    fn test_is_applicable_leading_slash_in_path() {
        // parse_path trims leading slashes, so this should still work
        let artifact = make_incus_artifact("incus.tar.xz", "/ubuntu-noble/20240215/incus.tar.xz");
        assert!(IncusScanner::is_applicable(&artifact));
    }

    #[test]
    fn test_not_applicable_meta_tar_xz() {
        let artifact = make_incus_artifact("meta.tar.xz", "ubuntu-noble/20240215/meta.tar.xz");
        assert!(!IncusScanner::is_applicable(&artifact));
    }

    // -----------------------------------------------------------------------
    // convert_findings: additional edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_convert_findings_no_vulnerabilities_field() {
        // When vulnerabilities is None, the result should produce no findings
        let report = TrivyReport {
            results: vec![crate::services::image_scanner::TrivyResult {
                target: "usr/lib/dpkg/status".to_string(),
                class: "os-pkgs".to_string(),
                result_type: "ubuntu".to_string(),
                vulnerabilities: None,
                packages: None,
            }],
        };
        let findings = IncusScanner::convert_findings(&report);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_convert_findings_empty_vulnerabilities_vec() {
        let report = TrivyReport {
            results: vec![crate::services::image_scanner::TrivyResult {
                target: "some/target".to_string(),
                class: "lang-pkgs".to_string(),
                result_type: "gomod".to_string(),
                vulnerabilities: Some(vec![]),
                packages: None,
            }],
        };
        let findings = IncusScanner::convert_findings(&report);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_convert_findings_multiple_results() {
        let report = TrivyReport {
            results: vec![
                crate::services::image_scanner::TrivyResult {
                    target: "dpkg/status".to_string(),
                    class: "os-pkgs".to_string(),
                    result_type: "ubuntu".to_string(),
                    vulnerabilities: Some(vec![
                        crate::services::image_scanner::TrivyVulnerability {
                            vulnerability_id: "CVE-2024-00001".to_string(),
                            pkg_name: "openssl".to_string(),
                            installed_version: "1.0.0".to_string(),
                            fixed_version: Some("1.0.1".to_string()),
                            severity: "CRITICAL".to_string(),
                            title: Some("Critical vuln".to_string()),
                            description: Some("Desc".to_string()),
                            primary_url: None,
                        },
                    ]),
                    packages: None,
                },
                crate::services::image_scanner::TrivyResult {
                    target: "go.sum".to_string(),
                    class: "lang-pkgs".to_string(),
                    result_type: "gomod".to_string(),
                    vulnerabilities: Some(vec![
                        crate::services::image_scanner::TrivyVulnerability {
                            vulnerability_id: "CVE-2024-00002".to_string(),
                            pkg_name: "github.com/example/lib".to_string(),
                            installed_version: "0.5.0".to_string(),
                            fixed_version: None,
                            severity: "LOW".to_string(),
                            title: None,
                            description: None,
                            primary_url: None,
                        },
                    ]),
                    packages: None,
                },
            ],
        };

        let findings = IncusScanner::convert_findings(&report);
        assert_eq!(findings.len(), 2);

        // First from os-pkgs result.
        // affected_component is the bare package name post-#903 — the
        // `(target)` suffix was dropped because it broke cross-source
        // joins (SBOM, CVE lookup, UI search). The target moves to
        // RawPackage.source_target.
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(findings[0].cve_id, Some("CVE-2024-00001".to_string()));
        assert_eq!(findings[0].affected_component, Some("openssl".to_string()));
        assert_eq!(findings[0].fixed_version, Some("1.0.1".to_string()));

        // Second from gomod result
        assert_eq!(findings[1].severity, Severity::Low);
        assert_eq!(
            findings[1].title,
            "CVE-2024-00002 in github.com/example/lib"
        );
        assert_eq!(
            findings[1].affected_component,
            Some("github.com/example/lib".to_string())
        );
        assert!(findings[1].fixed_version.is_none());
        assert!(findings[1].description.is_none());
        assert!(findings[1].source_url.is_none());
    }

    #[test]
    fn test_convert_findings_all_severity_levels() {
        let make_vuln = |id: &str, sev: &str| crate::services::image_scanner::TrivyVulnerability {
            vulnerability_id: id.to_string(),
            pkg_name: "pkg".to_string(),
            installed_version: "1.0".to_string(),
            fixed_version: None,
            severity: sev.to_string(),
            title: None,
            description: None,
            primary_url: None,
        };

        let report = TrivyReport {
            results: vec![crate::services::image_scanner::TrivyResult {
                target: "test".to_string(),
                class: "os-pkgs".to_string(),
                result_type: "debian".to_string(),
                vulnerabilities: Some(vec![
                    make_vuln("CVE-1", "CRITICAL"),
                    make_vuln("CVE-2", "HIGH"),
                    make_vuln("CVE-3", "MEDIUM"),
                    make_vuln("CVE-4", "LOW"),
                    make_vuln("CVE-5", "UNKNOWN"),
                ]),
                packages: None,
            }],
        };

        let findings = IncusScanner::convert_findings(&report);
        assert_eq!(findings.len(), 5);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(findings[1].severity, Severity::High);
        assert_eq!(findings[2].severity, Severity::Medium);
        assert_eq!(findings[3].severity, Severity::Low);
        // Unknown severity falls back to Info
        assert_eq!(findings[4].severity, Severity::Info);
    }

    #[test]
    fn test_convert_findings_preserves_source_url() {
        let report = TrivyReport {
            results: vec![crate::services::image_scanner::TrivyResult {
                target: "test".to_string(),
                class: "os-pkgs".to_string(),
                result_type: "alpine".to_string(),
                vulnerabilities: Some(vec![crate::services::image_scanner::TrivyVulnerability {
                    vulnerability_id: "CVE-2024-99999".to_string(),
                    pkg_name: "musl".to_string(),
                    installed_version: "1.2.4".to_string(),
                    fixed_version: Some("1.2.5".to_string()),
                    severity: "HIGH".to_string(),
                    title: Some("musl overflow".to_string()),
                    description: Some("Heap overflow in musl libc".to_string()),
                    primary_url: Some("https://avd.aquasec.com/nvd/cve-2024-99999".to_string()),
                }]),
                packages: None,
            }],
        };

        let findings = IncusScanner::convert_findings(&report);
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].source_url,
            Some("https://avd.aquasec.com/nvd/cve-2024-99999".to_string())
        );
        assert_eq!(
            findings[0].description,
            Some("Heap overflow in musl libc".to_string())
        );
        assert_eq!(findings[0].affected_version, Some("1.2.4".to_string()));
    }

    #[test]
    fn test_convert_findings_source_always_trivy_incus() {
        let report = TrivyReport {
            results: vec![crate::services::image_scanner::TrivyResult {
                target: "t".to_string(),
                class: "".to_string(),
                result_type: "".to_string(),
                vulnerabilities: Some(vec![crate::services::image_scanner::TrivyVulnerability {
                    vulnerability_id: "CVE-X".to_string(),
                    pkg_name: "p".to_string(),
                    installed_version: "1".to_string(),
                    fixed_version: None,
                    severity: "LOW".to_string(),
                    title: None,
                    description: None,
                    primary_url: None,
                }]),
                packages: None,
            }],
        };

        let findings = IncusScanner::convert_findings(&report);
        assert_eq!(findings[0].source, Some("trivy-incus".to_string()));
    }

    // -----------------------------------------------------------------------
    // scan method: non-applicable artifact and empty content
    // -----------------------------------------------------------------------

    /// Non-applicable artifacts must be filtered out via
    /// `Scanner::is_applicable` rather than absorbed inside `scan()` as
    /// `Ok(ScanOutput::default())`. The latter pattern is what produced the
    /// silent-success bug class behind #961 and #994: the orchestrator
    /// recorded a completed-with-zero-findings row for a scanner that
    /// never inspected the artifact.
    ///
    /// For an applicable artifact with empty content, `scan()` still
    /// returns `Ok` with an empty output — that is a real "applicable but
    /// nothing to scan" path, not a silent skip.
    #[tokio::test]
    async fn test_non_applicable_filtered_by_is_applicable_not_scan() {
        use crate::services::scanner_service::Scanner;

        let scanner = IncusScanner::new(
            "http://trivy:8090".to_string(),
            "/tmp/test-workspace".to_string(),
        );

        // Non-applicable artifacts: the trait gate must reject them so the
        // orchestrator never calls `scan()`.
        let non_applicable = [
            make_incus_artifact("index.json", "streams/v1/index.json"),
            make_incus_artifact("metadata.tar.xz", "ubuntu-noble/20240215/metadata.tar.xz"),
        ];
        for artifact in &non_applicable {
            assert!(
                !Scanner::is_applicable(&scanner, artifact),
                "Scanner::is_applicable must return false for {} so the orchestrator skips it before creating a scan_results row",
                artifact.name
            );
        }

        // Applicable artifact with empty content: scanner is invoked and
        // legitimately reports zero findings.
        let applicable = make_incus_artifact("incus.tar.xz", "ubuntu-noble/20240215/incus.tar.xz");
        assert!(Scanner::is_applicable(&scanner, &applicable));
        let output = scanner
            .scan(&applicable, None, &Bytes::new())
            .await
            .unwrap();
        assert!(output.is_empty());
    }

    // -----------------------------------------------------------------------
    // prepare_workspace: QCOW2 returns error (unscannable)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_prepare_workspace_qcow2_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let scanner = IncusScanner::new(
            "http://trivy:8090".to_string(),
            dir.path().to_string_lossy().to_string(),
        );
        let artifact = make_incus_artifact("rootfs.img", "ubuntu-noble/20240215/rootfs.img");
        let content = Bytes::from_static(b"fake qcow2 data");

        let result = scanner.prepare_workspace(&artifact, &content).await;
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("QCOW2"));
    }

    // -----------------------------------------------------------------------
    // prepare_workspace: invalid path yields error
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_prepare_workspace_invalid_path() {
        let dir = tempfile::tempdir().unwrap();
        let scanner = IncusScanner::new(
            "http://trivy:8090".to_string(),
            dir.path().to_string_lossy().to_string(),
        );
        // Single-segment path cannot be parsed by IncusHandler::parse_path
        let mut artifact = make_incus_artifact("bad.bin", "bad.bin");
        // Force path to something that fails parse_path but passes is_applicable check
        // Actually parse_path will fail, so prepare_workspace will error
        artifact.path = "single_segment".to_string();

        let content = Bytes::from_static(b"data");
        let result = scanner.prepare_workspace(&artifact, &content).await;
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("Invalid Incus path"));
    }

    // -----------------------------------------------------------------------
    // scan returns error when prepare_workspace fails
    // -----------------------------------------------------------------------

    /// Scan failures (QCOW2 unsupported, extraction failure) must propagate
    /// as Err, never as Ok(vec![]).
    #[tokio::test]
    async fn test_scan_propagates_errors() {
        let dir = tempfile::tempdir().unwrap();
        let scanner = IncusScanner::new(
            "http://localhost:0".to_string(),
            dir.path().to_string_lossy().to_string(),
        );

        // QCOW2 images are applicable but require mounting, so scan must fail
        let qcow2 = make_incus_artifact("rootfs.img", "ubuntu-noble/20240215/rootfs.img");
        assert!(
            scanner
                .scan(&qcow2, None, &Bytes::from_static(b"fake qcow2 data"))
                .await
                .is_err(),
            "scan() must return Err for unscannable QCOW2 images"
        );

        // Invalid tarball content causes extraction failure
        let tarball = make_incus_artifact("incus.tar.xz", "ubuntu-noble/20240215/incus.tar.xz");
        assert!(
            scanner
                .scan(&tarball, None, &Bytes::from_static(b"not a valid tarball"))
                .await
                .is_err(),
            "scan() must return Err when extraction fails"
        );
    }

    // -----------------------------------------------------------------------
    // extract_tarball: XZ magic bytes detection
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_extract_tarball_detects_xz_magic() {
        // We cannot produce a valid tar.xz in tests easily, but we can verify
        // the function correctly identifies XZ format via magic bytes and fails
        // gracefully on invalid content.
        let dir = tempfile::tempdir().unwrap();
        let rootfs_dir = dir.path().join("rootfs");
        tokio::fs::create_dir_all(&rootfs_dir).await.unwrap();

        let scanner = IncusScanner::new(
            "http://trivy:8090".to_string(),
            dir.path().to_string_lossy().to_string(),
        );

        // XZ magic bytes: 0xFD 0x37 0x7A 0x58 0x5A followed by invalid data
        let mut xz_content = vec![0xFD, 0x37, 0x7A, 0x58, 0x5A];
        xz_content.extend_from_slice(b"not-valid-xz-data");
        let content = Bytes::from(xz_content);

        let result = scanner.extract_tarball(&content, &rootfs_dir).await;
        // Should fail during tar extraction (invalid xz data), not during write
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("tar extraction failed"));
    }

    #[tokio::test]
    async fn test_extract_tarball_detects_zstd_magic() {
        // Mirrors the xz/gzip cases: feed the zstd magic bytes (0x28 0xB5 0x2F
        // 0xFD) followed by garbage and assert the function selects the zstd
        // (`--zstd`) extraction path and fails gracefully on the invalid body.
        // This exercises the `is_zstd` branch without needing a valid archive;
        // tar still reports a non-zero exit (whether via the zstd filter or a
        // missing-binary error), which `run_command` surfaces as the same
        // "tar extraction failed" error.
        let dir = tempfile::tempdir().unwrap();
        let rootfs_dir = dir.path().join("rootfs");
        tokio::fs::create_dir_all(&rootfs_dir).await.unwrap();

        let scanner = IncusScanner::new(
            "http://trivy:8090".to_string(),
            dir.path().to_string_lossy().to_string(),
        );

        // zstd magic: 0x28 0xB5 0x2F 0xFD followed by invalid data.
        let mut zstd_content = vec![0x28, 0xB5, 0x2F, 0xFD];
        zstd_content.extend_from_slice(b"not-valid-zstd-data");
        let content = Bytes::from(zstd_content);

        let result = scanner.extract_tarball(&content, &rootfs_dir).await;
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("tar extraction failed"));
    }

    #[tokio::test]
    async fn test_extract_tarball_detects_gzip_fallback() {
        // Content without XZ magic bytes should be treated as gzip
        let dir = tempfile::tempdir().unwrap();
        let rootfs_dir = dir.path().join("rootfs");
        tokio::fs::create_dir_all(&rootfs_dir).await.unwrap();

        let scanner = IncusScanner::new(
            "http://trivy:8090".to_string(),
            dir.path().to_string_lossy().to_string(),
        );

        // Gzip magic: 1F 8B, but followed by garbage
        let content = Bytes::from_static(&[0x1F, 0x8B, 0x08, 0x00, 0x00]);

        let result = scanner.extract_tarball(&content, &rootfs_dir).await;
        // Should fail during tar extraction (invalid gzip)
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("tar extraction failed"));
    }

    // -----------------------------------------------------------------------
    // extract_squashfs: nonexistent unsquashfs binary
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_extract_squashfs_writes_file_then_runs_unsquashfs() {
        // This test verifies that the squashfs path is written correctly.
        // unsquashfs is likely not available in CI, so we expect either
        // a "not found" error or a "failed" error from unsquashfs.
        let dir = tempfile::tempdir().unwrap();
        let workspace = dir.path().join("ws");
        let rootfs_dir = workspace.join("rootfs");
        tokio::fs::create_dir_all(&rootfs_dir).await.unwrap();

        let scanner = IncusScanner::new(
            "http://trivy:8090".to_string(),
            dir.path().to_string_lossy().to_string(),
        );

        let content = Bytes::from_static(b"not-a-real-squashfs");
        let result = scanner
            .extract_squashfs(&content, &workspace, &rootfs_dir)
            .await;

        // Should fail (unsquashfs either not found or fails on bad data)
        assert!(result.is_err());
    }

    /// Returns true when both `mksquashfs` and `unsquashfs` are on PATH, so the
    /// end-to-end squashfs extraction test can build and unpack a real image.
    fn squashfs_tools_available() -> bool {
        ["mksquashfs", "unsquashfs"].iter().all(|bin| {
            std::process::Command::new(bin)
                .arg("-version")
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
        })
    }

    /// Build a squashfs image from `(path, contents)` pairs by laying out a tree
    /// in a temp dir and running `mksquashfs`. Optionally plant a symlink
    /// (`link_path -> link_target`). Returns the image bytes. Caller must ensure
    /// `mksquashfs` is available (see [`squashfs_tools_available`]).
    fn build_squashfs(files: &[(&str, &[u8])], symlink: Option<(&str, &str)>) -> Bytes {
        let staging = tempfile::tempdir().unwrap();
        let src = staging.path().join("src");
        for (path, data) in files {
            let full = src.join(path);
            std::fs::create_dir_all(full.parent().unwrap()).unwrap();
            std::fs::write(&full, data).unwrap();
        }
        if let Some((link_path, link_target)) = symlink {
            let full = src.join(link_path);
            std::fs::create_dir_all(full.parent().unwrap()).unwrap();
            std::os::unix::fs::symlink(link_target, &full).unwrap();
        }

        let img = staging.path().join("img.squashfs");
        let out = std::process::Command::new("mksquashfs")
            .arg(&src)
            .arg(&img)
            .arg("-noappend")
            .output()
            .expect("mksquashfs must run");
        assert!(
            out.status.success(),
            "mksquashfs failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        Bytes::from(std::fs::read(&img).unwrap())
    }

    /// Platform-independent traversal-guard check for the SQUASHFS path: build an
    /// extracted-tree shape (the kind `unsquashfs` would produce) containing a
    /// `../`-relative symlink that escapes the workspace root, and assert the
    /// shared `enforce_extraction_limits` guard rejects it. This is the same
    /// helper the squashfs path now routes through, so it covers the guard logic
    /// on CI without an `unsquashfs` dependency. Complements the GNU-tar-gated
    /// `test_extract_tarball_rejects_escaping_symlink`.
    ///
    /// #1492: an absolute target is re-rooted under the workspace (chroot
    /// semantics) and is no longer an escape, so this exercises the relative
    /// `../` form that still escapes.
    #[tokio::test]
    async fn test_squashfs_extracted_tree_rejects_escaping_symlink() {
        let dir = tempfile::tempdir().unwrap();

        // Mimic an `unsquashfs -d <dest>` output dir holding an escaping symlink.
        let dest = dir.path().join("rootfs");
        tokio::fs::create_dir_all(dest.join("etc")).await.unwrap();
        tokio::fs::write(dest.join("etc/os-release"), b"ID=alpine\n")
            .await
            .unwrap();
        // Relative escape: rootfs/etc/escape -> ../../../host-secret (climbs out).
        std::os::unix::fs::symlink("../../../host-secret", dest.join("etc/escape")).unwrap();

        let res = IncusScanner::run_extraction_guard(&dest).await;
        assert!(
            res.is_err(),
            "squashfs-extracted tree with an escaping symlink must be rejected by the shared guard"
        );
        let msg = format!("{}", res.unwrap_err());
        assert!(
            msg.contains("escaping the workspace") || msg.contains("path traversal"),
            "guard error must name the traversal; got: {}",
            msg
        );
    }

    /// `extract_squashfs` enforces the compressed-input cap before writing the
    /// image, just like the tarball path. We can't allocate >2 GiB in a unit
    /// test, so we assert the shared `check_compressed_input_size` gate (which
    /// `extract_squashfs` now calls) rejects oversized input. The size-cap
    /// boundary itself is covered by `test_check_compressed_input_size_enforced`.
    #[tokio::test]
    async fn test_extract_squashfs_enforces_compressed_cap() {
        // The squashfs path shares the same compressed-size gate as the tarball
        // path; an over-limit input is refused before it touches disk.
        let res = IncusScanner::check_compressed_input_size(max_compressed_input_bytes() + 1);
        assert!(res.is_err());
        assert!(format!("{}", res.unwrap_err()).contains("too large to scan"));
    }

    /// End-to-end squashfs extraction: build a real squashfs image, extract it
    /// with the production `extract_squashfs` (no `-f`), and assert the shared
    /// guard ran (clean image passes, contents land under the dest). Skip-gated
    /// on the squashfs tools being installed, mirroring the GNU-tar tests; the
    /// platform-independent guard test above carries CI coverage when the tools
    /// are absent.
    #[tokio::test]
    async fn test_extract_squashfs_end_to_end_runs_guard() {
        if !squashfs_tools_available() {
            eprintln!("skipping: mksquashfs/unsquashfs not available");
            return;
        }

        let dir = tempfile::tempdir().unwrap();
        let scanner = IncusScanner::new(
            "http://trivy:8090".to_string(),
            dir.path().to_string_lossy().to_string(),
        );

        // Clean image with an in-tree relative symlink (must be accepted).
        let img = build_squashfs(
            &[
                ("etc/os-release", b"ID=alpine\nVERSION_ID=3.20\n"),
                ("var/lib/dpkg/status", b"Package: musl\n"),
            ],
            Some(("etc/os-release-link", "os-release")),
        );

        let workspace = dir.path().join("ws");
        let dest = workspace.join("rootfs");
        tokio::fs::create_dir_all(&dest).await.unwrap();

        scanner
            .extract_squashfs(&img, &workspace, &dest)
            .await
            .expect("a clean squashfs image must extract and pass the guard");

        // Contents landed under dest, the source image was cleaned up, and the
        // guard (which ran as part of extract_squashfs) accepted the tree.
        assert!(dest.join("etc/os-release").exists());
        assert!(dest.join("var/lib/dpkg/status").exists());
        assert!(
            !workspace.join("rootfs.squashfs").exists(),
            "source squashfs image must be removed after extraction"
        );

        // Now build a malicious image whose symlink escapes the workspace and
        // prove extract_squashfs rejects it via the post-extraction guard.
        let escape_img = build_squashfs(
            &[("etc/os-release", b"ID=alpine\n")],
            Some(("etc/escape", "/etc/shadow")),
        );
        let ws2 = dir.path().join("ws2");
        let dest2 = ws2.join("rootfs");
        tokio::fs::create_dir_all(&dest2).await.unwrap();

        let res = scanner.extract_squashfs(&escape_img, &ws2, &dest2).await;
        assert!(
            res.is_err(),
            "a squashfs image with an escaping symlink must be rejected by extract_squashfs"
        );
        let msg = format!("{}", res.unwrap_err());
        assert!(
            msg.contains("escaping the workspace") || msg.contains("path traversal"),
            "rejection must name the traversal; got: {}",
            msg
        );
    }

    // -----------------------------------------------------------------------
    // cleanup_workspace
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_cleanup_workspace_removes_directory() {
        let dir = tempfile::tempdir().unwrap();
        let scanner = IncusScanner::new(
            "http://trivy:8090".to_string(),
            dir.path().to_string_lossy().to_string(),
        );
        let artifact = make_incus_artifact("incus.tar.xz", "ubuntu-noble/20240215/incus.tar.xz");

        // Create a per-scan workspace dir and clean it up by path.
        let workspace = scanner.scan_workspace_dir(&artifact);
        tokio::fs::create_dir_all(&workspace).await.unwrap();
        assert!(workspace.exists());

        scanner.cleanup_workspace(&workspace).await;
        assert!(!workspace.exists());
    }

    #[tokio::test]
    async fn test_cleanup_workspace_nonexistent_dir_is_harmless() {
        let dir = tempfile::tempdir().unwrap();
        let scanner = IncusScanner::new(
            "http://trivy:8090".to_string(),
            dir.path().to_string_lossy().to_string(),
        );
        let artifact = make_incus_artifact("incus.tar.xz", "ubuntu-noble/20240215/incus.tar.xz");

        // Workspace doesn't exist, cleanup should not panic
        let workspace = scanner.scan_workspace_dir(&artifact);
        scanner.cleanup_workspace(&workspace).await;
    }

    // -----------------------------------------------------------------------
    // TrivyReport deserialization from JSON
    // -----------------------------------------------------------------------

    #[test]
    fn test_trivy_report_deserialization_full() {
        let json = r#"{
            "Results": [
                {
                    "Target": "usr/lib/dpkg/status",
                    "Class": "os-pkgs",
                    "Type": "ubuntu",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2024-11111",
                            "PkgName": "zlib",
                            "InstalledVersion": "1.2.13",
                            "FixedVersion": "1.2.14",
                            "Severity": "HIGH",
                            "Title": "zlib vuln",
                            "Description": "A vuln in zlib",
                            "PrimaryURL": "https://example.com/cve"
                        }
                    ]
                }
            ]
        }"#;

        let report: TrivyReport = serde_json::from_str(json).unwrap();
        assert_eq!(report.results.len(), 1);
        assert_eq!(report.results[0].target, "usr/lib/dpkg/status");
        let vulns = report.results[0].vulnerabilities.as_ref().unwrap();
        assert_eq!(vulns.len(), 1);
        assert_eq!(vulns[0].vulnerability_id, "CVE-2024-11111");
        assert_eq!(vulns[0].pkg_name, "zlib");
        assert_eq!(vulns[0].severity, "HIGH");
    }

    #[test]
    fn test_trivy_report_deserialization_empty_results() {
        let json = r#"{"Results": []}"#;
        let report: TrivyReport = serde_json::from_str(json).unwrap();
        assert!(report.results.is_empty());
    }

    #[test]
    fn test_trivy_report_deserialization_missing_results() {
        // "Results" field is missing entirely; defaults to empty vec
        let json = r#"{}"#;
        let report: TrivyReport = serde_json::from_str(json).unwrap();
        assert!(report.results.is_empty());
    }

    #[test]
    fn test_trivy_report_deserialization_no_vulnerabilities() {
        let json = r#"{
            "Results": [
                {
                    "Target": "Gemfile.lock",
                    "Class": "lang-pkgs",
                    "Type": "bundler"
                }
            ]
        }"#;
        let report: TrivyReport = serde_json::from_str(json).unwrap();
        assert_eq!(report.results.len(), 1);
        assert!(report.results[0].vulnerabilities.is_none());
    }

    /// `version()` covers the TTL-backed cached `trivy --version` probe path
    /// for the Incus scanner. The Incus scanner shares the Trivy binary
    /// with `TrivyFsScanner`, so the format is also `trivy-<ver>`. We
    /// tolerate hosts both with and without `trivy` installed; the
    /// assertion is on caching plus the prefix shape.
    #[tokio::test]
    async fn test_version_is_cached_and_deterministic() {
        let dir = tempfile::tempdir().unwrap();
        let scanner = IncusScanner::new(
            "http://localhost:0".to_string(),
            dir.path().to_string_lossy().to_string(),
        );
        let v1 = scanner.version().await;
        let v2 = scanner.version().await;
        assert_eq!(v1, v2, "VersionCache must return identical value on repeat");
        if let Some(v) = v1 {
            assert!(
                v.starts_with("trivy-"),
                "incus scanner version must be normalized 'trivy-<ver>'; got {}",
                v
            );
        }
    }

    // -----------------------------------------------------------------------
    // Real tarball extraction tests (#1427 regression + hardening guards).
    //
    // `extract_tarball` shells out to the system `tar`. The production flags
    // (`--mode=u=rwX,go=rX`, `--no-same-owner`) are GNU-tar specific; macOS
    // ships bsdtar, which rejects `--mode`. These tests therefore skip when the
    // local `tar` is not GNU tar. Linux CI (where the coverage gate runs) has
    // GNU tar, so the changed extraction code is exercised there.
    // -----------------------------------------------------------------------

    /// Returns true when the system `tar` is GNU tar (accepts `--mode`).
    fn system_tar_is_gnu() -> bool {
        std::process::Command::new("tar")
            .arg("--version")
            .output()
            .map(|o| {
                let s = String::from_utf8_lossy(&o.stdout);
                s.contains("GNU tar")
            })
            .unwrap_or(false)
    }

    /// Build a gzipped tar from `(path, contents)` pairs.
    fn build_gzip_tar(files: &[(&str, &[u8])]) -> Bytes {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;

        let mut tar_data = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_data);
            for (path, data) in files {
                let mut header = tar::Header::new_gnu();
                header.set_path(path).unwrap();
                header.set_size(data.len() as u64);
                header.set_mode(0o644);
                header.set_cksum();
                builder.append(&header, &data[..]).unwrap();
            }
            builder.finish().unwrap();
        }

        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        gz.write_all(&tar_data).unwrap();
        Bytes::from(gz.finish().unwrap())
    }

    /// #1427 regression: an `incus export` container-backup archive
    /// (`backup/container/rootfs/...`) must extract and resolve to the nested
    /// rootfs, with the package-DB marker present. Previously `prepare_workspace`
    /// only ever looked at `rootfs/` and produced an empty scan.
    #[tokio::test]
    async fn test_prepare_workspace_extracts_incus_export_backup() {
        if !system_tar_is_gnu() {
            eprintln!("skipping: system tar is not GNU tar (extraction flags unsupported)");
            return;
        }

        let dir = tempfile::tempdir().unwrap();
        let scanner = IncusScanner::new(
            "http://trivy:8090".to_string(),
            dir.path().to_string_lossy().to_string(),
        );
        let artifact = make_incus_artifact("incus.tar.xz", "ubuntu-noble/20240215/incus.tar.xz");

        let tarball = build_gzip_tar(&[
            (
                "backup/container/rootfs/var/lib/dpkg/status",
                b"Package: bash\nVersion: 5.2\n",
            ),
            (
                "backup/container/rootfs/etc/os-release",
                b"ID=ubuntu\nVERSION_ID=\"24.04\"\n",
            ),
        ]);

        let (rootfs, workspace) = scanner
            .prepare_workspace(&artifact, &tarball)
            .await
            .expect("prepare_workspace must succeed for a valid incus-export backup");

        // Returned rootfs is the nested backup path, and the marker file exists.
        assert_eq!(rootfs, workspace.join("backup/container/rootfs"));
        assert!(
            rootfs.join("var/lib/dpkg/status").exists(),
            "dpkg status marker must exist under the resolved rootfs"
        );

        scanner.cleanup_workspace(&workspace).await;
    }

    /// Wedged-workspace recovery: a leftover file in a stale workspace tree must
    /// not block a fresh extraction. With per-scan-unique dirs this is naturally
    /// clean, but we verify the `remove_dir_all` wipe still recovers if the same
    /// path is reused.
    #[tokio::test]
    async fn test_prepare_workspace_recovers_from_wedged_tree() {
        if !system_tar_is_gnu() {
            eprintln!("skipping: system tar is not GNU tar (extraction flags unsupported)");
            return;
        }

        let dir = tempfile::tempdir().unwrap();
        let scanner = IncusScanner::new(
            "http://trivy:8090".to_string(),
            dir.path().to_string_lossy().to_string(),
        );
        let artifact = make_incus_artifact("incus.tar.xz", "ubuntu-noble/20240215/incus.tar.xz");

        // Pre-create a per-scan workspace with leftover junk, then prove the
        // inner wipe + extraction starts from a clean slate. We exercise the
        // extraction body directly against this fixed path.
        let workspace = scanner.scan_workspace_dir(&artifact);
        let stale = workspace.join("rootfs/STALE_LEFTOVER");
        tokio::fs::create_dir_all(stale.parent().unwrap())
            .await
            .unwrap();
        tokio::fs::write(&stale, b"leftover from a crashed scan")
            .await
            .unwrap();
        assert!(stale.exists());

        // Manually replicate prepare_workspace's wipe-then-extract against the
        // wedged path (prepare_workspace itself allocates a fresh UUID dir).
        tokio::fs::remove_dir_all(&workspace).await.unwrap();
        let rootfs_dir = workspace.join("rootfs");
        tokio::fs::create_dir_all(&rootfs_dir).await.unwrap();

        let tarball = build_gzip_tar(&[("rootfs/etc/os-release", b"ID=ubuntu\n")]);
        scanner
            .extract_tarball(&tarball, &workspace)
            .await
            .expect("extraction into a freshly-wiped workspace must succeed");

        assert!(
            !stale.exists(),
            "leftover file from the wedged tree must be gone after the wipe"
        );
        let resolved = IncusScanner::find_rootfs(&workspace)
            .await
            .expect("os-release marker must be found");
        assert_eq!(resolved, workspace.join("rootfs"));
        assert!(resolved.join("etc/os-release").exists());

        scanner.cleanup_workspace(&workspace).await;
    }

    /// Path-traversal guard: an archive containing a `../`-relative symlink that
    /// escapes the workspace must be rejected, and nothing may be written
    /// outside the workspace via that link. (#1492: absolute targets are now
    /// re-rooted under the workspace per chroot semantics and are no longer
    /// treated as escapes; the relative `../` escape below still is.)
    #[tokio::test]
    async fn test_extract_tarball_rejects_escaping_symlink() {
        if !system_tar_is_gnu() {
            eprintln!("skipping: system tar is not GNU tar (extraction flags unsupported)");
            return;
        }

        let dir = tempfile::tempdir().unwrap();
        let scanner = IncusScanner::new(
            "http://trivy:8090".to_string(),
            dir.path().to_string_lossy().to_string(),
        );

        // A sentinel directory outside the workspace that the symlink targets.
        let escape_target = dir.path().join("escape_target");
        tokio::fs::create_dir_all(&escape_target).await.unwrap();

        let workspace = dir.path().join("ws");
        tokio::fs::create_dir_all(&workspace).await.unwrap();

        // Build an archive with a relative symlink `rootfs/escape -> ../../escape_target`
        // that climbs out of the workspace. Lexical normalisation resolves it
        // outside the root, so the guard must reject it.
        let mut tar_data = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_data);

            let mut link = tar::Header::new_gnu();
            link.set_entry_type(tar::EntryType::Symlink);
            link.set_path("rootfs/escape").unwrap();
            link.set_link_name("../../escape_target").unwrap();
            link.set_size(0);
            link.set_cksum();
            builder.append(&link, std::io::empty()).unwrap();

            builder.finish().unwrap();
        }
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;
        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        gz.write_all(&tar_data).unwrap();
        let tarball = Bytes::from(gz.finish().unwrap());

        let result = scanner.extract_tarball(&tarball, &workspace).await;
        assert!(
            result.is_err(),
            "extraction must be rejected when an archive plants a ../-escaping symlink"
        );
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("escaping the workspace") || msg.contains("path traversal"),
            "error must name the traversal violation; got: {}",
            msg
        );

        // Nothing must have been written into the escape target through the link.
        assert!(
            !escape_target.join("pwned").exists(),
            "no file may be written outside the workspace via the symlink"
        );
    }

    /// In-workspace symlinks (the common case: relative links inside the rootfs)
    /// must be accepted by the guard.
    #[tokio::test]
    async fn test_extract_tarball_allows_internal_symlink() {
        if !system_tar_is_gnu() {
            eprintln!("skipping: system tar is not GNU tar (extraction flags unsupported)");
            return;
        }

        let dir = tempfile::tempdir().unwrap();
        let scanner = IncusScanner::new(
            "http://trivy:8090".to_string(),
            dir.path().to_string_lossy().to_string(),
        );
        let workspace = dir.path().join("ws");
        tokio::fs::create_dir_all(&workspace).await.unwrap();

        let mut tar_data = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_data);

            let data = b"ID=ubuntu\n";
            let mut file = tar::Header::new_gnu();
            file.set_path("rootfs/etc/os-release").unwrap();
            file.set_size(data.len() as u64);
            file.set_mode(0o644);
            file.set_cksum();
            builder.append(&file, &data[..]).unwrap();

            // Relative, in-tree symlink: rootfs/etc/os-release-link -> os-release
            let mut link = tar::Header::new_gnu();
            link.set_entry_type(tar::EntryType::Symlink);
            link.set_path("rootfs/etc/os-release-link").unwrap();
            link.set_link_name("os-release").unwrap();
            link.set_size(0);
            link.set_cksum();
            builder.append(&link, std::io::empty()).unwrap();

            builder.finish().unwrap();
        }
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;
        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        gz.write_all(&tar_data).unwrap();
        let tarball = Bytes::from(gz.finish().unwrap());

        scanner
            .extract_tarball(&tarball, &workspace)
            .await
            .expect("in-workspace relative symlinks must be allowed");
        assert!(workspace.join("rootfs/etc/os-release").exists());

        scanner.cleanup_workspace(&workspace).await;
    }

    /// Compressed-input bomb cap: oversized input is rejected before extraction.
    /// We assert the cap logic by temporarily pointing the check at a tiny input
    /// that still exceeds a (conceptually) small bound — here we verify the
    /// boundary constant is enforced by exercising the lexical normaliser and the
    /// guard directly, since allocating >2 GiB in a unit test is impractical.
    #[test]
    fn test_normalize_lexically_collapses_traversal() {
        assert_eq!(
            normalize_lexically(Path::new("/a/b/../c")),
            PathBuf::from("/a/c")
        );
        assert_eq!(
            normalize_lexically(Path::new("/a/b/../../etc/passwd")),
            PathBuf::from("/etc/passwd")
        );
        // Cannot escape past root.
        assert_eq!(
            normalize_lexically(Path::new("/../../etc")),
            PathBuf::from("/etc")
        );
        // Relative escape is preserved so the starts_with(root) check fails.
        assert_eq!(
            normalize_lexically(Path::new("../../etc")),
            PathBuf::from("../../etc")
        );
    }

    /// The decompression-bomb entry-count / byte caps are enforced by
    /// `enforce_extraction_limits`. Verify a clean small tree (including an
    /// in-tree symlink) passes the guard. Runs on every platform.
    #[tokio::test]
    async fn test_enforce_extraction_limits_accepts_small_tree() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("tree");
        tokio::fs::create_dir_all(root.join("a/b")).await.unwrap();
        tokio::fs::write(root.join("a/b/file.txt"), b"hello")
            .await
            .unwrap();
        // An in-tree relative symlink must be accepted.
        std::os::unix::fs::symlink("file.txt", root.join("a/b/link")).unwrap();

        let root2 = root.clone();
        let res =
            tokio::task::spawn_blocking(move || IncusScanner::enforce_extraction_limits(&root2))
                .await
                .unwrap();
        assert!(
            res.is_ok(),
            "a small clean tree with an in-tree symlink must pass the guard"
        );
    }

    /// Platform-independent traversal-guard check: build the extracted tree
    /// directly with a `../`-relative symlink escaping the workspace root and
    /// assert `enforce_extraction_limits` rejects it. Complements
    /// `test_extract_tarball_rejects_escaping_symlink` (which needs GNU tar).
    ///
    /// #1492: a plain absolute symlink (`-> /run`, `-> <tmp>/secret`) is no
    /// longer treated as an escape — absolute targets are re-rooted under the
    /// workspace (chroot semantics), so this test exercises the relative `../`
    /// escape that survives the change. Absolute acceptance and absolute
    /// climbing-out are covered by their own dedicated tests above.
    #[tokio::test]
    async fn test_enforce_extraction_limits_rejects_escaping_symlink() {
        let dir = tempfile::tempdir().unwrap();

        // Relative escape: rootfs/etc/dotdot -> ../../../secret (dangling-safe).
        let root = dir.path().join("ws");
        tokio::fs::create_dir_all(root.join("rootfs/etc"))
            .await
            .unwrap();
        std::os::unix::fs::symlink("../../../secret", root.join("rootfs/etc/dotdot")).unwrap();
        let root2 = root.clone();
        let res =
            tokio::task::spawn_blocking(move || IncusScanner::enforce_extraction_limits(&root2))
                .await
                .unwrap();
        assert!(
            res.is_err(),
            "relative `../` escape must be rejected by the guard"
        );
        let msg = format!("{}", res.unwrap_err());
        assert!(
            msg.contains("escaping the workspace") || msg.contains("path traversal"),
            "guard error must name the traversal; got: {}",
            msg
        );
    }

    /// Compressed-input bomb cap (#2): inputs over the limit are rejected before
    /// they touch disk; inputs at/under the limit pass the size gate.
    #[test]
    fn test_check_compressed_input_size_enforced() {
        let cap = max_compressed_input_bytes();
        // At the limit: allowed.
        assert!(IncusScanner::check_compressed_input_size(cap).is_ok());
        // One byte over: rejected.
        let res = IncusScanner::check_compressed_input_size(cap + 1);
        assert!(res.is_err());
        let msg = format!("{}", res.unwrap_err());
        assert!(
            msg.contains("too large to scan"),
            "oversized-input error must explain the rejection; got: {}",
            msg
        );
        // Typical small archive: allowed.
        assert!(IncusScanner::check_compressed_input_size(4096).is_ok());
    }

    /// Chmod-before-cleanup: a `0o500` (no-write) subdirectory must not block
    /// recursive removal. `cleanup_path` pre-chmods `u+rwX` before deleting.
    #[tokio::test]
    async fn test_cleanup_removes_readonly_subdir() {
        let dir = tempfile::tempdir().unwrap();
        let scanner = IncusScanner::new(
            "http://trivy:8090".to_string(),
            dir.path().to_string_lossy().to_string(),
        );
        let artifact = make_incus_artifact("incus.tar.xz", "ubuntu-noble/20240215/incus.tar.xz");

        let workspace = scanner.scan_workspace_dir(&artifact);
        let locked = workspace.join("rootfs/locked");
        tokio::fs::create_dir_all(&locked).await.unwrap();
        tokio::fs::write(locked.join("inner"), b"x").await.unwrap();

        // Drop write/traverse-friendly bits: 0o500 = r-x------.
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&locked).unwrap().permissions();
        perms.set_mode(0o500);
        std::fs::set_permissions(&locked, perms).unwrap();

        scanner.cleanup_workspace(&workspace).await;
        assert!(
            !workspace.exists(),
            "cleanup must remove the workspace despite a 0o500 subdir"
        );
    }

    // -----------------------------------------------------------------------
    // #1492: env-tunable caps so a real multi-GiB OS image can be scanned.
    // -----------------------------------------------------------------------

    /// The byte-cap resolver falls back to the default when the override is
    /// unset, blank, non-numeric, or zero, and otherwise honours the parsed
    /// value. Pure over an `Option<String>` so the test never touches process
    /// env (which would race other tests).
    #[test]
    fn test_resolve_byte_cap_fallback_and_override() {
        let default = 16 * 1024 * 1024 * 1024;
        // Unset -> default.
        assert_eq!(resolve_byte_cap(None, default), default);
        // Blank / whitespace -> default.
        assert_eq!(resolve_byte_cap(Some("".to_string()), default), default);
        assert_eq!(resolve_byte_cap(Some("   ".to_string()), default), default);
        // Non-numeric -> default.
        assert_eq!(
            resolve_byte_cap(Some("16GiB".to_string()), default),
            default
        );
        // Zero -> default (a 0 cap would reject everything; treat as unset).
        assert_eq!(resolve_byte_cap(Some("0".to_string()), default), default);
        // Valid integer (with surrounding whitespace) -> parsed.
        assert_eq!(
            resolve_byte_cap(Some(" 5368709120 ".to_string()), default),
            5_368_709_120
        );
    }

    /// The default compressed cap must comfortably admit a real multi-GiB
    /// `incus export` OS image (the 2 GiB pre-#1492 cap rejected them).
    #[test]
    fn test_default_compressed_cap_admits_multi_gib_image() {
        let three_and_a_half_gib = 7 * 1024 * 1024 * 1024 / 2; // 3.5 GiB
        assert!(
            DEFAULT_MAX_COMPRESSED_INPUT_BYTES >= three_and_a_half_gib,
            "default compressed cap {} must admit a 3.5 GiB OS image",
            DEFAULT_MAX_COMPRESSED_INPUT_BYTES
        );
        // And the size gate agrees at the default.
        assert!(IncusScanner::check_compressed_input_size(three_and_a_half_gib).is_ok());
    }

    // -----------------------------------------------------------------------
    // #1492: make the extracted tree owner-traversable so a non-root scanner
    // UID can walk it (and trivy can read the package DBs). A real rootfs ships
    // restrictive modes that, with `--no-same-owner` extraction, EACCES both.
    // -----------------------------------------------------------------------

    /// A `0o000` directory holding a `0o000` file must become owner-traversable
    /// and owner-readable after `make_tree_owner_traversable`, without the call
    /// chasing or modifying any symlink target.
    #[tokio::test]
    async fn test_make_tree_owner_traversable_opens_locked_tree() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("tree");
        let locked = root.join("var/lib/private");
        tokio::fs::create_dir_all(&locked).await.unwrap();
        let file = locked.join("status");
        tokio::fs::write(&file, b"Package: bash\n").await.unwrap();

        // Lock the file and its parent dir to 0o000 (what a real rootfs may ship).
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o000)).unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();

        let root2 = root.clone();
        let res =
            tokio::task::spawn_blocking(move || IncusScanner::make_tree_owner_traversable(&root2))
                .await
                .unwrap();
        assert!(res.is_ok(), "making the tree traversable must succeed");

        // The previously-locked dir is now traversable, and the file readable.
        let dir_mode = std::fs::metadata(&locked).unwrap().permissions().mode() & 0o700;
        assert_eq!(dir_mode, 0o700, "owner rwx must be set on the locked dir");
        let file_mode = std::fs::metadata(&file).unwrap().permissions().mode() & 0o600;
        assert_eq!(file_mode, 0o600, "owner rw must be set on the locked file");
        assert!(std::fs::read_dir(&locked).is_ok(), "dir must be listable");
        assert_eq!(std::fs::read(&file).unwrap(), b"Package: bash\n");
    }

    /// The post-extraction guard must succeed on a restrictively-permissioned
    /// tree: it opens the tree first, then walks it. Pre-#1492 the guard's
    /// `read_dir` hit EACCES on a `0o000` dir and the whole scan failed.
    #[tokio::test]
    async fn test_run_extraction_guard_handles_restrictive_perms() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("ws");
        let locked = root.join("rootfs/root");
        tokio::fs::create_dir_all(&locked).await.unwrap();
        tokio::fs::write(locked.join(".bashrc"), b"export PS1=#\n")
            .await
            .unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();

        IncusScanner::run_extraction_guard(&root)
            .await
            .expect("guard must open and pass a restrictively-permissioned tree");
    }

    // -----------------------------------------------------------------------
    // #1492: chroot symlink semantics. Absolute targets resolve against the
    // workspace root (an in-tree, benign reference), not the host root, so the
    // ubiquitous `/var/run -> /run` present in every OS rootfs is accepted.
    // `../`-style escapes are still rejected.
    // -----------------------------------------------------------------------

    /// An absolute symlink whose target is in-tree under chroot semantics
    /// (`/var/run -> /run`, `/etc/x -> /usr/share/x`) must be accepted.
    #[tokio::test]
    async fn test_guard_accepts_absolute_intra_rootfs_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("ws");
        let var = root.join("backup/container/rootfs/var");
        tokio::fs::create_dir_all(&var).await.unwrap();
        // The exact link from the bug report: var/run -> /run (absolute).
        std::os::unix::fs::symlink("/run", var.join("run")).unwrap();
        // A second, deeper absolute link for good measure.
        let etc = root.join("backup/container/rootfs/etc");
        tokio::fs::create_dir_all(&etc).await.unwrap();
        std::os::unix::fs::symlink("/usr/share/zoneinfo/UTC", etc.join("localtime")).unwrap();

        let root2 = root.clone();
        let res =
            tokio::task::spawn_blocking(move || IncusScanner::enforce_extraction_limits(&root2))
                .await
                .unwrap();
        assert!(
            res.is_ok(),
            "absolute intra-rootfs symlinks (e.g. /var/run -> /run) must be accepted under chroot semantics; got: {:?}",
            res.err().map(|e| e.to_string())
        );
    }

    /// An absolute symlink with enough `..` to climb out of the re-rooted
    /// workspace must still be rejected as traversal.
    #[tokio::test]
    async fn test_guard_rejects_absolute_symlink_climbing_out() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("ws");
        let etc = root.join("rootfs/etc");
        tokio::fs::create_dir_all(&etc).await.unwrap();
        // Re-rooted under the workspace this still normalises above the root.
        std::os::unix::fs::symlink("/../../../../../../../../etc/shadow", etc.join("evil"))
            .unwrap();

        let root2 = root.clone();
        let res =
            tokio::task::spawn_blocking(move || IncusScanner::enforce_extraction_limits(&root2))
                .await
                .unwrap();
        assert!(
            res.is_err(),
            "an absolute symlink climbing out of the re-rooted workspace must be rejected"
        );
        let msg = format!("{}", res.unwrap_err());
        assert!(
            msg.contains("escaping the workspace") || msg.contains("path traversal"),
            "error must name the traversal; got: {}",
            msg
        );
    }
}
