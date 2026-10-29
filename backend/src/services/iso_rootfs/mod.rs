//! Package inventory of ISO9660 live and installer media (#1966).
//!
//! An uploaded `.iso` used to be staged as one opaque file: the engines
//! cataloged nothing inside it, and the scan read as a clean grade. This
//! module turns such an image into something the engines can inventory:
//!
//! 1. [`locator::locate_rootfs`] finds the embedded root filesystem image
//!    (`live/filesystem.squashfs`, `casper/filesystem.squashfs`,
//!    `LiveOS/squashfs.img`, `images/install.img`) by reading the volume
//!    descriptor and at most two directory extents per probe, in process,
//!    bounds-checked, without a tree walk.
//! 2. Only that byte range is written to the scan workspace, and only if it
//!    is a squashfs image: a nested ISO, or anything else, is refused, so the
//!    nesting depth is fixed at two (the ISO, then one squashfs).
//! 3. `unsquashfs -lls` lists the declared sizes of the package-database
//!    paths ([`PACKAGE_DB_PATHS`]) and the extraction is refused before
//!    anything is written when they exceed the scan-workspace extraction
//!    ceilings (`MAX_SCAN_EXTRACTED_BYTES`, 200,000 entries). The declared
//!    size is what `unsquashfs` writes, so a squashfs bomb or a huge sparse
//!    file is caught before it touches the disk.
//! 4. `unsquashfs` extracts ONLY those paths into the workspace root
//!    (`-follow-symlinks` resolves links inside the image, never on the
//!    host), single-threaded, with small queues, under a wall-clock timeout,
//!    and with address-space, CPU-time and file-size rlimits on the child.
//! 5. The Incus post-extraction guard walks the result: escaping symlinks
//!    refuse the image, and the same ceilings are enforced over what was
//!    actually written. A tree without a package database is refused too.
//!
//! Every way of failing to produce a package database leaves the workspace
//! EMPTY rather than holding the raw ISO, and reports
//! [`IsoStaging::Unscannable`] with the reason. The engines then catalog
//! nothing, and because an ISO9660 upload expects a catalog
//! (`ScanWorkspace::stages_iso_rootfs`, used by the orchestrator's
//! `upload_expects_catalog`), the scan is recorded `not_cataloged` with
//! `inventory_status = 'partial'`, never a clean grade.
//!
//! The design note is `docs/plans/2026-10-23-scanner-iso-rootfs-design.md`.

pub(crate) mod locator;
#[cfg(test)]
pub(crate) mod test_iso;

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use bytes::Bytes;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
use tracing::{info, warn};

use crate::error::{AppError, Result};
use crate::services::incus_scanner::{
    classify_unsquashfs_exit, guard_extracted_tree, open_tree_for_owner, summarize_stderr,
    TreeLimits,
};

pub(crate) use locator::is_iso9660;

/// Paths extracted from the rootfs image: the OS identification files and
/// the package databases Grype, Syft and Trivy read for an OS inventory.
/// Directories bring their subtree. `-follow-symlinks` implies
/// `-no-wildcards`, so these are literal paths; a path the image lacks is a
/// warning, not an error.
pub(crate) const PACKAGE_DB_PATHS: &[&str] = &[
    "etc/os-release",
    "usr/lib/os-release",
    "etc/lsb-release",
    "etc/debian_version",
    "etc/redhat-release",
    "etc/system-release",
    "etc/system-release-cpe",
    "etc/alpine-release",
    "var/lib/dpkg",
    "var/lib/rpm",
    "usr/lib/sysimage/rpm",
    "lib/apk/db",
];

/// Files whose presence means the extracted tree holds a package database.
const PACKAGE_DB_MARKERS: &[&str] = &[
    "var/lib/dpkg/status",
    "var/lib/rpm/rpmdb.sqlite",
    "var/lib/rpm/Packages",
    "var/lib/rpm/Packages.db",
    "usr/lib/sysimage/rpm/rpmdb.sqlite",
    "usr/lib/sysimage/rpm/Packages",
    "usr/lib/sysimage/rpm/Packages.db",
    "lib/apk/db/installed",
];

/// Name of the squashfs image staged in the workspace while it is listed and
/// extracted. Removed before the engines run. No extracted path can collide
/// with it: only [`PACKAGE_DB_PATHS`] are extracted.
const STAGED_IMAGE_NAME: &str = ".ak-iso-rootfs.squashfs";

/// Wall-clock limit on the `unsquashfs -lls` listing.
const LIST_TIMEOUT: Duration = Duration::from_secs(120);

/// Wall-clock limit on the selective extraction.
const EXTRACT_TIMEOUT: Duration = Duration::from_secs(300);

/// Address-space rlimit on each `unsquashfs` child. With one processor and
/// 32 MiB data and fragment queues it needs well under 256 MiB for a full
/// desktop image; the cap stops a crafted image whose metadata tables
/// decompress to far more than the image itself from exhausting the pod.
const UNSQUASHFS_ADDRESS_SPACE_BYTES: u64 = 1024 * 1024 * 1024;

/// CPU-time rlimit on each `unsquashfs` child, in seconds: a backstop to the
/// wall-clock timeouts that also holds when the host is heavily loaded.
const UNSQUASHFS_CPU_SECONDS: u64 = 300;

/// `-da` / `-fr` queue sizes (MiB) for the extraction. The defaults are
/// 256 MiB each; the package database is small.
const UNSQUASHFS_QUEUE_MIB: &str = "32";

/// Longest stderr kept from an `unsquashfs` child.
const MAX_STDERR_BYTES: u64 = 64 * 1024;

/// Longest `unsquashfs -lls` line read. A real line is a mode, an owner, a
/// size, a date and a path (plus a symlink target), well under 8 KiB; a
/// longer one comes from a crafted image and refuses it, so the listing
/// never buffers more than this per line.
const MAX_LISTING_LINE_BYTES: u64 = 64 * 1024;

/// Ceilings and timeouts for one ISO rootfs staging.
#[derive(Debug, Clone, Copy)]
pub(crate) struct IsoLimits {
    /// Most bytes the listed package-database paths may declare, and the
    /// most the extracted tree may hold (also each file's size rlimit).
    pub max_bytes: u64,
    /// Most entries the listing and the extracted tree may hold.
    pub max_entries: u64,
    pub list_timeout: Duration,
    pub extract_timeout: Duration,
}

impl IsoLimits {
    /// The scan-workspace extraction ceilings every archive scan draws on
    /// (`MAX_SCAN_EXTRACTED_BYTES`, default 2 GiB; 200,000 entries).
    pub(crate) fn for_scan_workspace() -> Self {
        Self {
            max_bytes: crate::services::scanner_service::max_scan_extracted_bytes(),
            max_entries: crate::services::scanner_service::MAX_SCAN_EXTRACTED_ENTRIES,
            list_timeout: LIST_TIMEOUT,
            extract_timeout: EXTRACT_TIMEOUT,
        }
    }
}

/// What staging an ISO9660 image produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum IsoStaging {
    /// The package database of the rootfs found at `probe` is in the
    /// workspace root, ready for the engines.
    Extracted { probe: String },
    /// Nothing scannable could be produced; the workspace is empty.
    Unscannable(String),
}

/// Stage the package database of the ISO9660 image `content` into
/// `workspace` (an empty, freshly created scan job directory).
///
/// `Err` only for a failure of the host (the workspace cannot be written or
/// emptied); everything about the image itself, including a missing
/// `unsquashfs`, is [`IsoStaging::Unscannable`] with the workspace empty.
pub(crate) async fn stage_iso_rootfs(
    workspace: &Path,
    content: &Bytes,
    limits: IsoLimits,
) -> Result<IsoStaging> {
    stage_with("unsquashfs", workspace, content, limits).await
}

/// [`stage_iso_rootfs`] with the extractor program as a parameter, so tests
/// can stand in a fake one.
async fn stage_with(
    program: &str,
    workspace: &Path,
    content: &Bytes,
    limits: IsoLimits,
) -> Result<IsoStaging> {
    let located = match locator::locate_rootfs(content) {
        Ok(located) => located,
        Err(e) => return Ok(IsoStaging::Unscannable(e.to_string())),
    };
    let (Ok(start), Ok(len)) = (
        usize::try_from(located.offset),
        usize::try_from(located.len),
    ) else {
        return Ok(IsoStaging::Unscannable(format!(
            "{} is too large to stage",
            located.probe
        )));
    };
    // The locator bounds-checked the range against `content`.
    let image = content.slice(start..start + len);
    if locator::is_iso9660(&image) {
        return Ok(IsoStaging::Unscannable(format!(
            "{} is itself an ISO9660 image; nested images past the squashfs rootfs are not unpacked",
            located.probe
        )));
    }
    if !image.starts_with(locator::SQUASHFS_MAGIC) {
        return Ok(IsoStaging::Unscannable(format!(
            "{} is not a squashfs image",
            located.probe
        )));
    }

    let staged = workspace.join(STAGED_IMAGE_NAME);
    // `image` is passed by value: `tokio::fs::write` takes an owned `Bytes`
    // as it is, but copies a borrowed buffer into a new `Vec` first, which
    // for a multi-GiB rootfs would double the scan's memory.
    tokio::fs::write(&staged, image).await.map_err(|e| {
        AppError::Internal(format!(
            "Failed to write the ISO rootfs image to the scan workspace: {}",
            e
        ))
    })?;

    let outcome = extract_package_db(program, &staged, workspace, &limits).await;
    // The image goes before the engines run (and before the guard counts
    // the tree), whatever happened.
    let _ = tokio::fs::remove_file(&staged).await;

    match outcome {
        Ok(()) => Ok(IsoStaging::Extracted {
            probe: located.probe,
        }),
        Err(reason) => {
            empty_workspace(workspace).await?;
            Ok(IsoStaging::Unscannable(format!(
                "{}: {}",
                located.probe, reason
            )))
        }
    }
}

/// List, extract and check the package database. `Err` carries the reason
/// the image is unscannable; the caller empties the workspace.
async fn extract_package_db(
    program: &str,
    image: &Path,
    dest: &Path,
    limits: &IsoLimits,
) -> std::result::Result<(), String> {
    let listed = list_declared(program, image, limits).await?;
    info!(
        "ISO rootfs package-database paths declare {} bytes in {} entries",
        listed.bytes, listed.entries
    );

    extract_paths(program, image, dest, limits).await?;

    // The image is still in `dest`; the guard must not count it, and it is
    // removed by the caller right after, so walk without it.
    let _ = tokio::fs::remove_file(image).await;
    guard_extracted_tree(
        dest,
        TreeLimits {
            max_bytes: limits.max_bytes,
            max_entries: limits.max_entries,
            label: "ISO rootfs image",
            reject_special_files: true,
        },
    )
    .await
    .map_err(|e| e.to_string())?;

    for marker in PACKAGE_DB_MARKERS {
        if tokio::fs::symlink_metadata(dest.join(marker))
            .await
            .is_ok_and(|m| m.is_file())
        {
            return Ok(());
        }
    }
    Err("the root filesystem image holds no dpkg, rpm or apk package database".to_string())
}

/// Totals of an `unsquashfs -lls` listing.
#[derive(Debug, Default, PartialEq, Eq)]
struct Listed {
    entries: u64,
    bytes: u64,
    /// Device nodes, FIFOs and sockets listed. A package database holds
    /// none, and an engine opening one could block or read a device, so any
    /// refuses the image before extraction.
    special: u64,
}

impl Listed {
    /// Account for one listing line. Lines that are not listing entries
    /// (warnings, a name split by an embedded newline) are ignored: they can
    /// only come in addition to the real entry lines, never instead of them.
    fn add_line(&mut self, line: &str) {
        let mut fields = line.split_whitespace();
        let Some(mode) = fields.next() else {
            return;
        };
        let Some(kind) = mode
            .chars()
            .next()
            .filter(|_| mode.len() == 10 && mode.is_ascii())
        else {
            return;
        };
        if !"-dlcbps".contains(kind) {
            return;
        }
        self.entries += 1;
        if "cbps".contains(kind) {
            self.special += 1;
        }
        if kind == '-' {
            let size = fields.nth(1).and_then(|s| s.parse::<u64>().ok());
            self.bytes = self.bytes.saturating_add(size.unwrap_or(u64::MAX));
        }
    }
}

/// `unsquashfs -lls -follow-symlinks <image> <paths>`: the declared size of
/// everything the extraction would write, read from the image's directory
/// and inode tables only. The listing is read as it streams and the child is
/// killed as soon as a ceiling is crossed, so a directory with millions of
/// entries does not have to be listed in full to be refused.
async fn list_declared(
    program: &str,
    image: &Path,
    limits: &IsoLimits,
) -> std::result::Result<Listed, String> {
    let mut args: Vec<String> = vec!["-lls".into(), "-follow-symlinks".into()];
    args.push(image.to_string_lossy().into_owned());
    args.extend(PACKAGE_DB_PATHS.iter().map(|p| p.to_string()));

    let mut command = unsquashfs_command(program, limits);
    command
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|e| format!("cannot run {}: {}", program, e))?;
    let stdout = child.stdout.take().ok_or("no listing output")?;
    let stderr = child.stderr.take().ok_or("no listing error output")?;
    let stderr_task = tokio::spawn(read_capped(stderr));

    let run = async {
        let mut listed = Listed::default();
        let mut reader = BufReader::new(stdout);
        let mut buf: Vec<u8> = Vec::new();
        loop {
            buf.clear();
            match (&mut reader)
                .take(MAX_LISTING_LINE_BYTES + 1)
                .read_until(b'\n', &mut buf)
                .await
            {
                Ok(0) => break,
                Ok(_) => {
                    if buf.len() as u64 > MAX_LISTING_LINE_BYTES {
                        return Err(format!(
                            "a squashfs listing line is longer than {} bytes",
                            MAX_LISTING_LINE_BYTES
                        ));
                    }
                    // Non-UTF-8 names: the listing cannot be trusted line by line.
                    let Ok(line) = std::str::from_utf8(&buf) else {
                        return Err("unreadable squashfs listing: not UTF-8".to_string());
                    };
                    listed.add_line(line);
                    if listed.special > 0 {
                        return Err(
                            "the package-database paths hold a device node, FIFO or socket"
                                .to_string(),
                        );
                    }
                    if listed.entries > limits.max_entries {
                        return Err(format!(
                            "the package-database paths hold more than {} entries; refusing to extract suspected decompression bomb",
                            limits.max_entries
                        ));
                    }
                    if listed.bytes > limits.max_bytes {
                        return Err(format!(
                            "the package-database paths declare more than {} bytes; refusing to extract suspected decompression bomb",
                            limits.max_bytes
                        ));
                    }
                }
                Err(e) => return Err(format!("unreadable squashfs listing: {}", e)),
            }
        }
        let status = child
            .wait()
            .await
            .map_err(|e| format!("squashfs listing did not finish: {}", e))?;
        Ok((listed, status))
    };
    let (listed, status) = match tokio::time::timeout(limits.list_timeout, run).await {
        Ok(Ok(done)) => done,
        Ok(Err(reason)) => return Err(reason),
        Err(_) => {
            return Err(format!(
                "squashfs listing did not finish within {} s",
                limits.list_timeout.as_secs()
            ))
        }
    };
    let stderr = stderr_task.await.unwrap_or_default();
    if !status.success() {
        return Err(format!(
            "squashfs listing failed ({}): {}",
            status,
            summarize_stderr(&stderr)
        ));
    }
    Ok(listed)
}

/// `unsquashfs` extracting only [`PACKAGE_DB_PATHS`] into `dest`, with the
/// Incus flags (`-no-xattrs -quiet -no-progress`) and exit classification
/// (#4470): exit 2 from device nodes the non-root UID cannot create is a
/// warning, anything else non-zero, a signal (an rlimit) or the timeout is a
/// failure. `-f` and `-ignore-errors` are never passed.
async fn extract_paths(
    program: &str,
    image: &Path,
    dest: &Path,
    limits: &IsoLimits,
) -> std::result::Result<(), String> {
    let mut args: Vec<String> = vec![
        "-no-xattrs".into(),
        "-quiet".into(),
        "-no-progress".into(),
        "-follow-symlinks".into(),
        "-processors".into(),
        "1".into(),
        "-da".into(),
        UNSQUASHFS_QUEUE_MIB.into(),
        "-fr".into(),
        UNSQUASHFS_QUEUE_MIB.into(),
        "-d".into(),
        dest.to_string_lossy().into_owned(),
        image.to_string_lossy().into_owned(),
    ];
    args.extend(PACKAGE_DB_PATHS.iter().map(|p| p.to_string()));

    let mut command = unsquashfs_command(program, limits);
    command
        .args(&args)
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|e| format!("cannot run {}: {}", program, e))?;
    let stderr = child.stderr.take().ok_or("no extraction error output")?;
    let stderr_task = tokio::spawn(read_capped(stderr));

    let status = match tokio::time::timeout(limits.extract_timeout, child.wait()).await {
        Ok(Ok(status)) => status,
        Ok(Err(e)) => return Err(format!("squashfs extraction did not finish: {}", e)),
        Err(_) => {
            return Err(format!(
                "squashfs extraction did not finish within {} s",
                limits.extract_timeout.as_secs()
            ))
        }
    };
    let stderr = stderr_task.await.unwrap_or_default();
    match classify_unsquashfs_exit(status.code(), &stderr) {
        Some(crate::services::incus_scanner::ExtractorExit::Clean) => Ok(()),
        Some(crate::services::incus_scanner::ExtractorExit::Skipped(summary)) => {
            warn!(
                "unsquashfs skipped entries the non-root scanner cannot create in an ISO rootfs; scanning the rest: {}",
                summary
            );
            Ok(())
        }
        None => Err(format!(
            "squashfs extraction failed ({}): {}",
            status,
            summarize_stderr(&stderr)
        )),
    }
}

/// An `unsquashfs` command: killed when its future is dropped (the scan's
/// wall-clock budget, #3455), messages in English for the classifiers, no
/// stdin, and on Linux the address-space, CPU-time and file-size rlimits.
fn unsquashfs_command(program: &str, limits: &IsoLimits) -> tokio::process::Command {
    let mut command = tokio::process::Command::new(program);
    command
        .kill_on_drop(true)
        .env("LC_ALL", "C")
        .stdin(Stdio::null());
    #[cfg(target_os = "linux")]
    {
        let file_bytes = limits.max_bytes.max(1);
        // SAFETY: the closure runs in the forked child before exec and only
        // calls setrlimit(2), which is async-signal-safe; it allocates
        // nothing and touches no lock.
        unsafe {
            command.pre_exec(move || {
                for (resource, value) in [
                    (libc::RLIMIT_AS, UNSQUASHFS_ADDRESS_SPACE_BYTES),
                    (libc::RLIMIT_CPU, UNSQUASHFS_CPU_SECONDS),
                    (libc::RLIMIT_FSIZE, file_bytes),
                ] {
                    let limit = libc::rlimit {
                        rlim_cur: value,
                        rlim_max: value,
                    };
                    if libc::setrlimit(resource, &limit) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = limits;
    command
}

/// Read at most [`MAX_STDERR_BYTES`] of a child's stderr, then keep
/// draining it so the child never blocks on a full pipe.
async fn read_capped<R: tokio::io::AsyncRead + Unpin>(reader: R) -> String {
    let mut kept = Vec::new();
    let mut reader = reader;
    let _ = (&mut reader)
        .take(MAX_STDERR_BYTES)
        .read_to_end(&mut kept)
        .await;
    let _ = tokio::io::copy(&mut reader, &mut tokio::io::sink()).await;
    String::from_utf8_lossy(&kept).into_owned()
}

/// Remove everything under `workspace`, keeping the directory (the guard
/// owns it). A partial tree must never reach the engines, so a failure to
/// empty it is an error.
async fn empty_workspace(workspace: &Path) -> Result<()> {
    let root: PathBuf = workspace.to_path_buf();
    tokio::task::spawn_blocking(move || -> Result<()> {
        // A tree extracted with restrictive modes is opened first so it can
        // be removed; failures surface on the removal below.
        let _ = open_tree_for_owner(&root);
        let entries = std::fs::read_dir(&root).map_err(|e| {
            AppError::Internal(format!(
                "Failed to read the scan workspace {}: {}",
                root.display(),
                e
            ))
        })?;
        for entry in entries {
            let entry = entry.map_err(|e| {
                AppError::Internal(format!("Failed to read the scan workspace: {}", e))
            })?;
            let path = entry.path();
            let is_dir = entry.file_type().is_ok_and(|t| t.is_dir());
            let removed = if is_dir {
                std::fs::remove_dir_all(&path)
            } else {
                std::fs::remove_file(&path)
            };
            removed.map_err(|e| {
                AppError::Internal(format!(
                    "Failed to empty the scan workspace at {}: {}",
                    path.display(),
                    e
                ))
            })?;
        }
        Ok(())
    })
    .await
    .map_err(|e| AppError::Internal(format!("Workspace cleanup task failed: {}", e)))?
}

#[cfg(ak_test_shard = "services-1")]
#[cfg(test)]
mod tests;
