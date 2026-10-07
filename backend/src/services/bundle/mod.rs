//! Artifact Keeper content bundles (#2464, Export/Import P1).
//!
//! A bundle is an uncompressed, inspectable `tar` file
//! (`<name>.akbundle.tar`) that carries one or more repositories from an
//! online instance to a disconnected one. This module is the format layer
//! only: the versioned `manifest.json` codec ([`manifest`]), the on-media
//! layout and its path guards ([`layout`]), and the bounded tar inspector
//! that refuses zip-slip, link and device entries before any byte is
//! trusted ([`archive`]). The export worker (PR2) and the
//! verify-before-commit import worker (PR3) build on it.
//!
//! Format decisions carried from the 2026-07-29 adversarial review on #2464:
//!
//! * **No bundle-layer compression or encryption.** Accredited transfer guards
//!   cannot inspect what they cannot read, and the artifacts inside are
//!   already format-compressed. A gzip/zstd/xz/bzip2/zip stream is refused
//!   ([`archive::refuse_compressed_prefix`]).
//! * **Flat, content-addressed blobs with the real extension**
//!   (`blobs/ab/<sha256>.jar`): bounded depth and name length for ISO 9660 /
//!   UDF media, and every artifact stays individually visible to file-type
//!   allowlists and AV engines. No nested archives, no base64 blobs in JSON.
//! * **Signing is structural.** Every item carries an optional per-record
//!   signature and the manifest an optional signing block, so a security
//!   officer can remove one record during a releasability review without
//!   invalidating the set. Verification arrives with #2466; until then a
//!   signed bundle is refused rather than silently trusted.
//! * **Baselines and cumulative sets, not strict sequence continuity.** The
//!   manifest reserves a monotonic sequence number and its baseline so a lost
//!   disc self-heals on the next set while replay stays detectable (P2).
//! * **Media profiles and volume sets** are recorded in the manifest so a
//!   missing volume is detectable and a failed burn can be re-exported.
//! * **Imported scan evidence is never a local scan result.** It is carried
//!   for a human reviewer and lands in `bundle_scan_evidence`, never in
//!   `scan_results`, so hash-based scan dedup can never turn a bundle-scoped
//!   trust decision into an instance-wide scan exemption.

pub mod archive;
pub mod layout;
pub mod manifest;

use thiserror::Error;

use crate::error::AppError;

/// Every way a bundle (or one of its parts) can be rejected by the format
/// layer. All variants are client errors: the bundle, not the server, is at
/// fault.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum BundleError {
    /// The manifest names a schema version this server cannot read.
    #[error(
        "unsupported bundle schema_version {found}; this server reads versions {min} through {max}"
    )]
    UnsupportedVersion { found: u64, min: u32, max: u32 },

    /// The document is not an Artifact Keeper bundle manifest at all.
    #[error("not an Artifact Keeper bundle manifest: {0}")]
    WrongFormat(String),

    /// The manifest is not valid JSON or does not match the schema.
    #[error("malformed bundle manifest: {0}")]
    Malformed(String),

    /// A path inside the bundle (or named by the manifest) is unsafe or does
    /// not match the bundle layout.
    #[error("unsafe or unexpected bundle path {path:?}: {reason}")]
    UnsafePath { path: String, reason: String },

    /// The tar stream carries an entry type the format never produces
    /// (symlink, hard link, device, FIFO, ...).
    #[error("bundle entry {path:?} has disallowed type {kind}")]
    DisallowedEntryType { path: String, kind: String },

    /// The same path appears twice in the tar stream.
    #[error("bundle entry {0:?} appears more than once")]
    DuplicateEntry(String),

    /// The bundle stream is compressed or wrapped in another archive format.
    #[error("bundle is {0}-compressed; the bundle format is an uncompressed tar so transfer guards can inspect it")]
    Compressed(&'static str),

    /// A size, count or byte budget was exceeded.
    #[error("bundle exceeds a limit: {0}")]
    LimitExceeded(String),

    /// The tar stream itself is corrupt.
    #[error("invalid bundle archive: {0}")]
    InvalidArchive(String),

    /// The manifest is well-formed but internally inconsistent.
    #[error("invalid bundle manifest: {0}")]
    Invalid(String),
}

impl From<BundleError> for AppError {
    fn from(err: BundleError) -> Self {
        AppError::Validation(err.to_string())
    }
}

/// Default cap on `manifest.json` bytes. A record is a few hundred bytes, so
/// this admits roughly a million items.
pub const DEFAULT_MAX_MANIFEST_BYTES: u64 = 256 * 1024 * 1024;
/// Default cap on manifest item records.
pub const DEFAULT_MAX_ITEMS: u64 = 2_000_000;
/// Default cap on tar entries walked (items, metadata documents, directories).
pub const DEFAULT_MAX_ENTRIES: u64 = 4_000_000;
/// Default cap on the total bytes of one bundle stream (4 TiB).
pub const DEFAULT_MAX_TOTAL_BYTES: u64 = 4 * 1024 * 1024 * 1024 * 1024;

/// Env overrides for the limits above (decimal; blank/zero/invalid = default).
pub const MAX_MANIFEST_BYTES_ENV: &str = "AK_BUNDLE_MAX_MANIFEST_BYTES";
pub const MAX_ITEMS_ENV: &str = "AK_BUNDLE_MAX_ITEMS";
pub const MAX_ENTRIES_ENV: &str = "AK_BUNDLE_MAX_ENTRIES";
pub const MAX_TOTAL_BYTES_ENV: &str = "AK_BUNDLE_MAX_TOTAL_BYTES";

/// Budgets applied while reading an untrusted bundle. Bundles are far larger
/// than the package archives `util::bounded_archive` was tuned for, so they
/// get their own defaults, read through the same `positive_env_or` idiom and
/// enforced with the same `BudgetReader`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BundleLimits {
    pub max_manifest_bytes: u64,
    pub max_items: u64,
    pub max_entries: u64,
    pub max_total_bytes: u64,
}

impl Default for BundleLimits {
    fn default() -> Self {
        Self {
            max_manifest_bytes: DEFAULT_MAX_MANIFEST_BYTES,
            max_items: DEFAULT_MAX_ITEMS,
            max_entries: DEFAULT_MAX_ENTRIES,
            max_total_bytes: DEFAULT_MAX_TOTAL_BYTES,
        }
    }
}

impl BundleLimits {
    /// Defaults with any operator overrides from the environment applied.
    pub fn from_env() -> Self {
        use crate::util::bounded_archive::positive_env_or;
        let d = Self::default();
        Self {
            max_manifest_bytes: positive_env_or(MAX_MANIFEST_BYTES_ENV, d.max_manifest_bytes),
            max_items: positive_env_or(MAX_ITEMS_ENV, d.max_items),
            max_entries: positive_env_or(MAX_ENTRIES_ENV, d.max_entries),
            max_total_bytes: positive_env_or(MAX_TOTAL_BYTES_ENV, d.max_total_bytes),
        }
    }
}

#[cfg(ak_test_shard = "services-1")]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundle_errors_map_to_validation() {
        let err: AppError = BundleError::Compressed("gzip").into();
        assert!(matches!(err, AppError::Validation(ref m) if m.contains("gzip")));
        let v = BundleError::UnsupportedVersion {
            found: 9,
            min: 1,
            max: 1,
        };
        assert!(v.to_string().contains("schema_version 9"));
    }

    fn rust_sources(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(dir).expect("read bundle source dir") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                rust_sources(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }

    /// Adversarial constraint 1 on #2464: nothing in the bundle subsystem may
    /// write imported scan evidence into `scan_results` (or the checksum-keyed
    /// `proxy_scan_results`), where hash-based dedup would turn it into an
    /// instance-wide scan exemption, nor go through the scan-result service
    /// that writes them. Imported evidence goes to `bundle_scan_evidence`
    /// only. Walks the whole module directory so files added by the export
    /// and import workers are covered without editing this list.
    #[test]
    fn bundle_code_never_writes_scan_results() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut files = Vec::new();
        rust_sources(&root.join("src/services/bundle"), &mut files);
        files.push(root.join("src/api/handlers/bundles.rs"));
        assert!(files.len() >= 5, "bundle sources not found: {files:?}");

        let table = concat!("scan_", "results");
        let write = regex::Regex::new(&format!(
            r"(?i)\b(insert\s+into|update|copy|delete\s+from)\s+(\w+\.)?(proxy_)?{table}\b"
        ))
        .unwrap();
        let service = concat!("ScanResult", "Service");
        for path in files {
            let src = std::fs::read_to_string(&path).expect("read source");
            let collapsed = src.split_whitespace().collect::<Vec<_>>().join(" ");
            assert!(
                !write.is_match(&collapsed),
                "{} writes {table}: imported evidence belongs in bundle_scan_evidence",
                path.display()
            );
            assert!(
                !src.contains(service),
                "{} uses the scan-result service; bundle code must not write scan results",
                path.display()
            );
        }
        // The pattern itself catches the shapes it is meant to.
        for bad in [
            "INSERT INTO {t} (",
            "insert into public.proxy_{t}",
            "UPDATE {t} SET",
        ] {
            assert!(write.is_match(&bad.replace("{t}", table)), "{bad}");
        }
        assert!(!write.is_match(&format!("{table}_origin_check")));
    }

    #[test]
    fn limits_read_env_overrides() {
        // Process-global env: nextest runs each test in its own process.
        std::env::set_var(MAX_ITEMS_ENV, "7");
        std::env::set_var(MAX_TOTAL_BYTES_ENV, "0");
        let limits = BundleLimits::from_env();
        std::env::remove_var(MAX_ITEMS_ENV);
        std::env::remove_var(MAX_TOTAL_BYTES_ENV);
        assert_eq!(limits.max_items, 7);
        assert_eq!(limits.max_total_bytes, DEFAULT_MAX_TOTAL_BYTES);
        assert_eq!(limits.max_manifest_bytes, DEFAULT_MAX_MANIFEST_BYTES);
    }
}
