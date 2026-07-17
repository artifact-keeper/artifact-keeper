//! Bounded archive decompression for ingestion/serve metadata extraction.
//!
//! Every format that needs package coordinates (name/version/description)
//! decompresses the uploaded or served archive *inside the request handler* to
//! read a single small metadata file (`Chart.yaml`, `.nuspec`, `pubspec.yaml`,
//! `METADATA`, `.podspec.json`, `metadata.config`, …). Those extractors never
//! touch the scanner's bounded extractors (`unpack_*_limited`, #2514) nor the
//! Debian-index cap (#2482), so historically they decoded a gzip/zip/bz2 stream
//! with **no cap on total decompressed bytes**, walked tar entries with **no
//! entry-count cap**, and read the target entry with **no per-entry cap** — a
//! decompression-bomb / unbounded-memory surface at upload and serve time.
//!
//! This module consolidates the proven bounding primitives into three shared
//! helpers so every ingestion metadata extractor gets the same three caps with
//! one implementation:
//!
//! 1. a **total decompressed-byte budget** on the decoded stream (default
//!    128 MiB, env [`MAX_INGEST_DECOMPRESSED_BYTES_ENV`]) — the core mechanism;
//!    it defeats both the *pre-target-inflation* bomb (huge entries walked
//!    before the metadata file) and the *entry-count* bomb (the walk hits the
//!    byte budget and stops),
//! 2. a **10 000 entry-count cap** ([`MAX_INGEST_ARCHIVE_ENTRIES`]) —
//!    defence-in-depth against inode/entry-count bombs with a clearer error,
//! 3. an **8 MiB per-metadata-entry cap** ([`MAX_INGEST_METADATA_ENTRY_BYTES`])
//!    — a metadata file larger than this is itself a bomb.
//!
//! Reference implementations reused here (do not re-derive):
//! - the scanner's `positive_env_or` env-override idiom and `copy_entry_bounded`
//!   running-budget check (#2514),
//! - the Debian index `.take()` byte budget (#2482),
//! - `api/handlers/conda.rs::limited_decode_zstd` streaming cap,
//! - **`api/handlers/swift.rs::extract_manifest_from_zip`** — already correctly
//!   bounded (`size()` pre-check + `.take(N + 1)` per entry, random-access zip
//!   so unmatched entries are never inflated); this module generalises exactly
//!   that pattern to the other formats.
//!
//! All caps sit far above real packages — metadata files are KB-scale, so a
//! legitimate large chart/wheel/nupkg/pod/gem reads only a few KB before the
//! match and never approaches a cap. A cap breach is surfaced as
//! [`AppError::Validation`] (HTTP 400) so ingestion **rejects** the bomb rather
//! than silently truncating or hanging.

use std::io::{self, Read, Seek};
use std::path::Path;
use std::sync::{Arc, OnceLock};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::error::{AppError, Result};

/// Total decompressed bytes any single ingestion metadata-extraction may
/// consume before it is rejected as a suspected decompression bomb. 128 MiB
/// matches the Debian #2482 index cap; it is generous for real charts/wheels/
/// nupkgs (whose metadata files are KB) — the cap only bites on bombs or on
/// pre-target inflation.
pub const DEFAULT_MAX_INGEST_DECOMPRESSED_BYTES: u64 = 128 * 1024 * 1024;

/// Env var overriding [`DEFAULT_MAX_INGEST_DECOMPRESSED_BYTES`]. Value is a
/// plain decimal byte count; blank/zero/non-numeric falls back to the default.
/// Named to mirror the scanner's `MAX_SCAN_EXTRACTED_BYTES` so operators tune
/// ingestion and scan caps with the same idiom.
pub const MAX_INGEST_DECOMPRESSED_BYTES_ENV: &str = "MAX_INGEST_DECOMPRESSED_BYTES";

/// Maximum tar/zip entries walked while searching for the metadata file.
/// 10 000 matches conda's `MAX_TAR_ENTRIES`; bounds inode/entry-count bombs.
pub const MAX_INGEST_ARCHIVE_ENTRIES: u64 = 10_000;

/// Maximum bytes read for the single matched metadata entry (`Chart.yaml` /
/// `.nuspec` / `pubspec.yaml` / `METADATA` / …). 8 MiB is ≥ helm's prior 4 MiB
/// per-entry cap; a metadata file larger than this is itself a bomb.
pub const MAX_INGEST_METADATA_ENTRY_BYTES: u64 = 8 * 1024 * 1024;

/// Parse a positive-integer environment override, falling back to `default`
/// when the variable is unset, blank, non-numeric, or zero (a zero cap would
/// reject every upload, so it is treated as "unset"). Mirrors the scanner's
/// `positive_env_or` so the parse/filter logic reads identically.
pub fn positive_env_or(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .filter(|&v| v > 0)
        .unwrap_or(default)
}

/// Effective total decompressed-byte ceiling, honouring
/// [`MAX_INGEST_DECOMPRESSED_BYTES_ENV`] over the default.
pub fn max_ingest_decompressed_bytes() -> u64 {
    positive_env_or(
        MAX_INGEST_DECOMPRESSED_BYTES_ENV,
        DEFAULT_MAX_INGEST_DECOMPRESSED_BYTES,
    )
}

// ---------------------------------------------------------------------------
// Concurrency cap (#2561)
// ---------------------------------------------------------------------------
//
// The three per-archive caps above bound a *single* extraction's memory/CPU,
// but place no bound on the NUMBER of extractions running at once. Every
// ingestion/serve metadata extractor decodes on the request path, so N parallel
// uploads decode N archives concurrently — N × up-to-`max_ingest_decompressed_bytes()`
// decode buffers plus N × decompressor CPU at the same time. This mirrors the
// scanner's own concurrent-extraction gap (`scanner_service.rs` #2540), which
// caps in-flight scan-workspace extractions with a process-wide semaphore.
//
// This module adds the ingestion analogue: a process-wide semaphore whose
// permits bound the number of concurrent ingestion decodes. Unlike the
// scanner's FIFO *blocking* acquire (detached background scans have no client
// latency SLA and must complete), ingestion decode happens on the request path,
// so the guard is acquired FAST-FAIL: on saturation it sheds the request with a
// 503 ([`AppError::ServiceUnavailable`]) instead of queueing more decode work.
// It is a *separate* semaphore from the scanner's, so ingestion and scan
// extractions do not double-count against one shared budget.

/// Default cap on how many ingestion/serve archive decompressions may run at
/// once, across ALL format extractors. Bounds worst-case concurrent decode
/// memory/CPU to roughly `cap × per-archive-cap`. A small default keeps the
/// out-of-the-box worst case modest while still allowing parallel uploads.
pub const DEFAULT_MAX_CONCURRENT_INGEST_EXTRACTIONS: usize = 8;

/// Env var overriding [`DEFAULT_MAX_CONCURRENT_INGEST_EXTRACTIONS`]. A blank,
/// non-numeric, or zero value falls back to the default (a zero cap would wedge
/// every upload, so it is treated as "unset").
pub const MAX_CONCURRENT_INGEST_EXTRACTIONS_ENV: &str = "MAX_CONCURRENT_INGEST_EXTRACTIONS";

/// Clamp a parsed permit count into the range tokio's `Semaphore` accepts.
/// `Semaphore::new` panics above [`Semaphore::MAX_PERMITS`] (2^61 - 1), and a
/// panic inside the `OnceLock` initializer would re-panic on EVERY subsequent
/// decode (the init is retried), wedging all ingestion — so an absurd override
/// is clamped rather than trusted. The floor of 1 keeps the semaphore usable
/// even if a caller ever bypasses `positive_env_or`'s zero filter.
fn clamp_ingest_permits(v: u64) -> usize {
    usize::try_from(v)
        .unwrap_or(usize::MAX)
        .clamp(1, Semaphore::MAX_PERMITS)
}

/// Effective concurrent-ingest-extraction cap, honouring
/// [`MAX_CONCURRENT_INGEST_EXTRACTIONS_ENV`] over the default, clamped to what
/// `Semaphore::new` accepts (see [`clamp_ingest_permits`]).
fn max_concurrent_ingest_extractions() -> usize {
    clamp_ingest_permits(positive_env_or(
        MAX_CONCURRENT_INGEST_EXTRACTIONS_ENV,
        DEFAULT_MAX_CONCURRENT_INGEST_EXTRACTIONS as u64,
    ))
}

/// Process-wide semaphore bounding concurrent ingestion decompressions. Seeded
/// once from [`max_concurrent_ingest_extractions`]; each in-flight extraction
/// holds one permit (via [`IngestExtractionGuard`]) only for the duration of the
/// decode. Never `close()`d — it lives for the process lifetime.
fn ingest_extraction_semaphore() -> &'static Arc<Semaphore> {
    static SEM: OnceLock<Arc<Semaphore>> = OnceLock::new();
    SEM.get_or_init(|| Arc::new(Semaphore::new(max_concurrent_ingest_extractions())))
}

/// RAII guard representing one in-flight ingestion decompression. Hold it across
/// the (synchronous) decode call and drop it promptly afterwards — dropping it
/// releases the permit so a slow downstream (DB/storage) never keeps a decode
/// slot occupied. Acquire it with [`acquire_ingest_extraction`].
#[must_use = "hold the guard across the decode; dropping it immediately releases the permit"]
#[derive(Debug)]
pub struct IngestExtractionGuard {
    _permit: OwnedSemaphorePermit,
}

/// Try to reserve one ingestion-decompression slot on `sem`, FAST-FAIL: on
/// saturation return an [`AppError::ServiceUnavailable`] (HTTP 503) rather than
/// blocking, so an overloaded server sheds excess decode work instead of piling
/// up memory/CPU. The `_from` seam takes the semaphore explicitly so tests can
/// drive a local cap without touching the process singleton.
fn acquire_ingest_extraction_from(sem: &Arc<Semaphore>) -> Result<IngestExtractionGuard> {
    match sem.clone().try_acquire_owned() {
        Ok(permit) => Ok(IngestExtractionGuard { _permit: permit }),
        Err(_) => Err(AppError::ServiceUnavailable(
            "Server is busy decompressing other uploads; please retry shortly".to_string(),
        )),
    }
}

/// Reserve one process-wide ingestion-decompression slot, FAST-FAIL to a 503 on
/// saturation. Call this in the async handler immediately before invoking the
/// (synchronous) archive extractor and hold the returned guard across that call.
/// Most call sites should prefer [`with_ingest_extraction`] /
/// [`with_ingest_extraction_async`], which scope the permit for you.
pub fn acquire_ingest_extraction() -> Result<IngestExtractionGuard> {
    acquire_ingest_extraction_from(ingest_extraction_semaphore())
}

/// Run `decode` (a synchronous archive decompression) while holding one
/// process-wide ingestion-decompression slot. FAST-FAILS with the 503
/// [`AppError::ServiceUnavailable`] on saturation *without* invoking `decode`;
/// otherwise the permit is held exactly for the duration of `decode` and
/// released as it returns (before any DB/storage work in the caller). `decode`'s
/// own return value — `Result`, `Option`, plain value — passes through inside
/// the `Ok`, so callers layer their existing error mapping on top:
///
/// ```ignore
/// let spec = with_ingest_extraction(|| extract_gemspec(&body))
///     .map_err(|e| e.into_response())?   // 503 shed
///     .map_err(|e| bad_request(e))?;     // decode's own error
/// ```
///
/// **This budget is for the *ingest* (publish/upload) path only.** A read path
/// that needs to re-open a stored archive must use
/// [`with_registry_extraction`] instead — see its docs for why.
pub fn with_ingest_extraction<T>(decode: impl FnOnce() -> T) -> Result<T> {
    with_ingest_extraction_from(ingest_extraction_semaphore(), decode)
}

/// `_from` seam for [`with_ingest_extraction`] — lets unit tests drive a local
/// cap without touching the process singleton.
fn with_ingest_extraction_from<T>(sem: &Arc<Semaphore>, decode: impl FnOnce() -> T) -> Result<T> {
    let _permit = acquire_ingest_extraction_from(sem)?;
    Ok(decode())
}

/// Like [`with_ingest_extraction`] but holds the slot across an `.await` — for
/// decodes that hop to a blocking thread (`spawn_blocking`) so the permit must
/// span the join. Same fast-fail-503 semantics; the future is never constructed
/// when the server is saturated.
pub async fn with_ingest_extraction_async<T, F>(decode: impl FnOnce() -> F) -> Result<T>
where
    F: std::future::Future<Output = T>,
{
    let _permit = acquire_ingest_extraction_from(ingest_extraction_semaphore())?;
    Ok(decode().await)
}

// ---------------------------------------------------------------------------
// Registry/read-path extraction budget
//
// A few read paths must re-open an archive that is already stored, to recover a
// fact about it that was not captured at publish (the hex registry's
// `inner_checksum` for artifacts published before that capture existed). That
// decode needs the same bounding as ingestion, but it must NOT draw on the same
// budget:
//
//   * The ingest semaphore is shared by EVERY format's publish path. Spending
//     its permits on reads lets read traffic shed *publishes* — across formats
//     that have nothing to do with the reader. A handful of concurrent
//     anonymous GETs could 503 every upload in the product.
//   * The two have opposite shapes. Ingest decode is once per upload, bounded
//     by the client's own upload rate. A registry read can fan out to one
//     decode per release *within a single request*, so it saturates a small
//     budget far more easily.
//
// Reads therefore get their own semaphore with the same fast-fail-503
// discipline. Saturating it degrades registry reads only; publishes are
// untouched. This budget is a backstop, not the primary mechanism — callers are
// expected to persist what they recover so the re-read happens at most once per
// artifact rather than once per request.
// ---------------------------------------------------------------------------

/// Default cap on how many registry/read-path archive decompressions may run at
/// once. Separate from (and additive to)
/// [`DEFAULT_MAX_CONCURRENT_INGEST_EXTRACTIONS`].
pub const DEFAULT_MAX_CONCURRENT_REGISTRY_EXTRACTIONS: usize = 4;

/// Env var overriding [`DEFAULT_MAX_CONCURRENT_REGISTRY_EXTRACTIONS`]. Same
/// blank/non-numeric/zero fallback rules as the ingest cap.
pub const MAX_CONCURRENT_REGISTRY_EXTRACTIONS_ENV: &str = "MAX_CONCURRENT_REGISTRY_EXTRACTIONS";

/// Effective concurrent-registry-extraction cap.
fn max_concurrent_registry_extractions() -> usize {
    clamp_ingest_permits(positive_env_or(
        MAX_CONCURRENT_REGISTRY_EXTRACTIONS_ENV,
        DEFAULT_MAX_CONCURRENT_REGISTRY_EXTRACTIONS as u64,
    ))
}

/// Process-wide semaphore bounding concurrent registry/read-path
/// decompressions. Deliberately a *different* singleton from
/// [`ingest_extraction_semaphore`] so read load can never shed uploads.
fn registry_extraction_semaphore() -> &'static Arc<Semaphore> {
    static SEM: OnceLock<Arc<Semaphore>> = OnceLock::new();
    SEM.get_or_init(|| Arc::new(Semaphore::new(max_concurrent_registry_extractions())))
}

/// Run `decode` (a synchronous archive decompression on a *read* path) while
/// holding one process-wide registry-decompression slot. Identical
/// fast-fail-503 semantics to [`with_ingest_extraction`], but on its own budget
/// — see the module note above for why the two must not share.
pub fn with_registry_extraction<T>(decode: impl FnOnce() -> T) -> Result<T> {
    with_ingest_extraction_from(registry_extraction_semaphore(), decode)
}

/// Test-only scaffolding for suites that manipulate the process-wide extraction
/// semaphores.
#[cfg(test)]
pub(crate) mod test_support {
    /// Serializes tests that touch the PROCESS-WIDE extraction semaphores,
    /// wherever they live in the crate.
    ///
    /// `cargo test` runs tests as threads in one process, so a test that
    /// deliberately saturates a singleton would otherwise shed a concurrent
    /// test's acquire and make it flake. (Under `cargo nextest`, which CI uses,
    /// each test is its own process and this is moot — but the suite must be
    /// correct under both runners.) The semaphores are process-wide, so the lock
    /// guarding them has to be too: a per-module lock would not serialize a
    /// handler test against a `bounded_archive` test.
    ///
    /// A `tokio::sync::Mutex` rather than a `std` one because async tests hold
    /// the guard across `.await`.
    static SINGLETON_SEM_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    /// Take the lock from a synchronous test.
    pub(crate) fn lock_singletons() -> tokio::sync::MutexGuard<'static, ()> {
        SINGLETON_SEM_LOCK.blocking_lock()
    }

    /// Take the lock from an async test; safe to hold across `.await`.
    pub(crate) async fn lock_singletons_async() -> tokio::sync::MutexGuard<'static, ()> {
        SINGLETON_SEM_LOCK.lock().await
    }
}

/// A `Read` wrapper enforcing a hard cumulative-byte budget on a *decoded*
/// stream. Once `budget` bytes have been read it probes for one more byte: a
/// genuine EOF exactly at the budget passes, but any further data trips an
/// [`io::ErrorKind::InvalidData`] error carrying [`BOMB_SENTINEL`]. This makes a
/// decompression bomb abort *mid-inflate* (the budget is on the stream, not on
/// a buffered result), and — unlike a bare `.take()` — surfaces an explicit
/// error instead of silently truncating the archive.
struct BudgetReader<R> {
    inner: R,
    remaining: u64,
}

/// Marker embedded in the budget-breach `io::Error` so the tar/zip boundary can
/// translate it into a clear "decompression bomb" validation error.
const BOMB_SENTINEL: &str = "ingest decompression budget exceeded";

impl<R: Read> BudgetReader<R> {
    fn new(inner: R, budget: u64) -> Self {
        Self {
            inner,
            remaining: budget,
        }
    }
}

impl<R: Read> Read for BudgetReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.remaining == 0 {
            // Budget spent: distinguish a clean EOF from further inflation.
            let mut probe = [0u8; 1];
            return match self.inner.read(&mut probe)? {
                0 => Ok(0),
                _ => Err(io::Error::new(io::ErrorKind::InvalidData, BOMB_SENTINEL)),
            };
        }
        let cap = std::cmp::min(buf.len() as u64, self.remaining) as usize;
        let n = self.inner.read(&mut buf[..cap])?;
        self.remaining -= n as u64;
        Ok(n)
    }
}

/// Translate a low-level archive `io::Error` into an [`AppError::Validation`],
/// mapping a budget breach to an explicit decompression-bomb message.
fn map_archive_err(context: &str, err: &io::Error) -> AppError {
    if err.to_string().contains(BOMB_SENTINEL) {
        AppError::Validation(
            "Archive expands beyond the decompression budget; refusing suspected decompression bomb"
                .to_string(),
        )
    } else {
        AppError::Validation(format!("{}: {}", context, err))
    }
}

/// Wrap a *decoded* stream in the shared total-byte budget so a decompression
/// bomb aborts mid-inflate. Use when a caller must drive its own tar/zip walk
/// (e.g. to keep a format-specific per-entry cap or message) but still wants the
/// module's total-byte defence; pair it with [`MAX_INGEST_ARCHIVE_ENTRIES`] for
/// the entry-count cap. A budget breach surfaces as an [`io::Error`] during the
/// walk, which the caller maps to its own validation error.
pub fn budgeted<R: Read>(reader: R) -> impl Read {
    budgeted_to(reader, max_ingest_decompressed_bytes())
}

/// Like [`budgeted`] but with an explicit byte budget. Callers that decompress a
/// *whole* stream (not a tar walk) — e.g. an upstream repo index — use this to
/// pick a budget appropriate to the payload, and unit tests use it to drive a
/// tiny budget against a tiny fixture.
pub fn budgeted_to<R: Read>(reader: R, budget: u64) -> impl Read {
    BudgetReader::new(reader, budget)
}

/// Read at most `cap` bytes from `reader`, rejecting input that exceeds `cap`.
///
/// Reads `cap + 1` bytes so an exactly-at-cap breach is detected rather than
/// silently truncated (mirrors swift's `.take(N + 1)` re-check). Used both for
/// the matched metadata entry inside the tar/zip walkers and directly by
/// callers that read a single already-located archive entry (conda zip-entry
/// reads, pypi wheel `METADATA`).
pub fn read_capped<R: Read>(reader: R, cap: u64, what: &str) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    reader
        .take(cap + 1)
        .read_to_end(&mut buf)
        .map_err(|e| AppError::Validation(format!("Failed to read {}: {}", what, e)))?;
    if buf.len() as u64 > cap {
        return Err(AppError::Validation(format!(
            "{} exceeds the maximum allowed size of {} bytes",
            what, cap
        )));
    }
    Ok(buf)
}

/// Walk an already-budget-wrapped tar stream, returning the first entry whose
/// path satisfies `matches`. Enforces the entry-count cap and reads the matched
/// entry through the per-entry cap. The total-byte budget is enforced by the
/// [`BudgetReader`] the caller wrapped `archive_reader` in, so *skipped* entries
/// (which tar must still inflate to reach the next header) also count against
/// the budget — defeating the pre-target-inflation bomb.
fn read_tar_entries<R: Read>(
    archive_reader: R,
    matches: impl Fn(&Path) -> bool,
    max_entries: u64,
    max_entry: u64,
) -> Result<Option<Vec<u8>>> {
    let mut archive = tar::Archive::new(archive_reader);

    let entries = archive
        .entries()
        .map_err(|e| map_archive_err("Invalid archive", &e))?;

    let mut entries_seen: u64 = 0;
    for entry in entries {
        let mut entry = entry.map_err(|e| map_archive_err("Invalid archive entry", &e))?;

        entries_seen += 1;
        if entries_seen > max_entries {
            return Err(AppError::Validation(format!(
                "Archive contains too many entries (> {}); refusing suspected decompression bomb",
                max_entries
            )));
        }

        let path = entry
            .path()
            .map_err(|e| map_archive_err("Invalid entry path", &e))?
            .to_path_buf();

        if matches(&path) {
            let bytes = read_capped(&mut entry, max_entry, "archive metadata entry")?;
            return Ok(Some(bytes));
        }
    }

    Ok(None)
}

/// Read the first matching metadata entry from a gzip-compressed tar stream,
/// bounded by the total-byte budget, entry-count cap, and per-entry cap.
/// `matches` selects the target entry by its path (e.g. `pubspec.yaml`,
/// `.podspec.json`). Returns `Ok(None)` when no entry matches (not a bomb) and
/// `Err` when any cap is breached.
pub fn read_metadata_from_tar_gz<R: Read>(
    reader: R,
    matches: impl Fn(&Path) -> bool,
) -> Result<Option<Vec<u8>>> {
    read_metadata_from_tar_gz_limited(
        reader,
        matches,
        max_ingest_decompressed_bytes(),
        MAX_INGEST_ARCHIVE_ENTRIES,
        MAX_INGEST_METADATA_ENTRY_BYTES,
    )
}

/// `_limited` seam for [`read_metadata_from_tar_gz`] — lets unit tests drive
/// tiny caps against tiny fixtures instead of building 128 MiB.
pub fn read_metadata_from_tar_gz_limited<R: Read>(
    reader: R,
    matches: impl Fn(&Path) -> bool,
    max_total: u64,
    max_entries: u64,
    max_entry: u64,
) -> Result<Option<Vec<u8>>> {
    read_metadata_from_decoded_tar_limited(
        flate2::read::GzDecoder::new(reader),
        matches,
        max_total,
        max_entries,
        max_entry,
    )
}

/// Read the first matching metadata entry from a bzip2-compressed tar stream
/// (conda v1 `.tar.bz2`), with the same three caps as the gzip variant.
pub fn read_metadata_from_tar_bz2<R: Read>(
    reader: R,
    matches: impl Fn(&Path) -> bool,
) -> Result<Option<Vec<u8>>> {
    read_metadata_from_tar_bz2_limited(
        reader,
        matches,
        max_ingest_decompressed_bytes(),
        MAX_INGEST_ARCHIVE_ENTRIES,
        MAX_INGEST_METADATA_ENTRY_BYTES,
    )
}

/// `_limited` seam for [`read_metadata_from_tar_bz2`].
pub fn read_metadata_from_tar_bz2_limited<R: Read>(
    reader: R,
    matches: impl Fn(&Path) -> bool,
    max_total: u64,
    max_entries: u64,
    max_entry: u64,
) -> Result<Option<Vec<u8>>> {
    read_metadata_from_decoded_tar_limited(
        bzip2::read::BzDecoder::new(reader),
        matches,
        max_total,
        max_entries,
        max_entry,
    )
}

/// Read the first matching metadata entry from an **xz**-compressed tar stream
/// (debian `control.tar.xz`, incus `.tar.xz` images). xz of null/repeated bytes
/// amplifies even harder than gzip, so the total-byte budget on the decoded
/// stream is the primary defence.
pub fn read_metadata_from_tar_xz<R: Read>(
    reader: R,
    matches: impl Fn(&Path) -> bool,
) -> Result<Option<Vec<u8>>> {
    read_metadata_from_tar_xz_limited(
        reader,
        matches,
        max_ingest_decompressed_bytes(),
        MAX_INGEST_ARCHIVE_ENTRIES,
        MAX_INGEST_METADATA_ENTRY_BYTES,
    )
}

/// `_limited` seam for [`read_metadata_from_tar_xz`].
pub fn read_metadata_from_tar_xz_limited<R: Read>(
    reader: R,
    matches: impl Fn(&Path) -> bool,
    max_total: u64,
    max_entries: u64,
    max_entry: u64,
) -> Result<Option<Vec<u8>>> {
    read_metadata_from_decoded_tar_limited(
        xz2::read::XzDecoder::new(reader),
        matches,
        max_total,
        max_entries,
        max_entry,
    )
}

/// Read the first matching metadata entry from a **zstd**-compressed tar stream
/// (debian `control.tar.zst`, incus `.tar.zst` images). Like xz, zstd bombs
/// amplify hard, so the decoded-stream budget is the primary defence.
pub fn read_metadata_from_tar_zst<R: Read>(
    reader: R,
    matches: impl Fn(&Path) -> bool,
) -> Result<Option<Vec<u8>>> {
    read_metadata_from_tar_zst_limited(
        reader,
        matches,
        max_ingest_decompressed_bytes(),
        MAX_INGEST_ARCHIVE_ENTRIES,
        MAX_INGEST_METADATA_ENTRY_BYTES,
    )
}

/// `_limited` seam for [`read_metadata_from_tar_zst`].
pub fn read_metadata_from_tar_zst_limited<R: Read>(
    reader: R,
    matches: impl Fn(&Path) -> bool,
    max_total: u64,
    max_entries: u64,
    max_entry: u64,
) -> Result<Option<Vec<u8>>> {
    let decoder = zstd::Decoder::new(reader)
        .map_err(|e| AppError::Validation(format!("Invalid zstd stream: {}", e)))?;
    read_metadata_from_decoded_tar_limited(decoder, matches, max_total, max_entries, max_entry)
}

/// Read the first matching metadata entry from an **already-decoded** tar stream
/// where the caller chose the decompressor at runtime (e.g. incus dispatches on
/// magic bytes, debian on the ar member extension, producing a `Box<dyn Read>`).
/// Wraps the decoded stream in the shared total-byte budget and applies the
/// entry-count + per-entry caps. This is the single seam through which every
/// tar-family helper flows.
pub fn read_metadata_from_decoded_tar<R: Read>(
    decoded: R,
    matches: impl Fn(&Path) -> bool,
) -> Result<Option<Vec<u8>>> {
    read_metadata_from_decoded_tar_limited(
        decoded,
        matches,
        max_ingest_decompressed_bytes(),
        MAX_INGEST_ARCHIVE_ENTRIES,
        MAX_INGEST_METADATA_ENTRY_BYTES,
    )
}

/// `_limited` seam for [`read_metadata_from_decoded_tar`]; the common core all
/// tar-family variants delegate to.
pub fn read_metadata_from_decoded_tar_limited<R: Read>(
    decoded: R,
    matches: impl Fn(&Path) -> bool,
    max_total: u64,
    max_entries: u64,
    max_entry: u64,
) -> Result<Option<Vec<u8>>> {
    read_tar_entries(
        BudgetReader::new(decoded, max_total),
        matches,
        max_entries,
        max_entry,
    )
}

/// Decompress a standalone **gzip** stream (not a tar) to bytes, bounded by
/// `max` so a gzip bomb aborts mid-inflate rather than buffering the whole
/// inflated payload. Used for rubygems' `metadata.gz` inner blob. Returns `Err`
/// when the decompressed size exceeds `max`.
pub fn decompress_gz_capped<R: Read>(reader: R, max: u64, what: &str) -> Result<Vec<u8>> {
    read_capped(flate2::read::GzDecoder::new(reader), max, what)
}

/// Read the first matching metadata entry from a *plain* (uncompressed) tar
/// stream (hex outer tarball). No decoder, but the same entry-count and
/// per-entry caps apply; the total-byte budget bounds the walk (a plain tar
/// still has low amplification, but the entry-count and per-entry caps bound
/// worst-case memory to a single entry).
pub fn read_metadata_from_tar<R: Read>(
    reader: R,
    matches: impl Fn(&Path) -> bool,
) -> Result<Option<Vec<u8>>> {
    read_metadata_from_tar_limited(
        reader,
        matches,
        max_ingest_decompressed_bytes(),
        MAX_INGEST_ARCHIVE_ENTRIES,
        MAX_INGEST_METADATA_ENTRY_BYTES,
    )
}

/// `_limited` seam for [`read_metadata_from_tar`].
pub fn read_metadata_from_tar_limited<R: Read>(
    reader: R,
    matches: impl Fn(&Path) -> bool,
    max_total: u64,
    max_entries: u64,
    max_entry: u64,
) -> Result<Option<Vec<u8>>> {
    read_metadata_from_decoded_tar_limited(reader, matches, max_total, max_entries, max_entry)
}

/// Read the first matching metadata entry from a ZIP archive (`.nupkg`, `.whl`,
/// `.conda` v2). Zip is random-access, so unmatched entries are never inflated
/// and no total-stream budget is needed; instead an entry-count cap is checked
/// up front and the matched entry is read through a header-size pre-check plus
/// the per-entry `.take()` cap — exactly swift's `extract_manifest_from_zip`
/// pattern. `matches` selects the target entry by its name.
pub fn read_metadata_from_zip<R: Read + Seek>(
    reader: R,
    matches: impl Fn(&str) -> bool,
) -> Result<Option<Vec<u8>>> {
    read_metadata_from_zip_limited(
        reader,
        matches,
        MAX_INGEST_ARCHIVE_ENTRIES,
        MAX_INGEST_METADATA_ENTRY_BYTES,
    )
}

/// `_limited` seam for [`read_metadata_from_zip`].
pub fn read_metadata_from_zip_limited<R: Read + Seek>(
    reader: R,
    matches: impl Fn(&str) -> bool,
    max_entries: u64,
    max_entry: u64,
) -> Result<Option<Vec<u8>>> {
    let mut archive = zip::ZipArchive::new(reader)
        .map_err(|e| AppError::Validation(format!("Invalid ZIP archive: {}", e)))?;

    if archive.len() as u64 > max_entries {
        return Err(AppError::Validation(format!(
            "ZIP archive contains too many entries (> {}); refusing suspected decompression bomb",
            max_entries
        )));
    }

    for i in 0..archive.len() {
        let mut file = archive
            .by_index(i)
            .map_err(|e| AppError::Validation(format!("Cannot read ZIP entry: {}", e)))?;
        if !file.is_file() {
            continue;
        }
        if !matches(file.name()) {
            continue;
        }
        // Header size is a hint (the central directory may lie); reject an
        // oversized entry up front, then re-check with the `.take()` read.
        if file.size() > max_entry {
            return Err(AppError::Validation(format!(
                "ZIP metadata entry exceeds the maximum allowed size of {} bytes",
                max_entry
            )));
        }
        let bytes = read_capped(&mut file, max_entry, "ZIP metadata entry")?;
        return Ok(Some(bytes));
    }

    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Tests using only local semaphores need not take these.
    use super::test_support::{lock_singletons, lock_singletons_async};

    fn tar_gz(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::default(),
        ));
        for (name, data) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append_data(&mut header, name, *data).unwrap();
        }
        builder.into_inner().unwrap().finish().unwrap()
    }

    fn plain_tar(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for (name, data) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append_data(&mut header, name, *data).unwrap();
        }
        builder.into_inner().unwrap()
    }

    fn zip_bytes(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut cursor = std::io::Cursor::new(Vec::new());
        {
            let mut w = zip::ZipWriter::new(&mut cursor);
            let opts: zip::write::FileOptions<'_, ()> = zip::write::FileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);
            for (name, data) in entries {
                w.start_file(*name, opts).unwrap();
                w.write_all(data).unwrap();
            }
            w.finish().unwrap();
        }
        cursor.into_inner()
    }

    fn is_chart(p: &Path) -> bool {
        p.ends_with("Chart.yaml")
    }

    #[test]
    fn positive_env_or_falls_back_on_blank_zero_nonnumeric() {
        assert_eq!(positive_env_or("AK_TEST_UNSET_VAR_XYZ", 42), 42);
    }

    #[test]
    fn tar_gz_normal_metadata_returns_bytes() {
        let archive = tar_gz(&[("chart/Chart.yaml", b"name: nginx\nversion: 1.2.3")]);
        let out = read_metadata_from_tar_gz_limited(
            &archive[..],
            is_chart,
            1024 * 1024,
            1000,
            1024 * 1024,
        )
        .unwrap();
        assert_eq!(out.unwrap(), b"name: nginx\nversion: 1.2.3");
    }

    #[test]
    fn tar_gz_absent_metadata_returns_none() {
        let archive = tar_gz(&[("chart/values.yaml", b"key: val")]);
        let out = read_metadata_from_tar_gz_limited(
            &archive[..],
            is_chart,
            1024 * 1024,
            1000,
            1024 * 1024,
        )
        .unwrap();
        assert!(out.is_none());
    }

    #[test]
    fn tar_gz_total_budget_breach_is_rejected() {
        // A highly-compressible 1 MiB payload placed BEFORE the target entry,
        // inflated past a tiny total budget → rejected mid-inflate even though
        // the compressed fixture is tiny (the pre-target-inflation bomb shape).
        let filler = vec![0u8; 1024 * 1024];
        let archive = tar_gz(&[
            ("chart/big.bin", &filler[..]),
            ("chart/Chart.yaml", b"name: x\nversion: 1"),
        ]);
        let err =
            read_metadata_from_tar_gz_limited(&archive[..], is_chart, 4096, 1000, 1024 * 1024);
        assert!(err.is_err(), "pre-target inflation past budget must reject");
    }

    #[test]
    fn tar_gz_entry_count_breach_is_rejected() {
        let mut entries: Vec<(String, Vec<u8>)> = (0..50)
            .map(|i| (format!("chart/f{}", i), vec![b'a']))
            .collect();
        entries.push(("chart/Chart.yaml".to_string(), b"name: x".to_vec()));
        let refs: Vec<(&str, &[u8])> = entries
            .iter()
            .map(|(n, d)| (n.as_str(), d.as_slice()))
            .collect();
        let archive = tar_gz(&refs);
        let err =
            read_metadata_from_tar_gz_limited(&archive[..], is_chart, 1024 * 1024, 10, 1024 * 1024);
        assert!(err.is_err(), "entry-count breach must reject");
    }

    #[test]
    fn tar_gz_per_entry_breach_is_rejected() {
        let archive = tar_gz(&[("chart/Chart.yaml", &vec![b'a'; 4096][..])]);
        let err =
            read_metadata_from_tar_gz_limited(&archive[..], is_chart, 1024 * 1024, 1000, 1024);
        assert!(err.is_err(), "oversized metadata entry must reject");
    }

    #[test]
    fn plain_tar_normal_and_missing() {
        let archive = plain_tar(&[("metadata.config", b"x")]);
        let out = read_metadata_from_tar_limited(
            &archive[..],
            |p| p == Path::new("metadata.config"),
            1024 * 1024,
            1000,
            1024 * 1024,
        )
        .unwrap();
        assert_eq!(out.unwrap(), b"x");

        let out2 = read_metadata_from_tar_limited(
            &archive[..],
            |p| p == Path::new("nope"),
            1024 * 1024,
            1000,
            1024 * 1024,
        )
        .unwrap();
        assert!(out2.is_none());
    }

    #[test]
    fn bz2_roundtrip_and_budget() {
        let mut enc = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::default());
        {
            let mut builder = tar::Builder::new(&mut enc);
            let data = b"name: x";
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, "info/index.json", &data[..])
                .unwrap();
            builder.finish().unwrap();
        }
        let compressed = enc.finish().unwrap();
        let out = read_metadata_from_tar_bz2_limited(
            &compressed[..],
            |p| p == Path::new("info/index.json"),
            1024 * 1024,
            1000,
            1024 * 1024,
        )
        .unwrap();
        assert_eq!(out.unwrap(), b"name: x");
    }

    #[test]
    fn zip_normal_absent_and_oversized() {
        let archive = zip_bytes(&[("lib/foo.nuspec", b"<id>Foo</id>")]);
        let cursor = std::io::Cursor::new(&archive);
        let out =
            read_metadata_from_zip_limited(cursor, |n| n.ends_with(".nuspec"), 1000, 1024 * 1024)
                .unwrap();
        assert_eq!(out.unwrap(), b"<id>Foo</id>");

        // Absent.
        let cursor2 = std::io::Cursor::new(&archive);
        let out2 =
            read_metadata_from_zip_limited(cursor2, |n| n.ends_with(".missing"), 1000, 1024 * 1024)
                .unwrap();
        assert!(out2.is_none());

        // Oversized matched entry.
        let big = zip_bytes(&[("a.nuspec", &vec![b'a'; 4096][..])]);
        let cursor3 = std::io::Cursor::new(&big);
        let err = read_metadata_from_zip_limited(cursor3, |n| n.ends_with(".nuspec"), 1000, 1024);
        assert!(err.is_err(), "oversized zip entry must reject");
    }

    #[test]
    fn zip_entry_count_breach_is_rejected() {
        let entries: Vec<(String, Vec<u8>)> = (0..20)
            .map(|i| (format!("f{}.txt", i), vec![b'a']))
            .collect();
        let refs: Vec<(&str, &[u8])> = entries
            .iter()
            .map(|(n, d)| (n.as_str(), d.as_slice()))
            .collect();
        let archive = zip_bytes(&refs);
        let cursor = std::io::Cursor::new(&archive);
        let err =
            read_metadata_from_zip_limited(cursor, |n| n.ends_with(".nuspec"), 5, 1024 * 1024);
        assert!(err.is_err(), "zip entry-count breach must reject");
    }

    #[test]
    fn read_capped_rejects_oversized() {
        assert!(read_capped(&b"abcdef"[..], 3, "x").is_err());
        assert_eq!(read_capped(&b"ab"[..], 8, "x").unwrap(), b"ab");
    }

    fn tar_xz(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut builder = tar::Builder::new(xz2::write::XzEncoder::new(Vec::new(), 6));
        for (name, data) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append_data(&mut header, name, *data).unwrap();
        }
        builder.into_inner().unwrap().finish().unwrap()
    }

    fn tar_zst(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let raw = plain_tar(entries);
        zstd::encode_all(std::io::Cursor::new(raw), 3).unwrap()
    }

    fn is_meta(p: &Path) -> bool {
        p == Path::new("metadata.yaml")
    }

    #[test]
    fn xz_normal_and_total_budget_breach() {
        let archive = tar_xz(&[("metadata.yaml", b"name: img\nversion: 1")]);
        let out = read_metadata_from_tar_xz_limited(
            &archive[..],
            is_meta,
            1024 * 1024,
            1000,
            1024 * 1024,
        )
        .unwrap();
        assert_eq!(out.unwrap(), b"name: img\nversion: 1");

        // 2 MiB of zeros before the target entry → past a tiny budget → reject.
        let filler = vec![0u8; 2 * 1024 * 1024];
        let bomb = tar_xz(&[("big.bin", &filler[..]), ("metadata.yaml", b"x")]);
        assert!(bomb.len() < 64 * 1024, "xz of zeros compresses tiny");
        let err = read_metadata_from_tar_xz_limited(&bomb[..], is_meta, 4096, 1000, 1024 * 1024);
        assert!(
            err.is_err(),
            "xz pre-target inflation past budget must reject"
        );
    }

    #[test]
    fn zst_normal_and_total_budget_breach() {
        let archive = tar_zst(&[("metadata.yaml", b"name: img\nversion: 2")]);
        let out = read_metadata_from_tar_zst_limited(
            &archive[..],
            is_meta,
            1024 * 1024,
            1000,
            1024 * 1024,
        )
        .unwrap();
        assert_eq!(out.unwrap(), b"name: img\nversion: 2");

        let filler = vec![0u8; 2 * 1024 * 1024];
        let bomb = tar_zst(&[("big.bin", &filler[..]), ("metadata.yaml", b"x")]);
        assert!(bomb.len() < 64 * 1024, "zstd of zeros compresses tiny");
        let err = read_metadata_from_tar_zst_limited(&bomb[..], is_meta, 4096, 1000, 1024 * 1024);
        assert!(
            err.is_err(),
            "zstd pre-target inflation past budget must reject"
        );
    }

    #[test]
    fn decompress_gz_capped_normal_and_bomb() {
        // Normal small blob round-trips.
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(b"name: g\nversion: 1").unwrap();
        let gz = enc.finish().unwrap();
        assert_eq!(
            decompress_gz_capped(&gz[..], 1024 * 1024, "x").unwrap(),
            b"name: g\nversion: 1"
        );

        // A gzip bomb: tiny compressed, inflates past the cap → reject.
        let mut enc2 = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
        enc2.write_all(&vec![0u8; 4 * 1024 * 1024]).unwrap();
        let bomb = enc2.finish().unwrap();
        assert!(bomb.len() < 64 * 1024, "gzip of zeros compresses tiny");
        assert!(
            decompress_gz_capped(&bomb[..], 1024, "x").is_err(),
            "gzip bomb past cap must reject"
        );
    }

    #[test]
    fn decoded_tar_generic_matches_plain() {
        // The generic decoded-tar seam over a plain (already-"decoded") stream.
        let archive = plain_tar(&[("metadata.yaml", b"ok")]);
        let out =
            read_metadata_from_decoded_tar_limited(&archive[..], is_meta, 1024 * 1024, 1000, 1024)
                .unwrap();
        assert_eq!(out.unwrap(), b"ok");
    }

    // -----------------------------------------------------------------------
    // #2561 — concurrent-ingest-extraction cap
    // -----------------------------------------------------------------------

    #[test]
    fn max_concurrent_ingest_extractions_env_override() {
        // Default when unset; a valid override wins; blank / non-numeric / zero
        // fall back to the default (a zero cap would wedge every upload).
        let key = MAX_CONCURRENT_INGEST_EXTRACTIONS_ENV;
        let saved = std::env::var(key).ok();

        std::env::remove_var(key);
        assert_eq!(
            max_concurrent_ingest_extractions(),
            DEFAULT_MAX_CONCURRENT_INGEST_EXTRACTIONS
        );

        std::env::set_var(key, "3");
        assert_eq!(max_concurrent_ingest_extractions(), 3);

        std::env::set_var(key, "64");
        assert_eq!(max_concurrent_ingest_extractions(), 64);

        for bad in ["0", "", "   ", "abc", "-1"] {
            std::env::set_var(key, bad);
            assert_eq!(
                max_concurrent_ingest_extractions(),
                DEFAULT_MAX_CONCURRENT_INGEST_EXTRACTIONS,
                "value {:?} should fall back to default",
                bad
            );
        }

        // A parseable-but-absurd value above tokio's `Semaphore::MAX_PERMITS`
        // (2^61 - 1) must be CLAMPED, not passed through: `Semaphore::new`
        // panics above that bound, and a panicking `OnceLock` initializer
        // re-panics on every subsequent decode, wedging all ingestion. Kept in
        // this test fn (not a sibling) so no two tests race on the env var.
        std::env::set_var(key, "9999999999999999999");
        assert_eq!(
            max_concurrent_ingest_extractions(),
            Semaphore::MAX_PERMITS,
            "huge override must clamp to Semaphore::MAX_PERMITS, not panic"
        );

        match saved {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
    }

    #[test]
    fn clamp_ingest_permits_bounds_and_floor() {
        // In-range values pass through untouched.
        assert_eq!(clamp_ingest_permits(1), 1);
        assert_eq!(
            clamp_ingest_permits(DEFAULT_MAX_CONCURRENT_INGEST_EXTRACTIONS as u64),
            DEFAULT_MAX_CONCURRENT_INGEST_EXTRACTIONS
        );

        // The exact bound is accepted; anything above clamps to it.
        assert_eq!(
            clamp_ingest_permits(Semaphore::MAX_PERMITS as u64),
            Semaphore::MAX_PERMITS
        );
        assert_eq!(
            clamp_ingest_permits(Semaphore::MAX_PERMITS as u64 + 1),
            Semaphore::MAX_PERMITS
        );
        assert_eq!(
            clamp_ingest_permits(9_999_999_999_999_999_999),
            Semaphore::MAX_PERMITS
        );
        assert_eq!(clamp_ingest_permits(u64::MAX), Semaphore::MAX_PERMITS);

        // Floor: a zero (only reachable if positive_env_or's filter is ever
        // bypassed) still yields a usable semaphore.
        assert_eq!(clamp_ingest_permits(0), 1);

        // The clamped ceiling actually constructs without panicking.
        let _sem = Semaphore::new(clamp_ingest_permits(u64::MAX));
    }

    #[test]
    fn acquire_ingest_extraction_fast_fails_when_saturated() {
        // A *local* cap-1 semaphore (not the process singleton) so this test is
        // deterministic regardless of test-thread count.
        let sem = Arc::new(Semaphore::new(1));

        // Under cap: the first acquire succeeds.
        let first = acquire_ingest_extraction_from(&sem).expect("first acquire is under cap");

        // Saturated: the next acquire FAST-FAILS to a 503 (ServiceUnavailable),
        // it does NOT block.
        let err = acquire_ingest_extraction_from(&sem)
            .expect_err("acquire past the cap must fail fast, not block");
        assert!(
            matches!(err, AppError::ServiceUnavailable(_)),
            "saturation must map to a 503 ServiceUnavailable, got {:?}",
            err
        );

        // Releasing the guard frees the slot promptly (no permit leak): a
        // subsequent acquire succeeds again.
        drop(first);
        let _third = acquire_ingest_extraction_from(&sem)
            .expect("slot must be reusable after the guard drops");
    }

    #[test]
    fn global_wrappers_uncontended_happy_path() {
        let _lock = lock_singletons();
        // The process-wide entry points (which the handlers call) work
        // uncontended: acquire + release, then a scoped decode passes through.
        let guard = acquire_ingest_extraction().expect("global acquire uncontended");
        drop(guard);
        let out = with_ingest_extraction(|| 5).expect("global scoped decode uncontended");
        assert_eq!(out, 5);
    }

    #[test]
    fn with_ingest_extraction_runs_decode_and_releases() {
        let sem = Arc::new(Semaphore::new(1));

        // Under cap: the decode runs and its value passes through.
        let out = with_ingest_extraction_from(&sem, || 41 + 1).expect("under-cap decode runs");
        assert_eq!(out, 42);

        // The permit was released when the closure returned: the slot is free
        // again immediately (no leak), so a second scoped decode also runs.
        let out2 = with_ingest_extraction_from(&sem, || "ok").expect("slot released after decode");
        assert_eq!(out2, "ok");

        // Saturated: the decode is NEVER invoked and the caller gets the 503.
        let held = acquire_ingest_extraction_from(&sem).expect("hold the only slot");
        let mut ran = false;
        let err = with_ingest_extraction_from(&sem, || ran = true)
            .expect_err("saturated helper must shed");
        assert!(
            matches!(err, AppError::ServiceUnavailable(_)),
            "saturation must map to a 503 ServiceUnavailable, got {:?}",
            err
        );
        assert!(!ran, "decode must not run when the acquire sheds");
        drop(held);
    }

    #[tokio::test]
    async fn with_ingest_extraction_async_holds_across_await() {
        let _lock = lock_singletons_async().await;
        // Happy path on the process-wide semaphore (uncontended in tests):
        // the future runs to completion and its value passes through.
        let out = with_ingest_extraction_async(|| async { 7 * 6 })
            .await
            .expect("uncontended async decode runs");
        assert_eq!(out, 42);
    }

    #[test]
    fn under_cap_ingest_extractions_all_proceed() {
        // With headroom every concurrent extraction proceeds unchanged.
        let sem = Arc::new(Semaphore::new(4));
        let g1 = acquire_ingest_extraction_from(&sem).expect("1/4");
        let g2 = acquire_ingest_extraction_from(&sem).expect("2/4");
        let g3 = acquire_ingest_extraction_from(&sem).expect("3/4");
        // Fourth still fits; fifth would shed.
        let g4 = acquire_ingest_extraction_from(&sem).expect("4/4");
        assert!(
            acquire_ingest_extraction_from(&sem).is_err(),
            "the 5th concurrent extraction past a cap of 4 must shed"
        );
        drop((g1, g2, g3, g4));
    }

    /// The registry (read) budget and the ingest (publish) budget must be
    /// SEPARATE singletons. This is the invariant that stops read traffic from
    /// shedding uploads: the hex registry read path re-reads stored tarballs
    /// once per release, so a single anonymous request can fan out to many
    /// extractions. If those spent ingest permits, ~8 concurrent anonymous
    /// registry GETs would 503 publishes across EVERY format in the product.
    #[test]
    fn registry_and_ingest_extraction_semaphores_are_distinct_singletons() {
        assert!(
            !Arc::ptr_eq(
                ingest_extraction_semaphore(),
                registry_extraction_semaphore()
            ),
            "reads and publishes must not share one budget"
        );
    }

    #[test]
    fn registry_and_ingest_extraction_budgets_are_independent() {
        let _lock = lock_singletons();
        // Saturate the real ingest budget completely.
        let ingest_sem = ingest_extraction_semaphore();
        let mut held = Vec::new();
        while let Ok(g) = acquire_ingest_extraction_from(ingest_sem) {
            held.push(g);
        }
        assert!(!held.is_empty(), "ingest budget must have had permits");
        assert!(
            acquire_ingest_extraction_from(ingest_sem).is_err(),
            "ingest budget is now saturated"
        );

        // A registry read must still proceed: it draws on its own budget.
        let out = with_registry_extraction(|| "read served")
            .expect("registry reads must not be shed by a saturated INGEST budget");
        assert_eq!(out, "read served");

        drop(held);
    }

    /// The converse: a saturated registry budget must never shed a publish.
    #[test]
    fn saturated_registry_budget_does_not_shed_ingest() {
        let _lock = lock_singletons();
        let registry_sem = registry_extraction_semaphore();
        let mut held = Vec::new();
        while let Ok(g) = acquire_ingest_extraction_from(registry_sem) {
            held.push(g);
        }
        assert!(!held.is_empty(), "registry budget must have had permits");
        assert!(
            acquire_ingest_extraction_from(registry_sem).is_err(),
            "registry budget is now saturated"
        );

        let out = with_ingest_extraction(|| "publish served")
            .expect("publishes must not be shed by a saturated REGISTRY budget");
        assert_eq!(out, "publish served");

        drop(held);
    }

    #[test]
    fn registry_extraction_runs_the_decode_and_passes_the_value_through() {
        let _lock = lock_singletons();
        let out = with_registry_extraction(|| 6 * 7).expect("uncontended decode runs");
        assert_eq!(out, 42);
    }
}
