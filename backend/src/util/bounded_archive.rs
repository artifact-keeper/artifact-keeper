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
    BudgetReader::new(reader, max_ingest_decompressed_bytes())
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
    let decoder = flate2::read::GzDecoder::new(reader);
    read_tar_entries(
        BudgetReader::new(decoder, max_total),
        matches,
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
    let decoder = bzip2::read::BzDecoder::new(reader);
    read_tar_entries(
        BudgetReader::new(decoder, max_total),
        matches,
        max_entries,
        max_entry,
    )
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
    read_tar_entries(
        BudgetReader::new(reader, max_total),
        matches,
        max_entries,
        max_entry,
    )
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
}
