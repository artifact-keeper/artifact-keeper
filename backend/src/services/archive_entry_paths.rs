//! Duplicate entry paths in a proxied package archive, found before the
//! scan-on-proxy gate decides what the archive is.
//!
//! The identity readers that tie a proxied package to the coordinate it is
//! served as (`package/package.json`, `Cargo.toml`, `*.nuspec`, `go.mod`,
//! `info/index.json`, ...) take the FIRST entry that matches. The scan
//! extractor (`ScanWorkspace::extract_archive`) writes every entry in order,
//! so the LAST entry at a path is the one left on disk for the engine. A zip
//! reader keyed on the raw name keeps the last central-directory record too,
//! while a reader matching the exact name and an extractor that normalises
//! `./` and `//` see two different files. An archive with two entries at one
//! path can therefore satisfy the identity check with one manifest while the
//! engine grades another, and which of the two a client installs is up to the
//! client's own extractor.
//!
//! The gate refuses to establish an identity for such an archive at all
//! (`proxy_helpers::gate_identity`), the way it treats an unreadable one.
//! Real packages do not carry duplicate paths: a survey of 1,282 published
//! archives (npm, PyPI wheels and sdists, gems, crates, NuGet, Maven jars
//! including Ant-built and shaded ones, conda v1 and v2) found none in any
//! outer container or conda payload tar. So the rule covers every
//! non-directory entry, not only the manifests.
//!
//! What is walked is what the extractor and the readers walk: a gzip or bzip2
//! tar, a plain tar, a zip (its central directory record by record, since the
//! zip crate folds records with the same raw name into one), and for a conda
//! v2 `.conda` the payload tars the extractor unpacks into one tree. The walk
//! runs under ceilings no lower than the extractor's. When it cannot finish,
//! the extractor cannot either (it then scans the raw file and no extracted
//! tree exists to disagree with the reader), so a walk that fails reports
//! nothing and the format's own reader decides as before.

use std::collections::HashSet;
use std::io::{Cursor, Read};

use crate::services::scanner_service::{
    is_conda_payload_member, max_scan_extracted_bytes, MAX_SCAN_EXTRACTED_ENTRIES,
};
use crate::util::bounded_archive;

/// Size of a zip central-directory file header before its variable fields.
const ZIP_CENTRAL_HEADER_LEN: usize = 46;
const ZIP_CENTRAL_HEADER_SIG: [u8; 4] = [0x50, 0x4b, 0x01, 0x02];

/// The first path that two non-directory entries of `bytes` share, after the
/// normalisation the scan extractor applies (`./` and empty components
/// dropped, `\` read as a separator), or `None` when there is none or `bytes`
/// is not an archive the gate's readers or the scan extractor open.
///
/// `filename` selects the conda v2 payload walk, as it selects the conda
/// reader and the conda extractor.
pub(crate) fn duplicated_entry_path(filename: &str, bytes: &[u8]) -> Option<String> {
    let budget = max_scan_extracted_bytes();
    if bytes.starts_with(&[0x1f, 0x8b]) {
        if let Some(dup) = tar_duplicate(flate2::read::GzDecoder::new(bytes), budget) {
            return Some(dup);
        }
    }
    if bytes.starts_with(b"BZh") {
        if let Some(dup) = tar_duplicate(bzip2::read::MultiBzDecoder::new(bytes), budget) {
            return Some(dup);
        }
    }
    if let Some(dup) = tar_duplicate(bytes, budget) {
        return Some(dup);
    }
    zip_duplicate(filename, bytes, budget)
}

/// The key the extractor writes an entry under: its normal components joined
/// with `/`. A `..` is kept as a component (the extractor skips such an
/// entry, and keeping it stops it colliding with a real path).
fn normalized(raw: &str) -> String {
    raw.split(['/', '\\'])
        .filter(|c| !c.is_empty() && *c != ".")
        .collect::<Vec<_>>()
        .join("/")
}

/// Paths seen so far in one extracted tree.
struct Tree {
    paths: HashSet<String>,
    entries: u64,
}

impl Tree {
    fn new() -> Self {
        Self {
            paths: HashSet::new(),
            entries: 0,
        }
    }

    /// Record one entry. `Err` past the entry ceiling, `Ok(Some(path))` when
    /// the path was already taken.
    fn add(&mut self, raw: &str) -> Result<Option<String>, ()> {
        self.entries += 1;
        if self.entries > MAX_SCAN_EXTRACTED_ENTRIES {
            return Err(());
        }
        let key = normalized(raw);
        if self.paths.insert(key.clone()) {
            Ok(None)
        } else {
            Ok(Some(key))
        }
    }

    /// A directory entry counts toward the entry ceiling as the extractor's
    /// does, but two directory entries at one path are harmless.
    fn add_dir(&mut self) {
        self.entries += 1;
    }
}

/// The first duplicated path of a decoded tar stream, or `None` when there is
/// none or the stream is not a tar the extractor can walk to the end.
fn tar_duplicate<R: Read>(decoded: R, budget: u64) -> Option<String> {
    let mut tree = Tree::new();
    tar_walk(decoded, budget, &mut tree).ok().flatten()
}

/// Walk a decoded tar stream into `tree`. `Ok(Some)` at the first duplicate;
/// `Err` when the stream is not a tar or breaches a ceiling.
fn tar_walk<R: Read>(decoded: R, budget: u64, tree: &mut Tree) -> Result<Option<String>, ()> {
    let mut archive = tar::Archive::new(bounded_archive::budgeted_to(decoded, budget));
    for entry in archive.entries().map_err(|_| ())? {
        let entry = entry.map_err(|_| ())?;
        if entry.header().entry_type().is_dir() {
            tree.add_dir();
            continue;
        }
        let path = entry.path().map_err(|_| ())?;
        let path = path.to_string_lossy().into_owned();
        if let Some(dup) = tree.add(&path)? {
            return Ok(Some(dup));
        }
    }
    Ok(None)
}

/// The raw names of a zip's central-directory records, in order, one per
/// record (the zip crate keeps only the last record of a repeated name).
/// `None` when the directory cannot be walked.
fn zip_central_names(bytes: &[u8], start: u64) -> Option<Vec<String>> {
    let mut pos = usize::try_from(start).ok()?;
    let mut names = Vec::new();
    while bytes.get(pos..pos + 4) == Some(&ZIP_CENTRAL_HEADER_SIG[..]) {
        if names.len() as u64 > MAX_SCAN_EXTRACTED_ENTRIES {
            return None;
        }
        let header = bytes.get(pos..pos + ZIP_CENTRAL_HEADER_LEN)?;
        let field = |at: usize| usize::from(u16::from_le_bytes([header[at], header[at + 1]]));
        let (name_len, extra_len, comment_len) = (field(28), field(30), field(32));
        let name_start = pos + ZIP_CENTRAL_HEADER_LEN;
        let name = bytes.get(name_start..name_start + name_len)?;
        names.push(String::from_utf8_lossy(name).into_owned());
        pos = name_start + name_len + extra_len + comment_len;
    }
    Some(names)
}

fn is_dir_name(name: &str) -> bool {
    name.ends_with('/') || name.ends_with('\\')
}

/// The first duplicated path of a zip: two central-directory records with one
/// raw name, two entries whose decoded names normalise to one path, or (for
/// a `.conda`) more than one info payload, or two payload entries at one path.
fn zip_duplicate(filename: &str, bytes: &[u8], budget: u64) -> Option<String> {
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).ok()?;
    if archive.len() as u64 > MAX_SCAN_EXTRACTED_ENTRIES {
        return None;
    }

    let mut records = Tree::new();
    for name in zip_central_names(bytes, archive.central_directory_start())? {
        if is_dir_name(&name) {
            records.add_dir();
            continue;
        }
        if let Some(dup) = records.add(&name).ok()? {
            return Some(dup);
        }
    }

    let mut decoded = Tree::new();
    let mut names = Vec::with_capacity(archive.len());
    for i in 0..archive.len() {
        let name = archive.name_for_index(i)?.ok()?.into_owned();
        if !is_dir_name(&name) {
            if let Some(dup) = decoded.add(&name).ok()? {
                return Some(dup);
            }
        }
        names.push(name);
    }

    if !filename.to_ascii_lowercase().ends_with(".conda") {
        return None;
    }
    conda_payload_duplicate(&mut archive, &names, budget)
}

/// A `.conda` container's payload as the extractor sees it: every root-level
/// `pkg-*.tar.zst` / `info-*.tar.zst` member unpacked into ONE tree. The
/// identity reader reads `info/index.json` from the first member whose raw
/// name starts with `info-`, so more than one member that either side takes
/// for the info payload is refused as well.
fn conda_payload_duplicate(
    archive: &mut zip::ZipArchive<Cursor<&[u8]>>,
    names: &[String],
    budget: u64,
) -> Option<String> {
    let mut members = Vec::new();
    let mut info_members = 0usize;
    for (i, name) in names.iter().enumerate() {
        let read_as_info = name.starts_with("info-") && name.ends_with(".tar.zst");
        let unpacked = archive
            .by_index(i)
            .ok()?
            .enclosed_name()
            .filter(|p| is_conda_payload_member(p));
        let unpacked_as_info = unpacked
            .as_ref()
            .and_then(|p| p.file_name())
            .is_some_and(|leaf| leaf.to_string_lossy().starts_with("info-"));
        if read_as_info || unpacked_as_info {
            info_members += 1;
        }
        if read_as_info || unpacked.is_some() {
            members.push(i);
        }
    }
    if info_members > 1 {
        return Some("info-*.tar.zst".to_string());
    }

    let mut tree = Tree::new();
    for i in members {
        let member = archive.by_index(i).ok()?;
        let decoder = zstd::Decoder::new(member).ok()?;
        if let Some(dup) = tar_walk(decoder, budget, &mut tree).ok()? {
            return Some(dup);
        }
    }
    None
}

/// Archive builders that, unlike the `zip` and `tar` writers' safe paths,
/// can put two entries at one path. Shared by the per-format tests.
#[cfg(test)]
pub(crate) mod test_support {
    /// CRC-32 (IEEE), bit by bit; the stored entries below need it.
    fn crc32(data: &[u8]) -> u32 {
        let mut crc = !0u32;
        for &b in data {
            crc ^= u32::from(b);
            for _ in 0..8 {
                crc = if crc & 1 != 0 {
                    (crc >> 1) ^ 0xEDB8_8320
                } else {
                    crc >> 1
                };
            }
        }
        !crc
    }

    /// A stored (uncompressed) zip with exactly these entries, in order,
    /// duplicates included.
    pub(crate) fn zip_with(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut central = Vec::new();
        for (name, data) in entries {
            let offset = out.len() as u32;
            let crc = crc32(data);
            let (n, len) = (name.len() as u16, data.len() as u32);
            out.extend_from_slice(&[0x50, 0x4b, 0x03, 0x04]);
            out.extend_from_slice(&20u16.to_le_bytes()); // version needed
            out.extend_from_slice(&0x0800u16.to_le_bytes()); // flags: UTF-8 names
            out.extend_from_slice(&0u16.to_le_bytes()); // stored
            out.extend_from_slice(&0u32.to_le_bytes()); // time, date
            out.extend_from_slice(&crc.to_le_bytes());
            out.extend_from_slice(&len.to_le_bytes());
            out.extend_from_slice(&len.to_le_bytes());
            out.extend_from_slice(&n.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes()); // extra
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(data);

            central.extend_from_slice(&[0x50, 0x4b, 0x01, 0x02]);
            central.extend_from_slice(&0x031Eu16.to_le_bytes()); // made by: unix
            central.extend_from_slice(&20u16.to_le_bytes());
            central.extend_from_slice(&0x0800u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u32.to_le_bytes());
            central.extend_from_slice(&crc.to_le_bytes());
            central.extend_from_slice(&len.to_le_bytes());
            central.extend_from_slice(&len.to_le_bytes());
            central.extend_from_slice(&n.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes()); // extra
            central.extend_from_slice(&0u16.to_le_bytes()); // comment
            central.extend_from_slice(&0u16.to_le_bytes()); // disk
            central.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
            let mode: u32 = if name.ends_with('/') {
                0o040755
            } else {
                0o100644
            };
            central.extend_from_slice(&(mode << 16).to_le_bytes());
            central.extend_from_slice(&offset.to_le_bytes());
            central.extend_from_slice(name.as_bytes());
        }
        let cd_offset = out.len() as u32;
        let count = entries.len() as u16;
        out.extend_from_slice(&central);
        out.extend_from_slice(&[0x50, 0x4b, 0x05, 0x06]);
        out.extend_from_slice(&0u32.to_le_bytes()); // disk numbers
        out.extend_from_slice(&count.to_le_bytes());
        out.extend_from_slice(&count.to_le_bytes());
        out.extend_from_slice(&(central.len() as u32).to_le_bytes());
        out.extend_from_slice(&cd_offset.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // comment
        out
    }

    /// A plain tar with exactly these entries, in order, duplicates included.
    /// The name is written into the header verbatim (a `./` prefix kept), so
    /// it must fit the 100-byte ustar name field.
    pub(crate) fn tar_with(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for (name, data) in entries {
            let mut header = tar::Header::new_ustar();
            let raw = &mut header.as_old_mut().name;
            raw[..name.len()].copy_from_slice(name.as_bytes());
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_entry_type(tar::EntryType::Regular);
            header.set_cksum();
            builder.append(&header, *data).unwrap();
        }
        builder.into_inner().unwrap()
    }

    /// [`tar_with`], gzipped.
    pub(crate) fn tar_gz_with(entries: &[(&str, &[u8])]) -> Vec<u8> {
        use std::io::Write;
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        gz.write_all(&tar_with(entries)).unwrap();
        gz.finish().unwrap()
    }

    /// [`tar_with`], bzip2-compressed.
    pub(crate) fn tar_bz2_with(entries: &[(&str, &[u8])]) -> Vec<u8> {
        use std::io::Write;
        let mut bz = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::fast());
        bz.write_all(&tar_with(entries)).unwrap();
        bz.finish().unwrap()
    }

    /// [`tar_with`], zstd-compressed (a `.conda` payload member).
    pub(crate) fn tar_zst_with(entries: &[(&str, &[u8])]) -> Vec<u8> {
        zstd::encode_all(&tar_with(entries)[..], 1).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;

    const GOOD: &[u8] = br#"{"name":"left","version":"1.0.0"}"#;
    const EVIL: &[u8] = br#"{"name":"right","version":"9.9.9"}"#;

    #[test]
    fn normalisation_matches_the_extractor() {
        assert_eq!(
            normalized("./package//package.json"),
            "package/package.json"
        );
        assert_eq!(normalized("/package/package.json"), "package/package.json");
        assert_eq!(normalized("a\\b"), "a/b");
        assert_eq!(normalized("a/../b"), "a/../b");
    }

    #[test]
    fn single_entries_are_not_duplicates() {
        let entries: &[(&str, &[u8])] = &[("package/package.json", GOOD), ("package/a.js", b"x")];
        assert_eq!(duplicated_entry_path("p.tgz", &tar_gz_with(entries)), None);
        assert_eq!(duplicated_entry_path("p.gem", &tar_with(entries)), None);
        assert_eq!(
            duplicated_entry_path("p.tar.bz2", &tar_bz2_with(entries)),
            None
        );
        assert_eq!(duplicated_entry_path("p.zip", &zip_with(entries)), None);
        // Directory entries repeat harmlessly.
        let dirs: &[(&str, &[u8])] = &[("d/", b""), ("d/", b""), ("d/f", b"x")];
        assert_eq!(duplicated_entry_path("p.zip", &zip_with(dirs)), None);
        // Not an archive at all.
        assert_eq!(duplicated_entry_path("p.tgz", b"<html>"), None);
    }

    #[test]
    fn every_container_reports_a_repeated_path() {
        for (first, second) in [
            ("package/package.json", "package/package.json"),
            ("package/package.json", "./package/package.json"),
            ("package/package.json", "package//package.json"),
        ] {
            let entries: &[(&str, &[u8])] =
                &[(first, GOOD), ("package/a.js", b"x"), (second, EVIL)];
            let want = Some("package/package.json".to_string());
            assert_eq!(
                duplicated_entry_path("p.tgz", &tar_gz_with(entries)),
                want,
                "{second}"
            );
            assert_eq!(
                duplicated_entry_path("p.gem", &tar_with(entries)),
                want,
                "{second}"
            );
            assert_eq!(
                duplicated_entry_path("p.tar.bz2", &tar_bz2_with(entries)),
                want
            );
            assert_eq!(
                duplicated_entry_path("p.zip", &zip_with(entries)),
                want,
                "{second}"
            );
        }
    }

    /// The defect itself, on the shared readers and the scan extractor: the
    /// reader returns the FIRST copy, the extracted tree holds the LAST.
    #[tokio::test]
    async fn readers_take_the_first_copy_and_the_extractor_keeps_the_last() {
        use crate::services::scanner_service::ScanWorkspace;
        use std::sync::atomic::AtomicBool;
        use std::sync::Arc;

        let entries: &[(&str, &[u8])] = &[
            ("package/package.json", GOOD),
            ("package/package.json", EVIL),
        ];
        let tgz = tar_gz_with(entries);
        let read = bounded_archive::read_metadata_from_tar_gz(&tgz[..], |p| {
            p == std::path::Path::new("package/package.json")
        })
        .unwrap();
        assert_eq!(read.as_deref(), Some(GOOD));

        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("p-1.0.0.tgz");
        std::fs::write(&archive, &tgz).unwrap();
        let out = dir.path().join("out");
        std::fs::create_dir_all(&out).unwrap();
        ScanWorkspace::extract_archive(&archive, &out, Arc::new(AtomicBool::new(false)))
            .await
            .unwrap();
        assert_eq!(
            std::fs::read(out.join("package/package.json")).unwrap(),
            EVIL
        );

        // A zip whose second copy differs only by `./`: the exact-name reader
        // reads the first, the extractor normalises both onto one file.
        let zip = zip_with(&[("m@v1.0.0/go.mod", GOOD), ("m@v1.0.0/./go.mod", EVIL)]);
        let read = bounded_archive::read_metadata_from_zip(Cursor::new(&zip[..]), |n| {
            n == "m@v1.0.0/go.mod"
        })
        .unwrap();
        assert_eq!(read.as_deref(), Some(GOOD));
        let archive = dir.path().join("m.zip");
        std::fs::write(&archive, &zip).unwrap();
        let out = dir.path().join("zip-out");
        std::fs::create_dir_all(&out).unwrap();
        ScanWorkspace::extract_archive(&archive, &out, Arc::new(AtomicBool::new(false)))
            .await
            .unwrap();
        assert_eq!(std::fs::read(out.join("m@v1.0.0/go.mod")).unwrap(), EVIL);

        assert!(duplicated_entry_path("p-1.0.0.tgz", &tgz).is_some());
        assert!(duplicated_entry_path("m.zip", &zip).is_some());
    }

    #[test]
    fn a_conda_container_is_walked_as_its_extracted_payload() {
        let info_good = tar_zst_with(&[("info/index.json", GOOD)]);
        let info_evil = tar_zst_with(&[("info/index.json", EVIL)]);
        let pkg = tar_zst_with(&[("lib/x.py", b"x")]);
        let ok = zip_with(&[
            ("metadata.json", b"{}"),
            ("info-p-1.0-0.tar.zst", &info_good),
            ("pkg-p-1.0-0.tar.zst", &pkg),
        ]);
        assert_eq!(duplicated_entry_path("p-1.0-0.conda", &ok), None);

        // `info/index.json` again in the pkg payload, unpacked into the same
        // tree after the info payload.
        let pkg_with_index = tar_zst_with(&[("info/index.json", EVIL)]);
        let shadowed = zip_with(&[
            ("info-p-1.0-0.tar.zst", &info_good),
            ("pkg-p-1.0-0.tar.zst", &pkg_with_index),
        ]);
        assert_eq!(
            duplicated_entry_path("p-1.0-0.conda", &shadowed).as_deref(),
            Some("info/index.json")
        );
        // Not a `.conda`: the payload is not unpacked by anyone.
        assert_eq!(duplicated_entry_path("p-1.0-0.zip", &shadowed), None);

        // Two info payloads, the second only the extractor's (`./` prefix).
        let two_infos = zip_with(&[
            ("info-p-1.0-0.tar.zst", &info_good),
            ("./info-q-1.0-0.tar.zst", &info_evil),
        ]);
        assert_eq!(
            duplicated_entry_path("p-1.0-0.conda", &two_infos).as_deref(),
            Some("info-*.tar.zst")
        );
        // One the reader takes for the info payload but the extractor never
        // unpacks (not at the root), beside the real one.
        let nested = zip_with(&[
            ("info-x/a.tar.zst", &info_evil),
            ("info-p-1.0-0.tar.zst", &info_good),
        ]);
        assert_eq!(
            duplicated_entry_path("p-1.0-0.conda", &nested).as_deref(),
            Some("info-*.tar.zst")
        );
    }

    #[test]
    fn a_zip_with_leading_bytes_is_still_walked() {
        let mut prefixed = b"#!/bin/sh\nexit 0\n".to_vec();
        let zip = zip_with(&[("a/METADATA", GOOD), ("a/METADATA", EVIL)]);
        // The offsets in a prepended zip are relative to the original start;
        // the zip crate locates the archive from its end either way.
        prefixed.extend_from_slice(&zip);
        if zip::ZipArchive::new(Cursor::new(&prefixed[..])).is_ok() {
            assert_eq!(
                duplicated_entry_path("a.whl", &prefixed).as_deref(),
                Some("a/METADATA")
            );
        }
    }
}
