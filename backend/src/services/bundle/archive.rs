//! Bounded, header-first inspection of an untrusted bundle tar stream.
//!
//! [`index_bundle`] walks every tar header once, without extracting anything,
//! and refuses the bundle on the first entry that could escape or confuse an
//! unpack: a traversal/absolute/drive-letter path (zip-slip), a path outside
//! the bundle layout, a symlink, hard link, device or FIFO, a duplicate path
//! (a later entry silently overwriting an earlier, already-verified one), a
//! compressed stream, or a breach of the entry-count or total-byte budget.
//! The manifest must be the first entry so an importer can plan before it
//! streams content. [`cross_check`] then reconciles the index with the
//! manifest so nothing crosses that the manifest does not account for.
//!
//! This is the pre-pass the import worker (PR3) runs before any database
//! write; it is pure over a `Read`, so it is unit-tested here against
//! hand-crafted hostile archives.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Cursor, Read};

use super::layout::{check_directory, classify_file, BundleEntry, MANIFEST_PATH};
use super::manifest::{
    decode_manifest, sha256_hex, validate_manifest, BundleManifest, ManifestSummary,
};
use super::{BundleError, BundleLimits};
use crate::util::bounded_archive::{budgeted_to, is_decompression_budget_breach};

/// Leading magic bytes of the stream formats a bundle must not be wrapped in.
const WRAPPER_MAGIC: &[(&[u8], &str)] = &[
    (b"\x1f\x8b", "gzip"),
    (b"\x28\xb5\x2f\xfd", "zstd"),
    (b"\xfd7zXZ\x00", "xz"),
    (b"BZh", "bzip2"),
    (b"PK\x03\x04", "zip"),
];

/// Longest magic in [`WRAPPER_MAGIC`].
const MAGIC_PEEK_BYTES: usize = 6;

/// Refuse a stream whose first bytes are a compression or archive wrapper.
pub fn refuse_compressed_prefix(head: &[u8]) -> Result<(), BundleError> {
    match WRAPPER_MAGIC
        .iter()
        .find(|(magic, _)| head.starts_with(magic))
    {
        Some((_, name)) => Err(BundleError::Compressed(name)),
        None => Ok(()),
    }
}

/// Header-level index of a bundle: the manifest bytes and every other file
/// with its declared size.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleIndex {
    pub manifest: Vec<u8>,
    pub files: BTreeMap<String, u64>,
}

fn archive_err(err: &io::Error, limits: &BundleLimits) -> BundleError {
    if is_decompression_budget_breach(err) {
        BundleError::LimitExceeded(format!(
            "bundle stream is larger than {} bytes",
            limits.max_total_bytes
        ))
    } else {
        BundleError::InvalidArchive(err.to_string())
    }
}

fn read_manifest_entry<R: Read>(
    entry: &mut R,
    limits: &BundleLimits,
) -> Result<Vec<u8>, BundleError> {
    let mut buf = Vec::new();
    entry
        .take(limits.max_manifest_bytes + 1)
        .read_to_end(&mut buf)
        .map_err(|e| archive_err(&e, limits))?;
    if buf.len() as u64 > limits.max_manifest_bytes {
        return Err(BundleError::LimitExceeded(format!(
            "manifest is larger than {} bytes",
            limits.max_manifest_bytes
        )));
    }
    Ok(buf)
}

/// Walk every tar header of an untrusted bundle stream (see module docs).
pub fn index_bundle<R: Read>(
    mut reader: R,
    limits: &BundleLimits,
) -> Result<BundleIndex, BundleError> {
    let mut head = Vec::with_capacity(MAGIC_PEEK_BYTES);
    (&mut reader)
        .take(MAGIC_PEEK_BYTES as u64)
        .read_to_end(&mut head)
        .map_err(|e| BundleError::InvalidArchive(e.to_string()))?;
    refuse_compressed_prefix(&head)?;

    let stream = budgeted_to(Cursor::new(head).chain(reader), limits.max_total_bytes);
    let mut archive = tar::Archive::new(stream);
    let entries = archive.entries().map_err(|e| archive_err(&e, limits))?;

    let mut manifest: Option<Vec<u8>> = None;
    let mut files = BTreeMap::new();
    let mut seen = BTreeSet::new();
    let mut count: u64 = 0;

    for entry in entries {
        let mut entry = entry.map_err(|e| archive_err(&e, limits))?;
        count += 1;
        if count > limits.max_entries {
            return Err(BundleError::LimitExceeded(format!(
                "bundle has more than {} entries",
                limits.max_entries
            )));
        }

        let raw = entry.path_bytes().into_owned();
        let path = String::from_utf8(raw).map_err(|e| BundleError::UnsafePath {
            path: String::from_utf8_lossy(e.as_bytes()).into_owned(),
            reason: "path is not UTF-8".into(),
        })?;
        let entry_type = entry.header().entry_type();

        if entry_type.is_dir() {
            let dir = path.strip_suffix('/').unwrap_or(&path);
            check_directory(dir)?;
            if !seen.insert(dir.to_string()) {
                return Err(BundleError::DuplicateEntry(dir.to_string()));
            }
            continue;
        }
        if !(entry_type.is_file() || entry_type == tar::EntryType::Continuous) {
            // Classify first so a hostile path is reported as such, then
            // refuse the type even when the path itself is fine.
            classify_file(&path)?;
            return Err(BundleError::DisallowedEntryType {
                path,
                kind: format!("{entry_type:?}"),
            });
        }

        let kind = classify_file(&path)?;
        if !seen.insert(path.clone()) {
            return Err(BundleError::DuplicateEntry(path));
        }
        if manifest.is_none() && kind != BundleEntry::Manifest {
            return Err(BundleError::Invalid(format!(
                "{MANIFEST_PATH} must be the first file in the bundle, found {path:?}"
            )));
        }
        if kind == BundleEntry::Manifest {
            manifest = Some(read_manifest_entry(&mut entry, limits)?);
        } else {
            // `entry.size()` is the size the stream is actually advanced by
            // (a PAX `size` record overrides the ustar header field), so the
            // cross-check reconciles what was read, not what a header claims.
            files.insert(path, entry.size());
        }
    }

    let manifest =
        manifest.ok_or_else(|| BundleError::Invalid(format!("bundle has no {MANIFEST_PATH}")))?;
    Ok(BundleIndex { manifest, files })
}

/// Reconcile an index with its manifest for `volume` (1-based). Every path the
/// manifest names for that volume must be present with the declared size, and
/// every present file must be named by the manifest. Repository metadata,
/// evidence and signing documents travel on volume 1.
pub fn cross_check(index: &BundleIndex, manifest: &BundleManifest, volume: u32) -> Vec<String> {
    let mut expected: BTreeMap<&str, Option<u64>> = BTreeMap::new();
    let mut problems = Vec::new();

    if volume == 1 {
        for repo in &manifest.repositories {
            expected.insert(&repo.metadata_path, None);
            expected.insert(&repo.artifacts_path, None);
            if let Some(oci) = &repo.oci_path {
                expected.insert(oci, None);
            }
        }
        for ev in &manifest.scan_evidence {
            if let Some(path) = &ev.evidence_path {
                expected.insert(path, None);
            }
        }
        if let Some(path) = manifest
            .signing
            .as_ref()
            .and_then(|s| s.key_status_list_path.as_ref())
        {
            expected.insert(path, None);
        }
    }
    for item in manifest.items.iter().filter(|i| i.volume == volume) {
        match expected.insert(&item.blob_path, Some(item.size_bytes)) {
            Some(Some(prev)) if prev != item.size_bytes => problems.push(format!(
                "{}: items sharing this blob declare different sizes",
                item.blob_path
            )),
            _ => {}
        }
    }

    for (path, size) in &expected {
        match (index.files.get(*path), size) {
            (None, _) => problems.push(format!("{path}: named by the manifest but missing")),
            (Some(actual), Some(declared)) if actual != declared => problems.push(format!(
                "{path}: archive entry is {actual} bytes, manifest declares {declared}"
            )),
            _ => {}
        }
    }
    for path in index.files.keys() {
        if !expected.contains_key(path.as_str()) {
            problems.push(format!("{path}: not referenced by the manifest"));
        }
    }
    problems
}

/// A single-volume bundle that passed every header-level and manifest check.
#[derive(Debug, Clone)]
pub struct InspectedBundle {
    pub manifest: BundleManifest,
    pub manifest_sha256: String,
    pub summary: ManifestSummary,
}

/// Index, decode, validate and cross-check a single-volume bundle stream.
/// Content digests are NOT verified here; the import worker (PR3) hashes each
/// blob as it streams it to staging, before any database write.
pub fn inspect_bundle<R: Read>(
    reader: R,
    limits: &BundleLimits,
) -> Result<InspectedBundle, BundleError> {
    let index = index_bundle(reader, limits)?;
    let manifest = decode_manifest(&index.manifest, limits)?;
    let summary =
        validate_manifest(&manifest, limits).map_err(|p| BundleError::Invalid(p.join("; ")))?;
    let problems = cross_check(&index, &manifest, 1);
    if !problems.is_empty() {
        return Err(BundleError::Invalid(problems.join("; ")));
    }
    Ok(InspectedBundle {
        manifest_sha256: sha256_hex(&index.manifest),
        manifest,
        summary,
    })
}

#[cfg(ak_test_shard = "services-1")]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::bundle::manifest::encode_manifest;
    use crate::services::bundle::manifest::tests::{sample_manifest, SHA_A, SHA_B};

    /// Append an entry with a raw header name, bypassing the `tar` crate's own
    /// path sanitising, which is exactly what a hostile producer would do.
    fn raw_entry(
        b: &mut tar::Builder<Vec<u8>>,
        name: &str,
        kind: tar::EntryType,
        data: &[u8],
        link: Option<&str>,
    ) {
        let mut h = tar::Header::new_gnu();
        {
            let gnu = h.as_gnu_mut().unwrap();
            gnu.name.fill(0);
            gnu.name[..name.len()].copy_from_slice(name.as_bytes());
        }
        h.set_entry_type(kind);
        h.set_mode(0o644);
        h.set_size(data.len() as u64);
        if let Some(target) = link {
            h.set_link_name(target).unwrap();
        }
        h.set_cksum();
        b.append(&h, data).unwrap();
    }

    fn file(b: &mut tar::Builder<Vec<u8>>, name: &str, data: &[u8]) {
        raw_entry(b, name, tar::EntryType::Regular, data, None);
    }

    /// A valid single-volume bundle for [`sample_manifest`].
    fn valid_bundle_parts() -> Vec<(String, Vec<u8>)> {
        let m = sample_manifest();
        let mut parts = vec![(MANIFEST_PATH.to_string(), encode_manifest(&m).unwrap())];
        parts.push(("repos/libs/repo.json".into(), b"{}".to_vec()));
        parts.push(("repos/libs/artifacts.json".into(), b"[]".to_vec()));
        for item in &m.items {
            parts.push((item.blob_path.clone(), vec![b'x'; item.size_bytes as usize]));
        }
        parts
    }

    fn build(parts: &[(String, Vec<u8>)]) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        raw_entry(&mut b, "blobs/", tar::EntryType::Directory, b"", None);
        for (name, data) in parts {
            file(&mut b, name, data);
        }
        b.into_inner().unwrap()
    }

    fn limits() -> BundleLimits {
        BundleLimits::default()
    }

    /// A bundle whose manifest is first, followed by one hostile entry.
    fn with_hostile(name: &str, kind: tar::EntryType, link: Option<&str>) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        file(
            &mut b,
            MANIFEST_PATH,
            &encode_manifest(&sample_manifest()).unwrap(),
        );
        raw_entry(&mut b, name, kind, b"pwned", link);
        b.into_inner().unwrap()
    }

    #[test]
    fn a_valid_bundle_inspects_clean() {
        let bytes = build(&valid_bundle_parts());
        let inspected = inspect_bundle(bytes.as_slice(), &limits()).unwrap();
        assert_eq!(inspected.summary.item_count, 2);
        assert_eq!(inspected.manifest_sha256.len(), 64);
    }

    #[test]
    fn contiguous_file_entries_are_accepted_as_regular_files() {
        let mut parts = valid_bundle_parts();
        let (name, data) = parts.pop().unwrap();
        let mut b = tar::Builder::new(Vec::new());
        for (n, d) in &parts {
            file(&mut b, n, d);
        }
        raw_entry(&mut b, &name, tar::EntryType::Continuous, &data, None);
        let bytes = b.into_inner().unwrap();
        let inspected = inspect_bundle(bytes.as_slice(), &limits()).unwrap();
        assert_eq!(inspected.summary.item_count, 2);
    }

    #[test]
    fn pax_size_override_is_what_gets_reconciled() {
        // The ustar header claims the manifest's 10 bytes for blob A, but a PAX
        // record says 5 and only 5 bytes follow. Readers advance by the PAX
        // size, so the cross-check must see 5, not the header's 10.
        let parts = valid_bundle_parts();
        let mut b = tar::Builder::new(Vec::new());
        for (n, d) in &parts {
            if n.contains(SHA_A) {
                b.append_pax_extensions([("size", b"5".as_slice())])
                    .unwrap();
                let mut h = tar::Header::new_gnu();
                h.set_path(n).unwrap();
                h.set_mode(0o644);
                h.set_size(10);
                h.set_cksum();
                b.append(&h, &b"xxxxx"[..]).unwrap();
            } else {
                file(&mut b, n, d);
            }
        }
        let index = index_bundle(b.into_inner().unwrap().as_slice(), &limits()).unwrap();
        let blob = parts.iter().find(|(n, _)| n.contains(SHA_A)).unwrap();
        assert_eq!(index.files.get(&blob.0), Some(&5));
        let problems = cross_check(&index, &sample_manifest(), 1);
        assert!(
            problems
                .iter()
                .any(|p| p.contains("archive entry is 5 bytes")),
            "{problems:?}"
        );
    }

    #[test]
    fn zip_slip_entries_are_refused_before_extraction() {
        for name in [
            "../evil.sh",
            "blobs/../../etc/cron.d/x",
            "/etc/passwd",
            "C:/Windows/evil.dll",
            "repos/libs/../../../x",
            "blobs\\..\\..\\evil",
        ] {
            let err = index_bundle(
                with_hostile(name, tar::EntryType::Regular, None).as_slice(),
                &limits(),
            )
            .unwrap_err();
            assert!(
                matches!(err, BundleError::UnsafePath { .. }),
                "{name:?}: {err}"
            );
        }
    }

    #[test]
    fn links_devices_and_fifos_are_refused() {
        let blob = format!("blobs/aa/{SHA_A}.jar");
        for (kind, link) in [
            (tar::EntryType::Symlink, Some("/etc/passwd")),
            (tar::EntryType::Link, Some(MANIFEST_PATH)),
            (tar::EntryType::Char, None),
            (tar::EntryType::Block, None),
            (tar::EntryType::Fifo, None),
        ] {
            let err =
                index_bundle(with_hostile(&blob, kind, link).as_slice(), &limits()).unwrap_err();
            assert!(
                matches!(err, BundleError::DisallowedEntryType { .. }),
                "{kind:?}: {err}"
            );
        }
        // A symlink with a traversal name is reported as the unsafe path.
        let err = index_bundle(
            with_hostile("../x", tar::EntryType::Symlink, Some("/")).as_slice(),
            &limits(),
        )
        .unwrap_err();
        assert!(matches!(err, BundleError::UnsafePath { .. }), "{err}");
    }

    #[test]
    fn duplicate_entries_are_refused() {
        let mut parts = valid_bundle_parts();
        parts.push(parts[3].clone());
        let err = index_bundle(build(&parts).as_slice(), &limits()).unwrap_err();
        assert!(matches!(err, BundleError::DuplicateEntry(_)), "{err}");

        let mut b = tar::Builder::new(Vec::new());
        file(&mut b, MANIFEST_PATH, b"{}");
        raw_entry(&mut b, "blobs", tar::EntryType::Directory, b"", None);
        raw_entry(&mut b, "blobs/", tar::EntryType::Directory, b"", None);
        let err = index_bundle(b.into_inner().unwrap().as_slice(), &limits()).unwrap_err();
        assert!(matches!(err, BundleError::DuplicateEntry(_)), "{err}");
    }

    #[test]
    fn unexpected_directories_are_refused() {
        let err = index_bundle(
            with_hostile("tmp/", tar::EntryType::Directory, None).as_slice(),
            &limits(),
        )
        .unwrap_err();
        assert!(matches!(err, BundleError::UnsafePath { .. }), "{err}");
    }

    #[test]
    fn manifest_must_come_first_and_exist() {
        let mut parts = valid_bundle_parts();
        parts.swap(0, 1);
        let err = index_bundle(build(&parts).as_slice(), &limits()).unwrap_err();
        assert!(err.to_string().contains("must be the first file"), "{err}");

        let empty = tar::Builder::new(Vec::new()).into_inner().unwrap();
        let err = index_bundle(empty.as_slice(), &limits()).unwrap_err();
        assert!(err.to_string().contains("has no manifest.json"), "{err}");
    }

    #[test]
    fn compressed_bundles_are_refused() {
        let tar_bytes = build(&valid_bundle_parts());
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        std::io::Write::write_all(&mut gz, &tar_bytes).unwrap();
        let err = index_bundle(gz.finish().unwrap().as_slice(), &limits()).unwrap_err();
        assert_eq!(err, BundleError::Compressed("gzip"));
        for (magic, name) in WRAPPER_MAGIC {
            assert_eq!(
                refuse_compressed_prefix(magic),
                Err(BundleError::Compressed(name))
            );
        }
        assert!(refuse_compressed_prefix(b"mani").is_ok());
        assert!(refuse_compressed_prefix(b"").is_ok());
    }

    #[test]
    fn entry_and_byte_budgets_are_enforced() {
        let bytes = build(&valid_bundle_parts());
        let few = BundleLimits {
            max_entries: 2,
            ..limits()
        };
        let err = index_bundle(bytes.as_slice(), &few).unwrap_err();
        assert!(matches!(err, BundleError::LimitExceeded(_)), "{err}");

        let small = BundleLimits {
            max_total_bytes: 1024,
            ..limits()
        };
        let err = index_bundle(bytes.as_slice(), &small).unwrap_err();
        assert!(
            matches!(err, BundleError::LimitExceeded(ref m) if m.contains("1024 bytes")),
            "{err}"
        );

        let tiny_manifest = BundleLimits {
            max_manifest_bytes: 16,
            ..limits()
        };
        let err = index_bundle(bytes.as_slice(), &tiny_manifest).unwrap_err();
        assert!(
            matches!(err, BundleError::LimitExceeded(ref m) if m.contains("manifest")),
            "{err}"
        );
    }

    #[test]
    fn truncated_and_non_utf8_archives_are_refused() {
        let bytes = build(&valid_bundle_parts());
        let err = index_bundle(&bytes[..700], &limits()).unwrap_err();
        assert!(matches!(err, BundleError::InvalidArchive(_)), "{err}");

        let mut b = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_gnu();
        h.as_gnu_mut().unwrap().name[..3].copy_from_slice(b"a\xffb");
        h.set_size(0);
        h.set_cksum();
        b.append(&h, &b""[..]).unwrap();
        let err = index_bundle(b.into_inner().unwrap().as_slice(), &limits()).unwrap_err();
        assert!(err.to_string().contains("not UTF-8"), "{err}");
    }

    #[test]
    fn cross_check_finds_missing_extra_and_resized_entries() {
        let m = sample_manifest();
        let mut parts = valid_bundle_parts();
        // Drop blob B, resize blob A, smuggle an unreferenced blob.
        parts.retain(|(p, _)| !p.contains(SHA_B));
        let a = parts.iter_mut().find(|(p, _)| p.contains(SHA_A)).unwrap();
        a.1.push(b'!');
        let stray = "c".repeat(64);
        parts.push((format!("blobs/cc/{stray}.jar"), b"x".to_vec()));
        let index = index_bundle(build(&parts).as_slice(), &limits()).unwrap();
        let problems = cross_check(&index, &m, 1);
        assert!(
            problems.iter().any(|p| p.contains("missing")),
            "{problems:?}"
        );
        assert!(
            problems.iter().any(|p| p.contains("manifest declares 10")),
            "{problems:?}"
        );
        assert!(
            problems.iter().any(|p| p.contains("not referenced")),
            "{problems:?}"
        );
        assert!(inspect_bundle(build(&parts).as_slice(), &limits()).is_err());

        // Volume 2 of the set expects none of volume 1's files.
        let full = index_bundle(build(&valid_bundle_parts()).as_slice(), &limits()).unwrap();
        assert_eq!(cross_check(&full, &m, 2).len(), 4);
    }

    #[test]
    fn cross_check_flags_shared_blob_size_conflicts_and_extra_documents() {
        let mut m = sample_manifest();
        let mut twin = m.items[0].clone();
        twin.logical_path = "com/acme/b/1.0/b-copy.jar".into();
        twin.size_bytes += 1;
        m.items.push(twin);
        m.repositories[0].oci_path = Some("repos/libs/oci.json".into());
        m.scan_evidence
            .push(crate::services::bundle::manifest::ScanEvidenceEntry {
                artifact_sha256: SHA_A.into(),
                scanner: "trivy".into(),
                scanner_version: None,
                vulnerability_db_version: None,
                scanned_at: chrono::Utc::now(),
                findings_count: 0,
                critical_count: 0,
                high_count: 0,
                medium_count: 0,
                low_count: 0,
                evidence_path: Some(crate::services::bundle::layout::evidence_path(SHA_A)),
            });
        m.signing = Some(crate::services::bundle::manifest::SigningInfo {
            signed_at: chrono::Utc::now(),
            signer_key_id: "k".into(),
            signer_fingerprint: "f".into(),
            algorithm: "a".into(),
            key_status_list_path: Some("signing/key-status.json".into()),
        });
        let index = index_bundle(build(&valid_bundle_parts()).as_slice(), &limits()).unwrap();
        let problems = cross_check(&index, &m, 1);
        for needle in [
            "different sizes",
            "repos/libs/oci.json: named by the manifest but missing",
            "evidence/aa/",
            "signing/key-status.json",
        ] {
            assert!(
                problems.iter().any(|p| p.contains(needle)),
                "{needle}: {problems:?}"
            );
        }
    }

    #[test]
    fn inspect_reports_manifest_problems() {
        let mut parts = valid_bundle_parts();
        let mut m = sample_manifest();
        m.items[0].repository_key = "nope".into();
        parts[0].1 = encode_manifest(&m).unwrap();
        let err = inspect_bundle(build(&parts).as_slice(), &limits()).unwrap_err();
        assert!(err.to_string().contains("not declared"), "{err}");

        parts[0].1 = br#"{"format":"akbundle","schema_version":2}"#.to_vec();
        let err = inspect_bundle(build(&parts).as_slice(), &limits()).unwrap_err();
        assert!(
            matches!(err, BundleError::UnsupportedVersion { found: 2, .. }),
            "{err}"
        );
    }
}
