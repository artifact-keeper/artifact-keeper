//! Arch Linux pacman format handler (#3343).
//!
//! Pure protocol logic for hosted pacman repositories: reading `.PKGINFO` and
//! the file list out of a `.pkg.tar.*`, validating package coordinates, and
//! rendering the per-package `desc`/`files` entries and the `{repo}.db` /
//! `{repo}.files` tarballs that `pacman -Sy` downloads. The HTTP side lives in
//! `api/handlers/pacman.rs`.
//!
//! The layout follows what `repo-add` (pacman 7) writes, so a database served
//! here is byte-for-byte the shape pacman reads from an official mirror:
//!
//! ```text
//! {pkgname}-{pkgver}/          directory entry
//! {pkgname}-{pkgver}/desc      %FILENAME%, %NAME%, %VERSION%, ... sections
//! {pkgname}-{pkgver}/files     %FILES% (only in the .files database)
//! ```

use std::io::Read;

use async_trait::async_trait;
use base64::Engine as _;
use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::error::{AppError, Result};
use crate::formats::FormatHandler;
use crate::models::repository::RepositoryFormat;

/// Package file extensions accepted for upload, longest first so the bare
/// `.pkg.tar` never shadows a compressed variant. These are the `PKGEXT`
/// values `makepkg` supports whose compression the backend can decode.
pub const PACKAGE_EXTENSIONS: &[&str] = &[
    ".pkg.tar.zst",
    ".pkg.tar.xz",
    ".pkg.tar.gz",
    ".pkg.tar.bz2",
    ".pkg.tar",
];

/// Suffix of a detached OpenPGP signature (`{file}.sig`).
pub const SIGNATURE_SUFFIX: &str = ".sig";

/// Largest `.PKGINFO` accepted. Real ones are a few hundred bytes; the cap
/// only keeps a crafted package from making the parser buffer a huge entry.
const PKGINFO_MAX_BYTES: u64 = 1024 * 1024;

/// Largest detached signature accepted on upload. An OpenPGP signature packet
/// for an RSA-4096 key is ~550 bytes armored-out; 16 KiB leaves room for any
/// sane key type plus armor without accepting arbitrary blobs.
pub const SIGNATURE_MAX_BYTES: usize = 16 * 1024;

/// Entries walked while looking for `.PKGINFO`. makepkg writes the package
/// metadata members (`.BUILDINFO`, `.MTREE`, `.PKGINFO`, `.INSTALL`, ...)
/// ahead of the payload, so a real package always reaches it within a few
/// entries; an archive that does not is refused before any payload is walked.
pub const PKGINFO_MAX_ENTRIES: u64 = 32;

/// Default decoded-byte budget for the file-list walk that continues once
/// `.PKGINFO` has been read. Listing a package's files means inflating all of
/// it (repo-add runs `bsdtar -tf` for the same reason), so the general ingest
/// budget (128 MiB) would refuse ordinary large packages. The walk streams and
/// keeps only entry names, so this bounds CPU, not memory; a package past it
/// is still published, just without a `%FILES%` entry. Override with
/// [`FILE_LIST_MAX_DECOMPRESSED_BYTES_ENV`].
pub const DEFAULT_FILE_LIST_MAX_DECOMPRESSED_BYTES: u64 = 4 * 1024 * 1024 * 1024;

/// Environment variable overriding [`DEFAULT_FILE_LIST_MAX_DECOMPRESSED_BYTES`].
pub const FILE_LIST_MAX_DECOMPRESSED_BYTES_ENV: &str = "PACMAN_FILE_LIST_MAX_DECOMPRESSED_BYTES";

/// Effective file-list budget, honouring [`FILE_LIST_MAX_DECOMPRESSED_BYTES_ENV`].
pub fn file_list_max_decompressed_bytes() -> u64 {
    crate::util::bounded_archive::positive_env_or(
        FILE_LIST_MAX_DECOMPRESSED_BYTES_ENV,
        DEFAULT_FILE_LIST_MAX_DECOMPRESSED_BYTES,
    )
}

/// Entry-count cap for the file-list walk (texlive-class packages carry tens
/// of thousands of entries).
pub const FILE_LIST_MAX_ENTRIES: u64 = 500_000;

/// Cap on the summed length of the collected entry names.
const FILE_LIST_MAX_NAME_BYTES: usize = 64 * 1024 * 1024;

/// Parsed `.PKGINFO` of a pacman package.
///
/// `pkgver` is the full `[epoch:]pkgver-pkgrel` string, exactly as makepkg
/// writes it and as `%VERSION%` carries it.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PkgInfo {
    pub pkgname: String,
    pub pkgbase: Option<String>,
    pub pkgver: String,
    pub pkgdesc: Option<String>,
    pub url: Option<String>,
    pub builddate: Option<i64>,
    pub packager: Option<String>,
    pub size: Option<i64>,
    pub arch: String,
    pub license: Vec<String>,
    pub replaces: Vec<String>,
    pub groups: Vec<String>,
    pub conflicts: Vec<String>,
    pub provides: Vec<String>,
    pub depends: Vec<String>,
    pub optdepends: Vec<String>,
    pub makedepends: Vec<String>,
    pub checkdepends: Vec<String>,
}

/// Whether `name` is a valid pacman package name (makepkg's lint: alphanumerics
/// and `@._+-`, not starting with a hyphen or dot).
pub fn is_valid_pkgname(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && !name.starts_with(['-', '.'])
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '@' | '.' | '_' | '+' | '-'))
}

/// Whether `version` is a valid full `[epoch:]pkgver-pkgrel` string.
pub fn is_valid_full_version(version: &str) -> bool {
    let Some((ver, rel)) = version.rsplit_once('-') else {
        return false;
    };
    let rel_ok = !rel.is_empty() && rel.chars().all(|c| c.is_ascii_alphanumeric() || c == '.');
    let ver = match ver.split_once(':') {
        Some((epoch, rest)) if !epoch.is_empty() && epoch.chars().all(|c| c.is_ascii_digit()) => {
            rest
        }
        Some(_) => return false,
        None => ver,
    };
    rel_ok
        && !ver.is_empty()
        && ver
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '~'))
}

/// Whether `arch` is a valid pacman architecture (`x86_64`, `aarch64`, `any`).
pub fn is_valid_arch(arch: &str) -> bool {
    !arch.is_empty()
        && arch.len() <= 64
        && arch.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Parse `.PKGINFO` (`key = value` lines, `#` comments, repeated keys for
/// list fields). Unknown keys (`xdata`, `backup`, ...) are ignored. Values are
/// single lines by construction, so nothing parsed here can break the
/// line-oriented `desc` format it is rendered back into; empty values and
/// values carrying control characters are dropped for the same reason.
pub fn parse_pkginfo(text: &str) -> Result<PkgInfo> {
    let mut info = PkgInfo::default();
    for line in text.lines() {
        let line = line.trim_end_matches('\r');
        if line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once(" = ") else {
            continue;
        };
        let value = value.trim();
        if value.is_empty() || value.chars().any(char::is_control) {
            continue;
        }
        let owned = value.to_string();
        match key.trim() {
            "pkgname" => info.pkgname = owned,
            "pkgbase" => info.pkgbase = Some(owned),
            "pkgver" => info.pkgver = owned,
            "pkgdesc" => info.pkgdesc = Some(owned),
            "url" => info.url = Some(owned),
            "builddate" => info.builddate = value.parse().ok(),
            "packager" => info.packager = Some(owned),
            "size" => info.size = value.parse().ok(),
            "arch" => info.arch = owned,
            "license" => info.license.push(owned),
            "replaces" => info.replaces.push(owned),
            "group" => info.groups.push(owned),
            "conflict" => info.conflicts.push(owned),
            "provides" => info.provides.push(owned),
            "depend" => info.depends.push(owned),
            "optdepend" => info.optdepends.push(owned),
            "makedepend" => info.makedepends.push(owned),
            "checkdepend" => info.checkdepends.push(owned),
            _ => {}
        }
    }

    if !is_valid_pkgname(&info.pkgname) {
        return Err(AppError::Validation(format!(
            ".PKGINFO has a missing or invalid pkgname '{}'",
            info.pkgname
        )));
    }
    if !is_valid_full_version(&info.pkgver) {
        return Err(AppError::Validation(format!(
            ".PKGINFO has a missing or invalid pkgver '{}' (expected [epoch:]pkgver-pkgrel)",
            info.pkgver
        )));
    }
    if !is_valid_arch(&info.arch) {
        return Err(AppError::Validation(format!(
            ".PKGINFO has a missing or invalid arch '{}'",
            info.arch
        )));
    }
    Ok(info)
}

/// Split a package filename into its stem and package extension.
pub fn split_package_filename(filename: &str) -> Option<(&str, &'static str)> {
    PACKAGE_EXTENSIONS.iter().find_map(|ext| {
        filename
            .strip_suffix(ext)
            .filter(|stem| !stem.is_empty())
            .map(|stem| (stem, *ext))
    })
}

/// The filename makepkg gives a package: `{pkgname}-{pkgver}-{arch}{ext}`.
pub fn canonical_filename(info: &PkgInfo, ext: &str) -> String {
    format!("{}-{}-{}{}", info.pkgname, info.pkgver, info.arch, ext)
}

/// The directory a package's entries live under inside the databases.
pub fn entry_dir(info: &PkgInfo) -> String {
    format!("{}-{}", info.pkgname, info.pkgver)
}

/// A file served under `/{repo_key}/{arch}/`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepoFile<'a> {
    /// `{name}.db` / `{name}.files` (or their `.tar.gz` targets), with
    /// `signature` set for the detached `.sig`.
    Database { files: bool, signature: bool },
    /// A package file, or its detached signature.
    Package { filename: &'a str, signature: bool },
}

/// Classify a requested filename. `None` for anything that is neither a
/// database nor a package (the handler answers 404).
pub fn classify_repo_file(filename: &str) -> Option<RepoFile<'_>> {
    let (base, signature) = match filename.strip_suffix(SIGNATURE_SUFFIX) {
        Some(base) => (base, true),
        None => (filename, false),
    };
    if split_package_filename(base).is_some() {
        return Some(RepoFile::Package {
            filename: base,
            signature,
        });
    }
    [
        (".db", false),
        (".db.tar.gz", false),
        (".files", true),
        (".files.tar.gz", true),
    ]
    .iter()
    .find(|(suffix, _)| base.strip_suffix(suffix).is_some_and(|s| !s.is_empty()))
    .map(|(_, files)| RepoFile::Database {
        files: *files,
        signature,
    })
}

// ---------------------------------------------------------------------------
// Package inspection
// ---------------------------------------------------------------------------

/// Pick a decompressor from the stream's magic bytes. pacman packages are
/// tarballs under whatever `PKGEXT` compression the packager chose, and the
/// magic (not the filename) is what decides how they decode. The multi-member
/// decoders match libarchive, which reads concatenated gzip/xz/bzip2 members.
fn package_decoder<'a>(data: &'a [u8]) -> Result<Box<dyn Read + 'a>> {
    let decoder: Box<dyn Read + 'a> = if data.starts_with(&[0x28, 0xB5, 0x2F, 0xFD]) {
        Box::new(
            zstd::Decoder::new(data)
                .map_err(|e| AppError::Validation(format!("Invalid zstd stream: {e}")))?,
        )
    } else if data.starts_with(&[0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00]) {
        Box::new(xz2::read::XzDecoder::new_multi_decoder(data))
    } else if data.starts_with(&[0x1F, 0x8B]) {
        Box::new(flate2::read::MultiGzDecoder::new(data))
    } else if data.starts_with(b"BZh") {
        Box::new(bzip2::read::MultiBzDecoder::new(data))
    } else {
        Box::new(data)
    };
    Ok(decoder)
}

/// What an uploaded package contains.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageContents {
    pub info: PkgInfo,
    /// Sorted, de-duplicated file list for the `.files` database (directories
    /// carry a trailing `/`, as `bsdtar -tf` prints them). `None` when the
    /// walk ran out of its file-list budgets: the package is still indexed in
    /// `.db`, it just has no `%FILES%` section.
    pub files: Option<Vec<String>>,
}

const BUDGET_EXHAUSTED: &str = "pacman package decompression budget exceeded";

/// A decoded-byte budget whose limit can be raised mid-stream: the walk runs
/// under the tight ingest budget until `.PKGINFO` is parsed, then continues
/// under the file-list budget. Records whether the budget (rather than a
/// corrupt stream) is what stopped the walk.
struct PhasedBudget<R> {
    inner: R,
    used: u64,
    limit: std::rc::Rc<std::cell::Cell<u64>>,
    exhausted: std::rc::Rc<std::cell::Cell<bool>>,
}

impl<R: Read> Read for PhasedBudget<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let remaining = self.limit.get().saturating_sub(self.used);
        if remaining == 0 {
            // At the limit: only a clean EOF is not a breach.
            let mut probe = [0u8; 1];
            return match self.inner.read(&mut probe)? {
                0 => Ok(0),
                _ => {
                    self.exhausted.set(true);
                    Err(std::io::Error::other(BUDGET_EXHAUSTED))
                }
            };
        }
        let cap = buf
            .len()
            .min(usize::try_from(remaining).unwrap_or(usize::MAX));
        let n = self.inner.read(&mut buf[..cap])?;
        self.used += n as u64;
        Ok(n)
    }
}

/// Budgets for [`inspect_package_limited`].
#[derive(Debug, Clone, Copy)]
pub(crate) struct InspectLimits {
    /// Decoded bytes allowed until `.PKGINFO` is parsed.
    pub pkginfo_bytes: u64,
    /// Entries allowed until `.PKGINFO` is found.
    pub pkginfo_entries: u64,
    /// Decoded bytes allowed for the whole walk once `.PKGINFO` is parsed.
    /// `None` stops the walk at `.PKGINFO` (no file list).
    pub file_list_bytes: Option<u64>,
    pub file_list_entries: u64,
    pub file_list_name_bytes: usize,
}

impl InspectLimits {
    fn upload() -> Self {
        Self {
            pkginfo_bytes: crate::util::bounded_archive::max_ingest_decompressed_bytes(),
            pkginfo_entries: PKGINFO_MAX_ENTRIES,
            file_list_bytes: Some(file_list_max_decompressed_bytes()),
            file_list_entries: FILE_LIST_MAX_ENTRIES,
            file_list_name_bytes: FILE_LIST_MAX_NAME_BYTES,
        }
    }
}

/// Read `.PKGINFO` and the file list out of an uploaded package in one
/// streaming walk, in two phases: `.PKGINFO` must turn up within the shared
/// ingest budget and [`PKGINFO_MAX_ENTRIES`], and only then does the file-list
/// walk continue under [`file_list_max_decompressed_bytes`].
pub fn inspect_package(data: &[u8]) -> Result<PackageContents> {
    inspect_package_limited(data, InspectLimits::upload())
}

/// Read only `.PKGINFO` (phase one of [`inspect_package`]).
pub fn read_pkginfo(data: &[u8]) -> Result<PkgInfo> {
    let limits = InspectLimits {
        file_list_bytes: None,
        ..InspectLimits::upload()
    };
    inspect_package_limited(data, limits).map(|c| c.info)
}

fn invalid_package(e: impl std::fmt::Display) -> AppError {
    AppError::Validation(format!("Invalid pacman package: {e}"))
}

/// `_limited` seam for [`inspect_package`] so tests can drive tiny budgets.
pub(crate) fn inspect_package_limited(
    data: &[u8],
    limits: InspectLimits,
) -> Result<PackageContents> {
    use std::{cell::Cell, rc::Rc};

    let limit = Rc::new(Cell::new(limits.pkginfo_bytes));
    let exhausted = Rc::new(Cell::new(false));
    let reader = PhasedBudget {
        inner: package_decoder(data)?,
        used: 0,
        limit: limit.clone(),
        exhausted: exhausted.clone(),
    };
    let mut archive = tar::Archive::new(reader);
    let entries = archive.entries().map_err(invalid_package)?;

    let mut info: Option<PkgInfo> = None;
    let mut files = Vec::new();
    let mut name_bytes = 0usize;
    let mut complete = true;
    let mut seen = 0u64;

    for entry in entries {
        seen += 1;
        if info.is_none() && seen > limits.pkginfo_entries {
            return Err(invalid_package(format!(
                ".PKGINFO not found within the first {} entries",
                limits.pkginfo_entries
            )));
        }
        if seen > limits.file_list_entries {
            complete = false;
            break;
        }
        let mut entry = match entry {
            Ok(entry) => entry,
            // Past `.PKGINFO`, running out of the file-list budget only costs
            // the file list. Anything else (a truncated or corrupt stream) is
            // a broken package, and so is every failure before `.PKGINFO`.
            Err(_) if info.is_some() && exhausted.get() => {
                complete = false;
                break;
            }
            Err(e) if exhausted.get() => {
                return Err(AppError::Validation(format!(
                    "Archive expands beyond the decompression budget before .PKGINFO: {e}"
                )))
            }
            Err(e) => return Err(invalid_package(e)),
        };
        let path = match entry.path() {
            Ok(p) => p.to_string_lossy().trim_start_matches("./").to_string(),
            Err(e) => return Err(invalid_package(e)),
        };
        if path == ".PKGINFO" && info.is_none() {
            let raw = crate::util::bounded_archive::read_capped(
                &mut entry,
                PKGINFO_MAX_BYTES,
                ".PKGINFO",
            )?;
            info = Some(parse_pkginfo(&String::from_utf8_lossy(&raw))?);
            match limits.file_list_bytes {
                Some(budget) => limit.set(budget.max(limits.pkginfo_bytes)),
                None => break,
            }
            continue;
        }
        // repo-add lists files with `bsdtar --exclude='^.*'`: the package
        // metadata members (.BUILDINFO, .MTREE, .INSTALL, ...) are not files.
        // Names carrying control characters cannot be represented in the
        // line-oriented `files` entry (or, for NUL, in JSONB) and are skipped.
        if path.is_empty() || path.starts_with('.') || path.chars().any(char::is_control) {
            continue;
        }
        let mut name = path;
        if entry.header().entry_type().is_dir() && !name.ends_with('/') {
            name.push('/');
        }
        name_bytes += name.len();
        if name_bytes > limits.file_list_name_bytes {
            complete = false;
            break;
        }
        files.push(name);
    }

    let info = info.ok_or_else(|| {
        AppError::Validation("Not a pacman package: .PKGINFO not found".to_string())
    })?;
    files.sort();
    files.dedup();
    Ok(PackageContents {
        info,
        files: (complete && limits.file_list_bytes.is_some()).then_some(files),
    })
}

// ---------------------------------------------------------------------------
// Signatures
// ---------------------------------------------------------------------------

/// Turn an uploaded detached signature (binary, as `makepkg --sign` and
/// `gpg --detach-sign` write it, or ASCII-armored) into the binary packet form
/// pacman expects in a `.sig` file and in `%PGPSIG%`. Refuses anything that
/// does not parse as an OpenPGP signature.
pub fn normalize_signature(raw: &[u8]) -> Result<Vec<u8>> {
    use pgp::composed::{Deserializable, StandaloneSignature};
    use pgp::ser::Serialize as _;

    if raw.is_empty() || raw.len() > SIGNATURE_MAX_BYTES {
        return Err(AppError::Validation(format!(
            "A detached signature must be between 1 and {SIGNATURE_MAX_BYTES} bytes"
        )));
    }
    let invalid = |e: pgp::errors::Error| {
        AppError::Validation(format!("Not a detached OpenPGP signature: {e}"))
    };
    let signature = match std::str::from_utf8(raw) {
        Ok(text)
            if text
                .trim_start()
                .starts_with("-----BEGIN PGP SIGNATURE-----") =>
        {
            StandaloneSignature::from_string(text).map_err(invalid)?.0
        }
        _ => StandaloneSignature::from_bytes(raw).map_err(invalid)?,
    };
    signature
        .to_bytes()
        .map_err(|e| AppError::Internal(format!("Failed to encode OpenPGP signature: {e}")))
}

/// Base64 form of a binary signature, as `%PGPSIG%` carries it.
pub fn signature_base64(binary: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(binary)
}

// ---------------------------------------------------------------------------
// Database rendering
// ---------------------------------------------------------------------------

/// One package as it appears in the databases.
#[derive(Debug, Clone)]
pub struct DbEntry<'a> {
    pub filename: &'a str,
    pub csize: i64,
    pub sha256: &'a str,
    /// Base64 binary signature for `%PGPSIG%`, when one was uploaded.
    pub pgpsig: Option<&'a str>,
    pub info: &'a PkgInfo,
    pub files: Option<&'a [String]>,
    /// Entry mtime inside the database tarball (the upload time). Fixed per
    /// package so the same package set always renders the same bytes: the
    /// detached `.db.sig` is fetched in a separate request and must verify
    /// against the `.db` fetched just before it.
    pub mtime: u64,
}

fn push_section<'v>(out: &mut String, key: &str, values: impl IntoIterator<Item = &'v str>) {
    let mut values = values.into_iter().filter(|v| !v.is_empty()).peekable();
    if values.peek().is_none() {
        return;
    }
    out.push('%');
    out.push_str(key);
    out.push_str("%\n");
    for value in values {
        out.push_str(value);
        out.push('\n');
    }
    out.push('\n');
}

/// Render a package's `desc` entry in repo-add's section order.
pub fn render_desc(entry: &DbEntry<'_>) -> String {
    let info = entry.info;
    let csize = entry.csize.to_string();
    let isize = info.size.map(|s| s.to_string());
    let builddate = info.builddate.map(|d| d.to_string());
    let base = info.pkgbase.as_deref().unwrap_or(&info.pkgname);
    let mut out = String::new();
    push_section(&mut out, "FILENAME", [entry.filename]);
    push_section(&mut out, "NAME", [info.pkgname.as_str()]);
    push_section(&mut out, "BASE", [base]);
    push_section(&mut out, "VERSION", [info.pkgver.as_str()]);
    push_section(&mut out, "DESC", info.pkgdesc.as_deref());
    push_section(&mut out, "GROUPS", info.groups.iter().map(String::as_str));
    push_section(&mut out, "CSIZE", [csize.as_str()]);
    push_section(&mut out, "ISIZE", isize.as_deref());
    push_section(&mut out, "SHA256SUM", [entry.sha256]);
    push_section(&mut out, "PGPSIG", entry.pgpsig);
    push_section(&mut out, "URL", info.url.as_deref());
    push_section(&mut out, "LICENSE", info.license.iter().map(String::as_str));
    push_section(&mut out, "ARCH", [info.arch.as_str()]);
    push_section(&mut out, "BUILDDATE", builddate.as_deref());
    push_section(&mut out, "PACKAGER", info.packager.as_deref());
    for (key, values) in [
        ("REPLACES", &info.replaces),
        ("CONFLICTS", &info.conflicts),
        ("PROVIDES", &info.provides),
        ("DEPENDS", &info.depends),
        ("OPTDEPENDS", &info.optdepends),
        ("MAKEDEPENDS", &info.makedepends),
        ("CHECKDEPENDS", &info.checkdepends),
    ] {
        push_section(&mut out, key, values.iter().map(String::as_str));
    }
    out
}

/// Render a package's `files` entry (no trailing blank line, as repo-add
/// writes it).
pub fn render_files(files: &[String]) -> String {
    let mut out = String::from("%FILES%\n");
    for file in files {
        out.push_str(file);
        out.push('\n');
    }
    out
}

fn db_header(entry_type: tar::EntryType, mode: u32, size: u64, mtime: u64) -> tar::Header {
    let mut header = tar::Header::new_ustar();
    header.set_entry_type(entry_type);
    header.set_mode(mode);
    header.set_size(size);
    header.set_mtime(mtime);
    header.set_uid(0);
    header.set_gid(0);
    header
}

/// Build `{repo}.db` (or, with `with_files`, `{repo}.files`) as a gzip'd tar.
///
/// Deterministic for a given entry list: tar mtimes come from the entries and
/// the gzip header carries no timestamp, so the bytes a `.sig` covers are the
/// bytes the previous `.db` request returned.
pub fn build_database(entries: &[DbEntry<'_>], with_files: bool) -> std::io::Result<Vec<u8>> {
    use std::io::Write;

    let mut builder = tar::Builder::new(Vec::new());
    for entry in entries {
        let dir = entry_dir(entry.info);
        let mut header = db_header(tar::EntryType::Directory, 0o755, 0, entry.mtime);
        builder.append_data(&mut header, format!("{dir}/"), std::io::empty())?;

        let mut members = vec![("desc", render_desc(entry))];
        if with_files {
            members.push(("files", render_files(entry.files.unwrap_or_default())));
        }
        for (member, body) in members {
            let mut header = db_header(
                tar::EntryType::Regular,
                0o644,
                body.len() as u64,
                entry.mtime,
            );
            builder.append_data(&mut header, format!("{dir}/{member}"), body.as_bytes())?;
        }
    }
    let tar = builder.into_inner()?;

    let mut gz = flate2::GzBuilder::new()
        .mtime(0)
        .write(Vec::new(), flate2::Compression::default());
    gz.write_all(&tar)?;
    gz.finish()
}

// ---------------------------------------------------------------------------
// FormatHandler
// ---------------------------------------------------------------------------

/// Arch Linux pacman format handler.
pub struct PacmanHandler;

impl PacmanHandler {
    pub fn new() -> Self {
        Self
    }

    /// Split a stored artifact path (`{arch}/{filename}`) and validate both
    /// halves.
    pub fn parse_path(path: &str) -> Result<(&str, RepoFile<'_>)> {
        let path = path.trim_start_matches('/');
        let invalid = || AppError::Validation(format!("Invalid pacman path: {path}"));
        let (arch, filename) = path.split_once('/').ok_or_else(invalid)?;
        if !is_valid_arch(arch) || filename.contains('/') {
            return Err(invalid());
        }
        let file = classify_repo_file(filename).ok_or_else(invalid)?;
        Ok((arch, file))
    }
}

impl Default for PacmanHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl FormatHandler for PacmanHandler {
    fn format(&self) -> RepositoryFormat {
        RepositoryFormat::Pacman
    }

    async fn parse_metadata(&self, path: &str, content: &Bytes) -> Result<serde_json::Value> {
        let (arch, file) = Self::parse_path(path)?;
        let mut metadata = serde_json::json!({ "arch": arch });
        if let RepoFile::Package {
            filename,
            signature: false,
        } = file
        {
            metadata["filename"] = filename.into();
            if !content.is_empty() {
                metadata["pkginfo"] = serde_json::to_value(read_pkginfo(content)?)?;
            }
        }
        Ok(metadata)
    }

    async fn validate(&self, path: &str, _content: &Bytes) -> Result<()> {
        Self::parse_path(path).map(|_| ())
    }

    async fn generate_index(&self) -> Result<Option<Vec<(String, Bytes)>>> {
        // The databases are rendered on demand from the artifact rows.
        Ok(None)
    }
}

#[cfg(ak_test_shard = "services-2")]
#[cfg(test)]
mod tests {
    use super::*;

    const MARKER_PKG: &[u8] =
        include_bytes!("../../tests/fixtures/ak-marker-1.0-1-any.pkg.tar.zst");
    const MARKER_SIG: &[u8] =
        include_bytes!("../../tests/fixtures/ak-marker-1.0-1-any.pkg.tar.zst.sig");
    const MARKER_SIGNER: &str = include_str!("../../tests/fixtures/ak-marker-signer.asc");
    /// What `repo-add` (pacman 7.1) wrote for the fixture package.
    const REPO_ADD_DESC: &str = include_str!("../../tests/fixtures/ak-marker-1.0-1.repo-add.desc");
    const REPO_ADD_FILES: &str =
        include_str!("../../tests/fixtures/ak-marker-1.0-1.repo-add.files");
    const MARKER_SHA256: &str = "1622a01ee5ee8c18a70ef8e49d74e598d1304f40dc30e508bebc83afbcb2a314";

    const PKGINFO: &str = "pkgname = demo\npkgver = 2:1.2.3-4\narch = x86_64\n";

    /// A tar of `entries` (`(path, body)`; a path ending in `/` is a
    /// directory), uncompressed.
    fn tar_of(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for (path, body) in entries {
            let mut header = tar::Header::new_gnu();
            if path.ends_with('/') {
                header.set_entry_type(tar::EntryType::Directory);
                header.set_mode(0o755);
            } else {
                header.set_mode(0o644);
            }
            header.set_size(body.len() as u64);
            header.set_cksum();
            builder.append_data(&mut header, path, *body).unwrap();
        }
        builder.into_inner().unwrap()
    }

    fn demo_package_tar() -> Vec<u8> {
        tar_of(&[
            (".BUILDINFO", b"x"),
            (".PKGINFO", PKGINFO.as_bytes()),
            (".MTREE", b"x"),
            ("usr/", b""),
            ("usr/bin/", b""),
            ("usr/bin/demo", b"#!/bin/sh\n"),
        ])
    }

    #[test]
    fn inspects_a_real_makepkg_package() {
        let contents = inspect_package(MARKER_PKG).unwrap();
        let info = &contents.info;
        assert_eq!(info.pkgname, "ak-marker");
        assert_eq!(info.pkgbase.as_deref(), Some("ak-marker"));
        assert_eq!(info.pkgver, "1.0-1");
        assert_eq!(info.arch, "any");
        assert_eq!(info.size, Some(21));
        assert_eq!(info.depends, vec!["bash"]);
        assert_eq!(info.provides, vec!["ak-marker-virt=1.0"]);
        assert_eq!(info.license, vec!["MIT"]);
        assert_eq!(
            contents.files.unwrap(),
            vec![
                "usr/",
                "usr/share/",
                "usr/share/ak-marker/",
                "usr/share/ak-marker/marker.txt"
            ]
        );
    }

    /// The rendered `desc`/`files` must be what repo-add writes for the same
    /// package, byte for byte: pacman parses these line by line.
    #[test]
    fn renders_desc_and_files_exactly_like_repo_add() {
        let contents = inspect_package(MARKER_PKG).unwrap();
        let files = contents.files.clone().unwrap();
        let entry = DbEntry {
            filename: "ak-marker-1.0-1-any.pkg.tar.zst",
            csize: MARKER_PKG.len() as i64,
            sha256: MARKER_SHA256,
            pgpsig: None,
            info: &contents.info,
            files: Some(&files),
            mtime: 0,
        };
        assert_eq!(render_desc(&entry), REPO_ADD_DESC);
        assert_eq!(render_files(&files), REPO_ADD_FILES);
    }

    #[test]
    fn decodes_every_supported_compression() {
        use std::io::Write;
        let tar = demo_package_tar();
        // Two concatenated gzip members, as libarchive (and so pacman) reads them.
        let gz = {
            let (a, b) = tar.split_at(700);
            let mut out = Vec::new();
            for part in [a, b] {
                let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
                e.write_all(part).unwrap();
                out.extend(e.finish().unwrap());
            }
            out
        };
        let xz = {
            let mut e = xz2::write::XzEncoder::new(Vec::new(), 1);
            e.write_all(&tar).unwrap();
            e.finish().unwrap()
        };
        let bz = {
            let mut e = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::fast());
            e.write_all(&tar).unwrap();
            e.finish().unwrap()
        };
        let zst = zstd::encode_all(&tar[..], 1).unwrap();
        for (label, data) in [
            ("tar", tar.clone()),
            ("gz", gz),
            ("xz", xz),
            ("bz2", bz),
            ("zst", zst),
        ] {
            let contents = inspect_package(&data).unwrap_or_else(|e| panic!("{label}: {e}"));
            assert_eq!(contents.info.pkgname, "demo", "{label}");
            assert_eq!(contents.info.pkgver, "2:1.2.3-4", "{label}");
            assert_eq!(
                contents.files.unwrap(),
                vec!["usr/", "usr/bin/", "usr/bin/demo"],
                "{label}"
            );
        }
    }

    fn limits(pkginfo_bytes: u64, file_list_bytes: Option<u64>, entries: u64) -> InspectLimits {
        InspectLimits {
            pkginfo_bytes,
            pkginfo_entries: PKGINFO_MAX_ENTRIES,
            file_list_bytes,
            file_list_entries: entries,
            file_list_name_bytes: 1 << 20,
        }
    }

    #[test]
    fn file_list_over_budget_keeps_the_package_indexable() {
        // Entry cap.
        let contents =
            inspect_package_limited(&demo_package_tar(), limits(u64::MAX, Some(u64::MAX), 3))
                .unwrap();
        assert_eq!(contents.info.pkgname, "demo");
        assert_eq!(contents.files, None);

        // Byte budget running out after `.PKGINFO`.
        let tar = tar_of(&[(".PKGINFO", PKGINFO.as_bytes()), ("usr/big", &[0u8; 8192])]);
        let contents = inspect_package_limited(&tar, limits(2048, Some(4096), 100)).unwrap();
        assert_eq!(contents.info.pkgname, "demo");
        assert_eq!(contents.files, None);
        // ...while a larger file-list budget lists it.
        let contents = inspect_package_limited(&tar, limits(2048, Some(1 << 20), 100)).unwrap();
        assert_eq!(contents.files.unwrap(), vec!["usr/big"]);
    }

    /// The upload walk must stay on the shared ingest budget until `.PKGINFO`
    /// is parsed: a bomb in front of it is refused at that budget, not at the
    /// much larger file-list one.
    #[test]
    fn rejects_a_bomb_before_pkginfo() {
        let tar = tar_of(&[("usr/big", &[0u8; 4096]), (".PKGINFO", PKGINFO.as_bytes())]);
        let err = inspect_package_limited(&tar, limits(1024, Some(u64::MAX), 100))
            .unwrap_err()
            .to_string();
        assert!(err.contains("decompression budget"), "{err}");
    }

    #[test]
    fn pkginfo_must_come_early() {
        let mut entries: Vec<(String, &[u8])> = (0..PKGINFO_MAX_ENTRIES)
            .map(|i| (format!("usr/f{i}"), b"x".as_slice()))
            .collect();
        entries.push((".PKGINFO".to_string(), PKGINFO.as_bytes()));
        let refs: Vec<(&str, &[u8])> = entries.iter().map(|(p, b)| (p.as_str(), *b)).collect();
        let err = inspect_package(&tar_of(&refs)).unwrap_err().to_string();
        assert!(err.contains("within the first"), "{err}");
    }

    /// A stream that breaks after `.PKGINFO` is a broken package, not an
    /// over-budget one: it must be refused rather than published.
    #[test]
    fn truncated_package_is_refused() {
        let tar = demo_package_tar();
        let cut = &tar[..tar.len() - 1024 - 700];
        assert!(inspect_package(cut).is_err());
        let zst = zstd::encode_all(&tar[..], 1).unwrap();
        assert!(inspect_package(&zst[..zst.len() - 8]).is_err());
    }

    #[test]
    fn skips_names_with_control_characters() {
        let tar = tar_of(&[
            (".PKGINFO", PKGINFO.as_bytes()),
            ("usr/ok", b"x"),
            ("usr/bad\u{1}name", b"x"),
        ]);
        assert_eq!(
            inspect_package(&tar).unwrap().files.unwrap(),
            vec!["usr/ok"]
        );
    }

    #[test]
    fn read_pkginfo_stops_at_pkginfo() {
        let tar = tar_of(&[(".PKGINFO", PKGINFO.as_bytes()), ("usr/big", &[0u8; 8192])]);
        assert_eq!(read_pkginfo(&tar).unwrap().pkgname, "demo");
        assert_eq!(read_pkginfo(MARKER_PKG).unwrap().pkgname, "ak-marker");
        assert!(read_pkginfo(b"nope").is_err());
        assert_eq!(
            file_list_max_decompressed_bytes(),
            DEFAULT_FILE_LIST_MAX_DECOMPRESSED_BYTES
        );
    }

    #[test]
    fn rejects_archives_without_pkginfo() {
        let tar = tar_of(&[("usr/bin/demo", b"x")]);
        let err = inspect_package(&tar).unwrap_err().to_string();
        assert!(err.contains(".PKGINFO not found"), "{err}");
        assert!(inspect_package(b"definitely not a package").is_err());
    }

    #[test]
    fn parses_pkginfo_lists_and_skips_unsafe_values() {
        let info = parse_pkginfo(
            "# comment\r\npkgname = demo\npkgver = 1.0-1\narch = x86_64\nxdata = pkgtype=pkg\n\
             depend = a\ndepend = b>=2\noptdepend = c: extra\ngroup = g\nconflict = d\n\
             replaces = e\nmakedepend = m\ncheckdepend = t\nlicense = MIT\nlicense = GPL\n\
             pkgdesc = has\u{7}bell\nurl = \nbuilddate = 1700000000\nsize = notanumber\n\
             packager = Someone <s@example.invalid>\n",
        )
        .unwrap();
        assert_eq!(info.depends, vec!["a", "b>=2"]);
        assert_eq!(info.optdepends, vec!["c: extra"]);
        assert_eq!(info.groups, vec!["g"]);
        assert_eq!(info.conflicts, vec!["d"]);
        assert_eq!(info.replaces, vec!["e"]);
        assert_eq!(info.makedepends, vec!["m"]);
        assert_eq!(info.checkdepends, vec!["t"]);
        assert_eq!(info.license, vec!["MIT", "GPL"]);
        assert_eq!(info.pkgdesc, None, "control characters are dropped");
        assert_eq!(info.url, None, "empty values are dropped");
        assert_eq!(info.builddate, Some(1_700_000_000));
        assert_eq!(info.size, None);
    }

    #[test]
    fn pkginfo_requires_valid_coordinates() {
        for bad in [
            "pkgver = 1.0-1\narch = x86_64\n",
            "pkgname = -bad\npkgver = 1.0-1\narch = x86_64\n",
            "pkgname = ok\npkgver = 1.0\narch = x86_64\n",
            "pkgname = ok\npkgver = 1.0-1\narch = x86/64\n",
            "pkgname = ok\npkgver = 1.0-1\n",
        ] {
            assert!(parse_pkginfo(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn validates_versions() {
        for good in ["1.0-1", "2:1.0-1", "1.0.r12.gabc+x~rc1-2.1"] {
            assert!(is_valid_full_version(good), "{good}");
        }
        for bad in [
            "", "1.0", "1.0-", "-1", "x:1.0-1", ":1.0-1", "1:2:3-1", "1/0-1", "1.0-1 ",
        ] {
            assert!(!is_valid_full_version(bad), "{bad}");
        }
        assert!(is_valid_pkgname("lib32-gcc-libs@x.y_z+"));
        assert!(!is_valid_pkgname(".hidden"));
        assert!(!is_valid_pkgname("a b"));
        assert!(is_valid_arch("x86_64"));
        assert!(!is_valid_arch(""));
    }

    #[test]
    fn classifies_repository_files() {
        use RepoFile::*;
        let pkg = "foo-1:2.0-1-x86_64.pkg.tar.zst";
        assert_eq!(
            classify_repo_file(pkg),
            Some(Package {
                filename: pkg,
                signature: false
            })
        );
        assert_eq!(
            classify_repo_file("foo-1:2.0-1-x86_64.pkg.tar.zst.sig"),
            Some(Package {
                filename: pkg,
                signature: true
            })
        );
        for (name, files, signature) in [
            ("core.db", false, false),
            ("core.db.tar.gz", false, false),
            ("core.db.sig", false, true),
            ("core.files", true, false),
            ("core.files.tar.gz", true, false),
            ("core.files.sig", true, true),
        ] {
            assert_eq!(
                classify_repo_file(name),
                Some(Database { files, signature }),
                "{name}"
            );
        }
        for none in [
            ".db",
            "README",
            "x.pkg.tar.lz4",
            ".pkg.tar.zst",
            "core.db.tar.zst",
        ] {
            assert_eq!(classify_repo_file(none), None, "{none}");
        }
    }

    #[test]
    fn canonical_filenames() {
        let info = parse_pkginfo(PKGINFO).unwrap();
        assert_eq!(
            canonical_filename(&info, ".pkg.tar.zst"),
            "demo-2:1.2.3-4-x86_64.pkg.tar.zst"
        );
        assert_eq!(entry_dir(&info), "demo-2:1.2.3-4");
        assert_eq!(
            split_package_filename("demo-1-1-any.pkg.tar"),
            Some(("demo-1-1-any", ".pkg.tar"))
        );
    }

    #[test]
    fn normalizes_binary_and_armored_signatures() {
        use pgp::composed::StandaloneSignature;
        let binary = normalize_signature(MARKER_SIG).unwrap();
        assert_eq!(binary, MARKER_SIG, "binary input is already canonical");

        let armored = {
            use pgp::composed::Deserializable;
            StandaloneSignature::from_bytes(MARKER_SIG)
                .unwrap()
                .to_armored_string(pgp::ArmorOptions::default())
                .unwrap()
        };
        assert_eq!(normalize_signature(armored.as_bytes()).unwrap(), MARKER_SIG);

        // And the normalized bytes still verify against the signer.
        let armored_again = {
            use pgp::composed::Deserializable;
            StandaloneSignature::from_bytes(&binary[..])
                .unwrap()
                .to_armored_string(pgp::ArmorOptions::default())
                .unwrap()
        };
        crate::services::signing_service::verify_detached(
            MARKER_SIGNER,
            MARKER_PKG,
            &armored_again,
        )
        .expect("fixture signature verifies");

        assert!(normalize_signature(b"").is_err());
        assert!(normalize_signature(b"not a signature").is_err());
        assert!(normalize_signature(&vec![0u8; SIGNATURE_MAX_BYTES + 1]).is_err());
        assert_eq!(signature_base64(b"\x00\x01"), "AAE=");
    }

    /// The database must be a gzip'd tar pacman can read, and rendering the
    /// same entries twice must give the same bytes (the `.sig` depends on it).
    #[test]
    fn builds_deterministic_databases() {
        use std::io::Read;
        let info = parse_pkginfo(PKGINFO).unwrap();
        let files = vec!["usr/".to_string(), "usr/bin/demo".to_string()];
        let entry = DbEntry {
            filename: "demo-2:1.2.3-4-x86_64.pkg.tar.zst",
            csize: 10,
            sha256: "ab",
            pgpsig: Some("c2ln"),
            info: &info,
            files: Some(&files),
            mtime: 1_700_000_000,
        };
        let db = build_database(std::slice::from_ref(&entry), false).unwrap();
        assert_eq!(
            db,
            build_database(std::slice::from_ref(&entry), false).unwrap()
        );

        for (with_files, expected) in [
            (false, vec!["demo-2:1.2.3-4/", "demo-2:1.2.3-4/desc"]),
            (
                true,
                vec![
                    "demo-2:1.2.3-4/",
                    "demo-2:1.2.3-4/desc",
                    "demo-2:1.2.3-4/files",
                ],
            ),
        ] {
            let db = build_database(std::slice::from_ref(&entry), with_files).unwrap();
            let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(&db[..]));
            let mut names = Vec::new();
            for e in archive.entries().unwrap() {
                let mut e = e.unwrap();
                let name = e.path().unwrap().to_string_lossy().to_string();
                assert_eq!(e.header().mtime().unwrap(), 1_700_000_000);
                if name.ends_with("/desc") {
                    let mut text = String::new();
                    e.read_to_string(&mut text).unwrap();
                    assert!(text.contains("%PGPSIG%\nc2ln\n\n"), "{text}");
                    assert!(text.contains("%VERSION%\n2:1.2.3-4\n\n"), "{text}");
                    assert!(!text.contains("%DESC%"), "absent fields are omitted");
                }
                names.push(name);
            }
            assert_eq!(names, expected);
        }
    }

    #[tokio::test]
    async fn format_handler_contract() {
        let handler = PacmanHandler::new();
        assert_eq!(handler.format(), RepositoryFormat::Pacman);
        assert_eq!(handler.format_key(), "pacman");
        assert!(handler.generate_index().await.unwrap().is_none());

        let path = "any/ak-marker-1.0-1-any.pkg.tar.zst";
        handler.validate(path, &Bytes::new()).await.unwrap();
        let meta = handler
            .parse_metadata(path, &Bytes::from_static(MARKER_PKG))
            .await
            .unwrap();
        assert_eq!(meta["arch"], "any");
        assert_eq!(meta["filename"], "ak-marker-1.0-1-any.pkg.tar.zst");
        assert_eq!(meta["pkginfo"]["pkgname"], "ak-marker");

        let db_meta = handler
            .parse_metadata("x86_64/core.db", &Bytes::new())
            .await
            .unwrap();
        assert!(db_meta.get("filename").is_none());

        for bad in ["noslash", "x86/64/a.db", "x86_64/README", "bad arch/a.db"] {
            assert!(handler.validate(bad, &Bytes::new()).await.is_err(), "{bad}");
        }
    }
}
