//! MCPB bundles (#5253, Phase 3): the `manifest.json` inside a bundle and
//! its signature.
//!
//! A bundle (`.mcpb`, formerly `.dxt`) is a ZIP archive with a
//! `manifest.json` at its root. The `@anthropic-ai/mcpb` signer
//! (`src/node/sign.ts` in `modelcontextprotocol/mcpb`) appends a signature
//! block to the archive:
//!
//! ```text
//! <zip> "MCPB_SIG_V1" <u32 LE length> <PKCS#7 SignedData, DER, detached> "MCPB_SIG_END"
//! ```
//!
//! The SignedData signs the archive bytes as they were before signing
//! (SHA-256, signed attributes `contentType`, `messageDigest`,
//! `signingTime`). Since upstream #194 the signer also grows the ZIP
//! end-of-central-directory comment length by the block length, so the
//! bytes in front of the block differ from the signed bytes in that one
//! field; [`signed_content_candidates`] undoes it (bundles signed before #194
//! are accepted as well).
//!
//! Verification is pure (no outbound connection, no trust store): the
//! signature must verify with the certificate the block carries (RSA
//! PKCS#1 v1.5 with SHA-256, the only scheme the upstream signer produces)
//! and that certificate must be valid at signing time. Whether the
//! certificate chains to a trusted root is not decided here; the result
//! records the signer, issuer, fingerprint and whether it is self-signed.
//!
//! Trust is an explicit allowlist: a verified signature is `valid` only
//! when its certificate's SHA-256 fingerprint is listed in
//! [`TRUSTED_SIGNERS_ENV`] (set by the instance operator); any other
//! verified signature is `self_signed` -- it proves the bytes match what
//! the holder of that certificate signed, and nothing about who that is.
//!
//! Against signature wrapping, the SignedData is parsed strictly (no
//! unsigned attributes, every `certificates` entry a certificate, the signer
//! identified by issuer and serial), the signature block may not carry ZIP
//! records, and the manifest is read only from the signed bytes.

use std::borrow::Cow;
use std::io::Read;

use chrono::{DateTime, TimeZone, Utc};
use serde::Serialize;
use sha2::{Digest, Sha256};

/// Largest bundle accepted on upload.
pub const MCPB_MAX_BYTES: usize = 256 * 1024 * 1024;
/// Largest `manifest.json` read out of a bundle.
pub const MANIFEST_MAX_BYTES: u64 = 1024 * 1024;
/// Largest manifest kept in metadata (the rest of the bundle is not parsed).
pub const MANIFEST_KEEP_MAX_BYTES: usize = 64 * 1024;

const SIG_HEADER: &[u8] = b"MCPB_SIG_V1";
const SIG_FOOTER: &[u8] = b"MCPB_SIG_END";
const EOCD_MAGIC: &[u8] = b"PK\x05\x06";
const CDIR_MAGIC: &[u8] = b"PK\x01\x02";

/// Environment variable listing the trusted MCPB signer certificates:
/// SHA-256 fingerprints of the signing certificate (DER), hex, separated by
/// commas or whitespace (`:` separators and case are ignored).
pub const TRUSTED_SIGNERS_ENV: &str = "MCP_TRUSTED_BUNDLE_SIGNERS";

/// A fingerprint in canonical form: lower-case hex without separators.
pub fn normalize_fingerprint(s: &str) -> String {
    s.chars()
        .filter(|c| *c != ':')
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

/// Parse a trusted-signer list (pure): every 64-hex-digit entry, normalized.
pub fn parse_trusted_signers(raw: &str) -> Vec<String> {
    raw.split(|c: char| c == ',' || c.is_whitespace())
        .map(normalize_fingerprint)
        .filter(|f| f.len() == 64 && f.bytes().all(|b| b.is_ascii_hexdigit()))
        .collect()
}

/// The operator's trusted signer fingerprints ([`TRUSTED_SIGNERS_ENV`]).
pub fn trusted_signers() -> Vec<String> {
    std::env::var(TRUSTED_SIGNERS_ENV)
        .map(|v| parse_trusted_signers(&v))
        .unwrap_or_default()
}

/// Whether `fingerprint` is on `trusted`.
pub fn is_trusted(fingerprint: Option<&str>, trusted: &[String]) -> bool {
    fingerprint.is_some_and(|f| {
        let f = normalize_fingerprint(f);
        trusted.contains(&f)
    })
}

/// The trust decision on a verified signature: `valid` when the signer's
/// fingerprint is on `trusted`, else `self_signed`. Other states are kept.
pub fn apply_trust(info: &mut SignatureInfo, trusted: &[String]) {
    if matches!(
        info.state,
        SignatureState::Valid | SignatureState::SelfSigned
    ) {
        info.state = if is_trusted(info.fingerprint.as_deref(), trusted) {
            SignatureState::Valid
        } else {
            SignatureState::SelfSigned
        };
    }
}

/// The trust state of RECORDED signature facts (`metadata.signature` of a
/// stored bundle) against `trusted` now: `valid` only for a verified
/// signature whose fingerprint is trusted; `None` facts are `unsigned`.
pub fn recorded_state(facts: Option<&serde_json::Value>, trusted: &[String]) -> SignatureState {
    let Some(f) = facts else {
        return SignatureState::Unsigned;
    };
    match f.get("state").and_then(|v| v.as_str()) {
        Some("valid") | Some("self_signed") => {
            if is_trusted(f.get("fingerprint").and_then(|v| v.as_str()), trusted) {
                SignatureState::Valid
            } else {
                SignatureState::SelfSigned
            }
        }
        Some("invalid") => SignatureState::Invalid,
        _ => SignatureState::Unsigned,
    }
}

/// Whether the signature block region carries ZIP records (an end record or
/// a central directory header): a ZIP reader looking past the signed archive
/// would find them, so such a bundle is refused.
fn block_has_zip_records(block: &[u8]) -> bool {
    rfind(block, EOCD_MAGIC).is_some() || rfind(block, CDIR_MAGIC).is_some()
}
const EOCD_MIN: usize = 22;

// OID contents (without tag and length).
const OID_SIGNED_DATA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02];
const OID_DATA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01];
const OID_SHA256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
const OID_RSA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01];
const OID_SHA256_RSA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B];
const OID_CONTENT_TYPE: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x03];
const OID_MESSAGE_DIGEST: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x04];
const OID_SIGNING_TIME: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x05];

/// A bundle that cannot be accepted (400 `mcp_bundle_invalid`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleError(pub String);

impl std::fmt::Display for BundleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

fn bad(msg: impl Into<String>) -> BundleError {
    BundleError(msg.into())
}

// ---------------------------------------------------------------------------
// Signature block
// ---------------------------------------------------------------------------

/// A bundle split into its archive bytes and signature block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SplitBundle<'a> {
    /// The bytes in front of the signature block (the whole file if none).
    pub archive: &'a [u8],
    /// The PKCS#7 DER, when a block is present.
    pub signature: Option<&'a [u8]>,
    /// Length of the whole block (header, length, DER, footer).
    pub block_len: usize,
    /// A block is present but its framing is broken.
    pub malformed: bool,
}

fn rfind(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.len() > hay.len() {
        return None;
    }
    (0..=hay.len() - needle.len())
        .rev()
        .find(|&i| &hay[i..i + needle.len()] == needle)
}

/// Split `bytes` the way upstream `extractSignatureBlock` does: the last
/// footer, the nearest header before it, and the length in between. A
/// block whose length does not reach exactly to its footer, or that is not
/// at the end of the file, is malformed (present, so never "unsigned").
pub fn split_signature(bytes: &[u8]) -> SplitBundle<'_> {
    let unsigned = SplitBundle {
        archive: bytes,
        signature: None,
        block_len: 0,
        malformed: false,
    };
    let Some(footer) = rfind(bytes, SIG_FOOTER) else {
        return unsigned;
    };
    let Some(header) = rfind(&bytes[..footer], SIG_HEADER) else {
        return unsigned;
    };
    let start = header + SIG_HEADER.len();
    let malformed = SplitBundle {
        archive: &bytes[..header],
        signature: None,
        block_len: bytes.len() - header,
        malformed: true,
    };
    let Some(len_bytes) = bytes.get(start..start + 4) else {
        return malformed;
    };
    let len = u32::from_le_bytes([len_bytes[0], len_bytes[1], len_bytes[2], len_bytes[3]]) as usize;
    let der_start = start + 4;
    if der_start.checked_add(len) != Some(footer) || footer + SIG_FOOTER.len() != bytes.len() {
        return malformed;
    }
    SplitBundle {
        archive: &bytes[..header],
        signature: Some(&bytes[der_start..footer]),
        block_len: bytes.len() - header,
        malformed: false,
    }
}

/// The bytes the signer may have signed: the archive with its EOCD comment
/// length restored (current signer) and the archive as it is (signers
/// before upstream #194).
pub fn signed_content_candidates<'a>(split: &SplitBundle<'a>) -> Vec<Cow<'a, [u8]>> {
    let mut out = Vec::with_capacity(2);
    let archive = split.archive;
    if let Some(eocd) = rfind(archive, EOCD_MAGIC).filter(|&i| i + EOCD_MIN <= archive.len()) {
        let at = eocd + 20;
        let current = u16::from_le_bytes([archive[at], archive[at + 1]]) as usize;
        if let Some(orig) = current.checked_sub(split.block_len) {
            let mut restored = archive.to_vec();
            restored[at..at + 2].copy_from_slice(&(orig as u16).to_le_bytes());
            out.push(Cow::Owned(restored));
        }
    }
    out.push(Cow::Borrowed(archive));
    out
}

// ---------------------------------------------------------------------------
// Manifest
// ---------------------------------------------------------------------------

/// Read `manifest.json` from the archive bytes of a bundle. The manifest must
/// be a JSON object with a string `name` and `version`.
pub fn read_manifest(archive: &[u8]) -> Result<serde_json::Value, BundleError> {
    read_manifest_from(std::io::Cursor::new(archive))
}

fn read_manifest_from<R: std::io::Read + std::io::Seek>(
    archive: R,
) -> Result<serde_json::Value, BundleError> {
    let mut zip =
        zip::ZipArchive::new(archive).map_err(|e| bad(format!("not a ZIP archive: {e}")))?;
    crate::util::bounded_archive::check_zip_entry_count(&zip).map_err(|error| match error {
        crate::error::AppError::Validation(message) => bad(message),
        other => bad(other.to_string()),
    })?;
    let entries = vet_entry_names(&zip)?;
    let has_duplicates = zip.has_duplicate_names();
    let dir_start = zip.central_directory_start();
    let raw = {
        let mut entry = zip
            .by_name("manifest.json")
            .map_err(|_| bad("the bundle has no manifest.json at its root"))?;
        if entry.size() > MANIFEST_MAX_BYTES {
            return Err(bad("manifest.json is larger than 1 MiB"));
        }
        let mut raw = Vec::new();
        entry
            .by_ref()
            .take(MANIFEST_MAX_BYTES + 1)
            .read_to_end(&mut raw)
            .map_err(|e| bad(format!("manifest.json could not be read: {e}")))?;
        raw
    };
    // The manifest bytes are only held in memory until every header has been
    // vetted: nothing is accepted from an archive that fails below.
    vet_entry_headers(&mut zip.into_inner(), &entries, dir_start, has_duplicates)?;
    if raw.len() as u64 > MANIFEST_MAX_BYTES {
        return Err(bad("manifest.json is larger than 1 MiB"));
    }
    if crate::formats::mcp::json_depth_exceeds(&raw, crate::formats::mcp::MAX_DEPTH) {
        return Err(bad("manifest.json nests too deeply"));
    }
    crate::formats::mcp::reject_duplicate_json_keys(&raw)
        .map_err(|e| bad(format!("manifest.json: {e}")))?;
    let manifest: serde_json::Value =
        serde_json::from_slice(&raw).map_err(|e| bad(format!("manifest.json: {e}")))?;
    for field in ["name", "version"] {
        if !manifest.get(field).is_some_and(|v| v.is_string()) {
            return Err(bad(format!("manifest.json has no string `{field}`")));
        }
    }
    Ok(manifest)
}

// ---------------------------------------------------------------------------
// Archive entries (#5468, #5469, #5470)
// ---------------------------------------------------------------------------
//
// AK stores a bundle verbatim, so every entry is vetted for the client that
// later unpacks it: one unambiguous, relative, UTF-8 name per entry (the same
// in the central directory and the local header), regular files and
// directories only, and a single root `manifest.json`.

const LOCAL_MAGIC: &[u8] = b"PK\x03\x04";
/// Unix file-type bits (`S_IFMT`) of an entry's mode, and the types a bundle
/// may hold besides "none recorded" (0).
const S_IFMT: u32 = 0o170000;
const S_IFREG: u32 = 0o100000;
const S_IFDIR: u32 = 0o040000;
const S_IFLNK: u32 = 0o120000;

use crate::formats::mcp::shown;

/// Refuse a name a client could resolve outside, or ambiguously inside, the
/// directory it unpacks into: the shared archive policy
/// ([`crate::util::bounded_archive::is_unsafe_archive_entry_name`]: absolute,
/// drive-qualified, `..` segments), plus any backslash (a separator on
/// Windows, a file-name character elsewhere), any `:` (a drive prefix, or
/// an NTFS alternate data stream such as `manifest.json::$DATA` that Windows
/// writes into `manifest.json`), control character, or an empty name.
fn check_entry_name(name: &str) -> Result<(), BundleError> {
    if name.is_empty()
        || crate::util::bounded_archive::is_unsafe_archive_entry_name(name)
        || name.contains(['\\', ':'])
        || name.chars().any(char::is_control)
    {
        return Err(bad(format!("unsafe entry name: {}", shown(name))));
    }
    Ok(())
}

/// Refuse a symlink or other special file (device, FIFO, socket); a mode
/// with no file-type bits (as many archivers write) is a regular file. Both
/// the mode the ZIP reader derives (`unix_mode`) and the Unix mode in the
/// high 16 bits of the external attributes are checked, whatever host made
/// the entry: 7-Zip writes a Windows-side symlink as a FAT-made entry with
/// its Unix mode there, which `unix_mode` ignores, and 7-Zip on Linux
/// re-creates the link.
fn check_entry_type(
    name: &str,
    unix_mode: Option<u32>,
    external_attributes: u32,
) -> Result<(), BundleError> {
    let high = external_attributes >> 16;
    for mode in unix_mode.into_iter().chain((high != 0).then_some(high)) {
        match mode & S_IFMT {
            S_IFLNK => return Err(bad(format!("symlink entry: {}", shown(name)))),
            0 | S_IFREG | S_IFDIR => {}
            _ => return Err(bad(format!("special file entry: {}", shown(name)))),
        }
    }
    Ok(())
}

/// The path a client would unpack `name` to, for collision checks: empty and
/// `.` segments dropped, Unicode NFC (what a normalizing file system stores).
fn entry_key(name: &str) -> String {
    use unicode_normalization::UnicodeNormalization;
    name.split('/')
        .filter(|s| !s.is_empty() && *s != ".")
        .collect::<Vec<_>>()
        .join("/")
        .nfc()
        .collect()
}

/// Where an entry's two headers are, and the name the ZIP reader took for it.
struct EntryHeaders {
    central: u64,
    local: u64,
    name: Vec<u8>,
}

/// Vet every entry's name and type from the central directory (nothing is
/// opened or inflated) and return where its headers are for
/// [`vet_entry_headers`].
fn vet_entry_names<R: std::io::Read + std::io::Seek>(
    zip: &zip::ZipArchive<R>,
) -> Result<Vec<EntryHeaders>, BundleError> {
    let mut out = Vec::with_capacity(zip.len());
    let mut keys = std::collections::HashSet::with_capacity(zip.len());
    let mut manifests = 0usize;
    for i in 0..zip.len() {
        let entry = zip
            .by_index_data(i)
            .map_err(|e| bad(format!("entry {i} could not be read: {e}")))?;
        let name = std::str::from_utf8(entry.name_raw())
            .map_err(|_| bad(format!("entry {i} name is not UTF-8")))?;
        check_entry_name(name)?;
        check_entry_type(name, entry.unix_mode(), entry.external_attributes())?;
        let key = entry_key(name);
        // Upper-casing, unlike lower-casing, folds `ſ` (U+017F) and `ﬆ`
        // to `S`/`ST`, as NTFS and other case-insensitive file systems do.
        if key.to_uppercase() == "MANIFEST.JSON" {
            manifests += 1;
            if manifests > 1 {
                return Err(bad("duplicate entry manifest.json"));
            }
        }
        if !keys.insert(key) {
            return Err(bad(format!("duplicate entry {}", shown(name))));
        }
        out.push(EntryHeaders {
            central: entry.central_header_start(),
            local: entry.header_start(),
            name: entry.name_raw().to_vec(),
        });
    }
    Ok(out)
}

/// A raw ZIP header's file name and extra field, and where the header after
/// it starts.
struct RawHeader {
    name: Vec<u8>,
    extra: Vec<u8>,
    next: u64,
}

/// The central (`central`) or local header at `at`; `None` when no such
/// header is there.
fn raw_header<R: std::io::Read + std::io::Seek>(
    r: &mut R,
    at: u64,
    central: bool,
) -> std::io::Result<Option<RawHeader>> {
    let (magic, fixed, name_len_at) = if central {
        (CDIR_MAGIC, 46, 28)
    } else {
        (LOCAL_MAGIC, 30, 26)
    };
    let mut head = [0u8; 46];
    r.seek(std::io::SeekFrom::Start(at))?;
    r.read_exact(&mut head[..fixed])?;
    if &head[..4] != magic {
        return Ok(None);
    }
    let field = |i: usize| u16::from_le_bytes([head[i], head[i + 1]]) as usize;
    let mut name = vec![0u8; field(name_len_at)];
    r.read_exact(&mut name)?;
    let mut extra = vec![0u8; field(name_len_at + 2)];
    r.read_exact(&mut extra)?;
    let comment = if central { field(32) } else { 0 };
    let next = at + (fixed + name.len() + extra.len() + comment) as u64;
    Ok(Some(RawHeader { name, extra, next }))
}

/// Info-ZIP Unicode Path extra field (APPNOTE 4.6.9).
const UNICODE_PATH_FIELD: u16 = 0x7075;

/// Whether `extra` carries a Unicode Path field whose path is not `name`
/// (whatever its CRC: readers differ on when they honour it), or is too
/// short to hold one.
fn has_foreign_unicode_path(extra: &[u8], name: &[u8]) -> bool {
    let mut rest = extra;
    while rest.len() >= 4 {
        let id = u16::from_le_bytes([rest[0], rest[1]]);
        let len = u16::from_le_bytes([rest[2], rest[3]]) as usize;
        let data = &rest[4..(4 + len).min(rest.len())];
        if id == UNICODE_PATH_FIELD && data.get(5..) != Some(name) {
            return true;
        }
        rest = &rest[(4 + len).min(rest.len())..];
    }
    false
}

/// Vet the raw headers behind the ZIP reader's view: an exact duplicate name
/// (which the reader collapses to its last entry) is refused by name; each
/// entry's central-directory name must be the name the reader used and the
/// same bytes as its local header's, and neither header may carry a Unicode
/// path extra field naming another path. Two short reads per entry, bounded by the entry ceiling.
fn vet_entry_headers<R: std::io::Read + std::io::Seek>(
    r: &mut R,
    entries: &[EntryHeaders],
    dir_start: u64,
    has_duplicates: bool,
) -> Result<(), BundleError> {
    if has_duplicates {
        let mut seen = std::collections::HashSet::new();
        let mut at = dir_start;
        while let Ok(Some(h)) = raw_header(r, at, true) {
            if !seen.insert(h.name.clone()) {
                let name = String::from_utf8_lossy(&h.name);
                return Err(bad(format!("duplicate entry {}", shown(&name))));
            }
            at = h.next;
        }
        return Err(bad("duplicate entry names in the archive"));
    }
    for (i, e) in entries.iter().enumerate() {
        let foreign_path = || {
            bad(format!(
                "entry {i} has a Unicode path extra field naming another path"
            ))
        };
        let central = match raw_header(r, e.central, true) {
            Ok(Some(h)) => h,
            _ => return Err(bad(format!("entry {i} has no central directory header"))),
        };
        if std::str::from_utf8(&central.name).is_err() {
            return Err(bad(format!("entry {i} name is not UTF-8")));
        }
        if central.name != e.name || has_foreign_unicode_path(&central.extra, &central.name) {
            return Err(foreign_path());
        }
        let local = match raw_header(r, e.local, false) {
            Ok(Some(h)) => h,
            _ => return Err(bad(format!("entry {i} has no local header"))),
        };
        if local.name != central.name {
            return Err(bad(format!(
                "central/local header name mismatch for entry {i}"
            )));
        }
        if has_foreign_unicode_path(&local.extra, &local.name) {
            return Err(foreign_path());
        }
    }
    Ok(())
}

/// The manifest kept in `metadata.bundles[].manifest`: the whole manifest
/// when it is small, else its identity, tools and prompts only.
pub fn manifest_for_metadata(manifest: &serde_json::Value) -> serde_json::Value {
    let size = serde_json::to_vec(manifest).map(|v| v.len()).unwrap_or(0);
    if size <= MANIFEST_KEEP_MAX_BYTES {
        return manifest.clone();
    }
    let mut out = serde_json::Map::new();
    for key in [
        "manifest_version",
        "dxt_version",
        "name",
        "display_name",
        "version",
        "description",
        "tools",
        "prompts",
        "tools_generated",
        "prompts_generated",
    ] {
        if let Some(v) = manifest.get(key) {
            out.insert(key.to_string(), v.clone());
        }
    }
    out.insert("truncated".into(), true.into());
    serde_json::Value::Object(out)
}

// ---------------------------------------------------------------------------
// DER reading (just enough for CMS SignedData)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
struct Tlv<'a> {
    tag: u8,
    value: &'a [u8],
    /// The whole element, header included.
    raw: &'a [u8],
}

fn read_tlv(input: &[u8]) -> Result<(Tlv<'_>, &[u8]), BundleError> {
    let err = || bad("malformed signature (DER)");
    let tag = *input.first().ok_or_else(err)?;
    if tag & 0x1F == 0x1F {
        return Err(err());
    }
    let first = *input.get(1).ok_or_else(err)?;
    let (len, hdr) = if first < 0x80 {
        (first as usize, 2)
    } else {
        let n = (first & 0x7F) as usize;
        if n == 0 || n > 4 {
            return Err(err());
        }
        let bytes = input.get(2..2 + n).ok_or_else(err)?;
        (
            bytes.iter().fold(0usize, |acc, b| (acc << 8) | *b as usize),
            2 + n,
        )
    };
    let end = hdr.checked_add(len).ok_or_else(err)?;
    let raw = input.get(..end).ok_or_else(err)?;
    Ok((
        Tlv {
            tag,
            value: &raw[hdr..],
            raw,
        },
        &input[end..],
    ))
}

/// Every element of a constructed value, in order.
fn children(value: &[u8]) -> Result<Vec<Tlv<'_>>, BundleError> {
    let mut out = Vec::new();
    let mut rest = value;
    while !rest.is_empty() {
        let (t, r) = read_tlv(rest)?;
        out.push(t);
        rest = r;
    }
    Ok(out)
}

fn expect(t: Tlv<'_>, tag: u8) -> Result<Tlv<'_>, BundleError> {
    if t.tag == tag {
        Ok(t)
    } else {
        Err(bad("unexpected signature structure"))
    }
}

/// The OID contents of an `AlgorithmIdentifier`.
fn algorithm_oid<'a>(t: &Tlv<'a>) -> Result<&'a [u8], BundleError> {
    let parts = children(expect(*t, 0x30)?.value)?;
    Ok(expect(*parts.first().ok_or_else(|| bad("empty algorithm"))?, 0x06)?.value)
}

/// `YYMMDDHHMMSSZ` (UTCTime) or `YYYYMMDDHHMMSSZ` (GeneralizedTime).
fn parse_der_time(t: &Tlv<'_>) -> Option<DateTime<Utc>> {
    let s = std::str::from_utf8(t.value).ok()?.strip_suffix('Z')?;
    let (year, rest) = match t.tag {
        0x17 if s.len() == 12 => {
            let yy: i32 = s[..2].parse().ok()?;
            (if yy >= 50 { 1900 + yy } else { 2000 + yy }, &s[2..])
        }
        0x18 if s.len() == 14 => (s[..4].parse().ok()?, &s[4..]),
        _ => return None,
    };
    let n = |i: usize| rest.get(i..i + 2)?.parse::<u32>().ok();
    Utc.with_ymd_and_hms(year, n(0)?, n(2)?, n(4)?, n(6)?, n(8)?)
        .single()
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

/// `metadata.bundles[].signature.state`: `valid` (verifies, and the signer
/// is on the operator's trusted list), `self_signed` (verifies against the
/// certificate the bundle carries, which nothing vouches for), `unsigned`,
/// `invalid`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureState {
    Valid,
    SelfSigned,
    Unsigned,
    Invalid,
}

/// What signature verification found.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignatureInfo {
    pub state: SignatureState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    /// SHA-256 of the signing certificate (DER), lower-case hex.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub self_signed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed_at: Option<DateTime<Utc>>,
    /// Why an `invalid` signature was refused.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl SignatureInfo {
    fn unsigned() -> Self {
        Self {
            state: SignatureState::Unsigned,
            signer: None,
            issuer: None,
            fingerprint: None,
            self_signed: None,
            signed_at: None,
            reason: None,
        }
    }

    fn invalid(reason: impl Into<String>) -> Self {
        Self {
            state: SignatureState::Invalid,
            reason: Some(reason.into()),
            ..Self::unsigned()
        }
    }
}

/// The parts of a SignerInfo the verification needs.
struct Signer<'a> {
    issuer_raw: Option<&'a [u8]>,
    serial: Option<&'a [u8]>,
    digest_alg: &'a [u8],
    signed_attrs: &'a [u8],
    signature_alg: &'a [u8],
    signature: &'a [u8],
}

/// `(certificates, signer)` of a DER ContentInfo holding SignedData.
fn parse_signed_data(der: &[u8]) -> Result<(Vec<&[u8]>, Signer<'_>), BundleError> {
    let (ci, rest) = read_tlv(der)?;
    if !rest.is_empty() {
        return Err(bad("trailing bytes after the signature"));
    }
    let ci = children(expect(ci, 0x30)?.value)?;
    if ci.len() < 2 || expect(ci[0], 0x06)?.value != OID_SIGNED_DATA {
        return Err(bad("the signature is not CMS SignedData"));
    }
    let inner = children(expect(ci[1], 0xA0)?.value)?;
    let sd = children(expect(*inner.first().ok_or_else(|| bad("empty SignedData"))?, 0x30)?.value)?;
    // version, digestAlgorithms, encapContentInfo, [0] certs?, [1] crls?, signerInfos
    if sd.len() < 4 {
        return Err(bad("incomplete SignedData"));
    }
    let encap = children(expect(sd[2], 0x30)?.value)?;
    if encap.first().map(|t| t.value) != Some(OID_DATA) || encap.len() > 1 {
        return Err(bad("the signature must be detached over data"));
    }
    // Only `[0] certificates` may sit between encapContentInfo and
    // signerInfos, and every entry of it must be a certificate: anything
    // else (CRLs, attribute certificates, opaque blobs) could smuggle bytes
    // into the block.
    let mut certs = Vec::new();
    for t in &sd[3..sd.len() - 1] {
        if t.tag != 0xA0 {
            return Err(bad(
                "the signature carries something other than certificates",
            ));
        }
        for c in children(t.value)? {
            if c.tag != 0x30 {
                return Err(bad(
                    "the signature's certificate set holds a non-certificate",
                ));
            }
            certs.push(c.raw);
        }
    }
    let infos = children(expect(sd[sd.len() - 1], 0x31)?.value)?;
    if infos.len() != 1 {
        return Err(bad("exactly one signer is supported"));
    }
    let si = children(expect(infos[0], 0x30)?.value)?;
    // version, sid, digestAlgorithm, [0] signedAttrs, signatureAlgorithm,
    // signature. Unsigned attributes (`[1]`) are refused: nothing covers them.
    if si.len() < 6 {
        return Err(bad("the signer has no signed attributes"));
    }
    if si.len() > 6 {
        return Err(bad("the signer carries unsigned attributes"));
    }
    let (issuer_raw, serial) = match si[1].tag {
        0x30 => {
            let ias = children(si[1].value)?;
            (
                ias.first().map(|t| t.raw),
                ias.get(1).filter(|t| t.tag == 0x02).map(|t| t.value),
            )
        }
        _ => (None, None),
    };
    Ok((
        certs,
        Signer {
            issuer_raw,
            serial,
            digest_alg: algorithm_oid(&si[2])?,
            signed_attrs: expect(si[3], 0xA0)?.value,
            signature_alg: algorithm_oid(&si[4])?,
            signature: expect(si[5], 0x04)?.value,
        },
    ))
}

/// `(contentType, messageDigest, signingTime)` of the signed attributes.
type SignedAttributes<'a> = (Option<&'a [u8]>, Option<&'a [u8]>, Option<DateTime<Utc>>);

fn signed_attributes(attrs: &[u8]) -> Result<SignedAttributes<'_>, BundleError> {
    let (mut ct, mut md, mut at) = (None, None, None);
    for attr in children(attrs)? {
        let parts = children(expect(attr, 0x30)?.value)?;
        let (Some(oid), Some(values)) = (parts.first(), parts.get(1)) else {
            continue;
        };
        let first = children(expect(*values, 0x31)?.value)?.into_iter().next();
        match (expect(*oid, 0x06)?.value, first) {
            (OID_CONTENT_TYPE, Some(v)) if v.tag == 0x06 => ct = Some(v.value),
            (OID_MESSAGE_DIGEST, Some(v)) if v.tag == 0x04 => md = Some(v.value),
            (OID_SIGNING_TIME, Some(v)) => at = parse_der_time(&v),
            _ => {}
        }
    }
    Ok((ct, md, at))
}

fn common_name(name: &x509_cert::name::Name) -> String {
    use x509_cert::der::Decode;
    const CN: x509_cert::der::asn1::ObjectIdentifier =
        x509_cert::der::asn1::ObjectIdentifier::new_unwrap("2.5.4.3");
    for rdn in name.0.iter() {
        for atv in rdn.0.iter() {
            if atv.oid != CN {
                continue;
            }
            let raw = x509_cert::der::Encode::to_der(&atv.value).unwrap_or_default();
            if let Ok(s) = x509_cert::der::asn1::Utf8StringRef::from_der(&raw) {
                return s.to_string();
            }
            if let Ok(s) = x509_cert::der::asn1::PrintableStringRef::from_der(&raw) {
                return s.to_string();
            }
        }
    }
    name.to_string()
}

/// Verify the signature of a split bundle (pure). A signature that
/// verifies is reported `valid` here; [`apply_trust`] decides whether it
/// stays `valid` or is `self_signed`.
pub fn verify_signature(split: &SplitBundle<'_>) -> SignatureInfo {
    verify_split(split, &signed_content_candidates(split)).0
}

/// The verification result and the index of the candidate the signature
/// covers (`None` unless it verifies).
fn verify_split(
    split: &SplitBundle<'_>,
    candidates: &[Cow<'_, [u8]>],
) -> (SignatureInfo, Option<usize>) {
    if split.malformed {
        return (
            SignatureInfo::invalid("the signature block is malformed"),
            None,
        );
    }
    let Some(der) = split.signature else {
        return (SignatureInfo::unsigned(), None);
    };
    let digests: Vec<Option<[u8; 32]>> = candidates
        .iter()
        .map(|c| Some(Sha256::digest(&c[..]).into()))
        .collect();
    match verify_der_digests(der, &digests) {
        Ok((info, at)) => (info, Some(at)),
        Err(e) => (SignatureInfo::invalid(e.0), None),
    }
}

fn verify_der_digests(
    der: &[u8],
    contents: &[Option<[u8; 32]>],
) -> Result<(SignatureInfo, usize), BundleError> {
    use x509_cert::der::{Decode, Encode};
    let (certs, signer) = parse_signed_data(der)?;
    if signer.digest_alg != OID_SHA256 {
        return Err(bad("unsupported digest algorithm (SHA-256 is required)"));
    }
    if !matches!(signer.signature_alg, OID_RSA | OID_SHA256_RSA) {
        return Err(bad("unsupported signature algorithm (RSA is required)"));
    }
    let (content_type, digest, signed_at) = signed_attributes(signer.signed_attrs)?;
    if content_type != Some(OID_DATA) {
        return Err(bad("the signed content type is not data"));
    }
    let digest = digest.ok_or_else(|| bad("the signature has no message digest"))?;
    let matched = contents
        .iter()
        .position(|c| c.is_some_and(|c| c.as_slice() == digest))
        .ok_or_else(|| bad("the bundle was changed after it was signed"))?;
    let mut parsed: Vec<(x509_cert::Certificate, &[u8])> = Vec::with_capacity(certs.len());
    for raw in &certs {
        let c = x509_cert::Certificate::from_der(raw)
            .map_err(|_| bad("the signature carries an unreadable certificate"))?;
        parsed.push((c, *raw));
    }
    // The signing certificate is the one the SignerInfo names (issuer and
    // serial number); no fallback to another certificate.
    let (cert, cert_raw) = parsed
        .iter()
        .find(|(c, _)| {
            let issuer = c.tbs_certificate.issuer.to_der().unwrap_or_default();
            signer.issuer_raw == Some(issuer.as_slice())
                && signer.serial == Some(c.tbs_certificate.serial_number.as_bytes())
        })
        .ok_or_else(|| bad("the signature carries no signing certificate"))?;
    // The signature covers the DER of the attributes as a SET (RFC 5652
    // 5.4): the received encoding with the [0] tag replaced.
    verify_rsa(cert, &as_der_set(signer.signed_attrs), signer.signature)?;
    let validity = &cert.tbs_certificate.validity;
    let at = signed_at.unwrap_or_else(Utc::now);
    let from = validity.not_before.to_unix_duration().as_secs() as i64;
    let to = validity.not_after.to_unix_duration().as_secs() as i64;
    if at.timestamp() < from || at.timestamp() > to {
        return Err(bad(
            "the signing certificate was not valid when the bundle was signed",
        ));
    }
    let subject = &cert.tbs_certificate.subject;
    let issuer = &cert.tbs_certificate.issuer;
    Ok((
        SignatureInfo {
            state: SignatureState::Valid,
            signer: Some(common_name(subject)),
            issuer: Some(common_name(issuer)),
            fingerprint: Some(hex::encode(Sha256::digest(cert_raw))),
            self_signed: Some(subject.to_der().ok() == issuer.to_der().ok()),
            signed_at,
            reason: None,
        },
        matched,
    ))
}

/// `contents` re-tagged as a DER `SET` (tag `0x31`, definite length).
fn as_der_set(contents: &[u8]) -> Vec<u8> {
    let mut out = vec![0x31u8];
    let n = contents.len();
    if n < 0x80 {
        out.push(n as u8);
    } else {
        let bytes = (n as u32).to_be_bytes();
        let skip = bytes.iter().take_while(|b| **b == 0).count();
        out.push(0x80 | (4 - skip) as u8);
        out.extend_from_slice(&bytes[skip..]);
    }
    out.extend_from_slice(contents);
    out
}

fn verify_rsa(
    cert: &x509_cert::Certificate,
    message: &[u8],
    signature: &[u8],
) -> Result<(), BundleError> {
    use rsa::pkcs8::DecodePublicKey;
    use rsa::signature::Verifier;
    use x509_cert::der::Encode;
    let spki = cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|_| bad("unreadable signing key"))?;
    let key = rsa::RsaPublicKey::from_public_key_der(&spki)
        .map_err(|_| bad("unsupported signing key (RSA is required)"))?;
    let sig = rsa::pkcs1v15::Signature::try_from(signature)
        .map_err(|_| bad("malformed signature value"))?;
    rsa::pkcs1v15::VerifyingKey::<Sha256>::new(key)
        .verify(message, &sig)
        .map_err(|_| bad("the signature does not verify"))
}

// ---------------------------------------------------------------------------
// One bundle
// ---------------------------------------------------------------------------

/// Everything AK records about an uploaded bundle.
#[derive(Debug, Clone, PartialEq)]
pub struct BundleFacts {
    pub file_sha256: String,
    pub size: u64,
    pub signature: SignatureInfo,
    pub manifest: serde_json::Value,
}

/// Inspect a bundle: hash it, verify its signature, read its manifest, and
/// decide the signer's trust against the operator's list. The manifest of a
/// bundle whose signature block is present is read only from the signed
/// bytes (the archive with its ZIP comment length restored, or as it is for
/// signers before upstream #194), never from the whole file, and a block
/// that carries ZIP records is refused.
pub fn inspect(bytes: &[u8]) -> Result<BundleFacts, BundleError> {
    inspect_with(bytes, &trusted_signers())
}

/// [`inspect`] against an explicit trusted-signer list (pure).
pub fn inspect_with(bytes: &[u8], trusted: &[String]) -> Result<BundleFacts, BundleError> {
    let split = split_signature(bytes);
    if split.block_len > 0 && block_has_zip_records(&bytes[split.archive.len()..]) {
        return Err(bad("the signature block carries ZIP records"));
    }
    let candidates = signed_content_candidates(&split);
    let (mut signature, matched) = verify_split(&split, &candidates);
    apply_trust(&mut signature, trusted);
    let manifest = if split.block_len == 0 {
        read_manifest(bytes)?
    } else {
        read_manifest(&candidates[matched.unwrap_or(0)])?
    };
    Ok(BundleFacts {
        file_sha256: hex::encode(Sha256::digest(bytes)),
        size: bytes.len() as u64,
        signature,
        manifest: manifest_for_metadata(&manifest),
    })
}

/// How much of a file's end [`inspect_file`] reads to find the signature
/// block and the ZIP end record (a signature block is a few KiB).
const TAIL_BYTES: u64 = 1024 * 1024;

/// A `Read + Seek` view of the first `len` bytes of a file, with the two
/// bytes at `fix.0` read as `fix.1` (the restored ZIP comment length).
struct Window<R> {
    inner: R,
    len: u64,
    pos: u64,
    fix: Option<(u64, [u8; 2])>,
}

impl<R: std::io::Read + std::io::Seek> std::io::Read for Window<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let left = self.len.saturating_sub(self.pos);
        let n = (buf.len() as u64).min(left) as usize;
        if n == 0 {
            return Ok(0);
        }
        let got = self.inner.read(&mut buf[..n])?;
        if let Some((at, bytes)) = self.fix {
            for (k, b) in bytes.iter().enumerate() {
                let p = at + k as u64;
                if p >= self.pos && p < self.pos + got as u64 {
                    buf[(p - self.pos) as usize] = *b;
                }
            }
        }
        self.pos += got as u64;
        Ok(got)
    }
}

impl<R: std::io::Read + std::io::Seek> std::io::Seek for Window<R> {
    fn seek(&mut self, to: std::io::SeekFrom) -> std::io::Result<u64> {
        let target = match to {
            std::io::SeekFrom::Start(n) => n as i64,
            std::io::SeekFrom::End(d) => self.len as i64 + d,
            std::io::SeekFrom::Current(d) => self.pos as i64 + d,
        };
        if target < 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "seek before start",
            ));
        }
        self.pos = (target as u64).min(self.len);
        self.inner.seek(std::io::SeekFrom::Start(self.pos))?;
        Ok(self.pos)
    }
}

/// [`inspect`] for a staged file, without reading it into memory: the
/// signature block and ZIP end record are found in the file's last
/// [`TAIL_BYTES`], the manifest is read through a window over the archive,
/// and the digests are streamed. `file_sha256` is the caller's (computed
/// while staging).
pub fn inspect_file(path: &std::path::Path, file_sha256: &str) -> Result<BundleFacts, BundleError> {
    inspect_file_with(path, file_sha256, &trusted_signers())
}

/// [`inspect_file`] against an explicit trusted-signer list.
pub fn inspect_file_with(
    path: &std::path::Path,
    file_sha256: &str,
    trusted: &[String],
) -> Result<BundleFacts, BundleError> {
    use std::io::{Seek, SeekFrom};
    let io = |e: std::io::Error| bad(format!("the bundle could not be read: {e}"));
    let mut file = std::fs::File::open(path).map_err(io)?;
    let size = file.metadata().map_err(io)?.len();
    let tail_start = size.saturating_sub(TAIL_BYTES);
    file.seek(SeekFrom::Start(tail_start)).map_err(io)?;
    let mut tail = Vec::new();
    (&mut file)
        .take(TAIL_BYTES)
        .read_to_end(&mut tail)
        .map_err(io)?;
    let split = split_signature(&tail);
    if split.block_len > 0 && block_has_zip_records(&tail[split.archive.len()..]) {
        return Err(bad("the signature block carries ZIP records"));
    }
    let archive_len = tail_start + split.archive.len() as u64;
    // The restored ZIP comment length (current signer), as in
    // [`signed_content_candidates`]; the EOCD sits in the tail.
    let fix = if split.block_len > 0 {
        rfind(split.archive, EOCD_MAGIC)
            .filter(|&i| i + EOCD_MIN <= split.archive.len())
            .and_then(|i| {
                let at = i + 20;
                let cur = u16::from_le_bytes([split.archive[at], split.archive[at + 1]]) as usize;
                cur.checked_sub(split.block_len)
                    .map(|orig| (tail_start + at as u64, (orig as u16).to_le_bytes()))
            })
    } else {
        None
    };
    let (mut signature, matched) = if split.malformed {
        (
            SignatureInfo::invalid("the signature block is malformed"),
            None,
        )
    } else if let Some(der) = split.signature {
        file.seek(SeekFrom::Start(0)).map_err(io)?;
        let (restored, as_is) = stream_digests(&mut file, archive_len, fix).map_err(io)?;
        match verify_der_digests(der, &[restored, Some(as_is)]) {
            Ok((info, at)) => (info, Some(at)),
            Err(e) => (SignatureInfo::invalid(e.0), None),
        }
    } else {
        (SignatureInfo::unsigned(), None)
    };
    apply_trust(&mut signature, trusted);
    // As in [`inspect`]: the whole file when unsigned, else only the signed
    // bytes -- the restored archive (candidate 0) or the archive as it is.
    let window_fix = match (split.block_len, matched) {
        (0, _) => None,
        (_, Some(1)) => None,
        (_, Some(_)) => fix,
        (_, None) => fix,
    };
    let window_len = if split.block_len == 0 {
        size
    } else {
        archive_len
    };
    file.seek(SeekFrom::Start(0)).map_err(io)?;
    let manifest = read_manifest_from(Window {
        inner: std::io::BufReader::new(&mut file),
        len: window_len,
        pos: 0,
        fix: window_fix,
    })?;
    Ok(BundleFacts {
        file_sha256: file_sha256.to_string(),
        size,
        signature,
        manifest: manifest_for_metadata(&manifest),
    })
}

/// SHA-256 of the first `len` bytes as they are, and with the two bytes at
/// `fix.0` replaced by `fix.1` (when given).
fn stream_digests(
    r: &mut impl std::io::Read,
    len: u64,
    fix: Option<(u64, [u8; 2])>,
) -> std::io::Result<(Option<[u8; 32]>, [u8; 32])> {
    let mut as_is = Sha256::new();
    let mut restored = fix.map(|_| Sha256::new());
    let mut buf = vec![0u8; 64 * 1024];
    let mut pos = 0u64;
    let mut r = r.take(len);
    loop {
        let n = r.read(&mut buf)?;
        if n == 0 {
            break;
        }
        let chunk = &mut buf[..n];
        as_is.update(&*chunk);
        if let (Some(h), Some((at, bytes))) = (restored.as_mut(), fix) {
            for (k, b) in bytes.iter().enumerate() {
                let p = at + k as u64;
                if p >= pos && p < pos + n as u64 {
                    chunk[(p - pos) as usize] = *b;
                }
            }
            h.update(&*chunk);
        }
        pos += n as u64;
    }
    Ok((
        restored.map(|h| h.finalize().into()),
        as_is.finalize().into(),
    ))
}

/// Whether `file` is an acceptable bundle file name: `<name>.mcpb`, letters,
/// digits, `.`, `_`, `-`, at most 200 characters, not starting with `.`.
pub fn valid_file_name(file: &str) -> bool {
    file.len() <= 200
        && file.len() > ".mcpb".len()
        && file.ends_with(".mcpb")
        && !file.starts_with('.')
        && file
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// Hostile MCPB archives for the archive-entry regressions (#5468, #5469,
/// #5470), shared by the inspection tests here and the upload-route tests.
/// The `zip` writer refuses most of these names, so each archive is written
/// with a same-length placeholder name and then patched byte-for-byte.
/// Ungated by shard: both the `services-1` and `handlers-1` legs use it.
#[cfg(test)]
pub(crate) mod hostile_zips {
    /// A valid manifest.
    pub const MANIFEST: &[u8] = br#"{"name":"x","version":"1"}"#;

    /// A ZIP of `entries` (`(name, body)`), written by the `zip` crate.
    pub fn zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut buf = std::io::Cursor::new(Vec::new());
        {
            let mut z = zip::ZipWriter::new(&mut buf);
            let options = zip::write::SimpleFileOptions::default();
            for (name, body) in entries {
                z.start_file(*name, options).unwrap();
                std::io::Write::write_all(&mut z, body).unwrap();
            }
            z.finish().unwrap();
        }
        buf.into_inner()
    }

    /// Every header (`PK\x01\x02` central, `PK\x03\x04` local) whose name
    /// is `name`, as `(offset, is_central)`.
    fn headers(bytes: &[u8], name: &[u8]) -> Vec<(usize, bool)> {
        let mut out = Vec::new();
        for at in 0..bytes.len().saturating_sub(4) {
            let (central, fixed) = match &bytes[at..at + 4] {
                b"PK\x01\x02" => (true, 46),
                b"PK\x03\x04" => (false, 30),
                _ => continue,
            };
            let len_at = at + if central { 28 } else { 26 };
            let Some(len) = bytes.get(len_at..len_at + 2) else {
                continue;
            };
            let len = u16::from_le_bytes([len[0], len[1]]) as usize;
            if bytes.get(at + fixed..at + fixed + len) == Some(name) {
                out.push((at, central));
            }
        }
        out
    }

    /// Rename entry `from` to the same-length `to` in its central header
    /// (`central`) and/or local header (`local`).
    pub fn rename(
        mut bytes: Vec<u8>,
        from: &str,
        to: &[u8],
        central: bool,
        local: bool,
    ) -> Vec<u8> {
        assert_eq!(from.len(), to.len());
        let found = headers(&bytes, from.as_bytes());
        assert_eq!(found.len(), 2, "{from}: one local and one central header");
        for (at, is_central) in found {
            if (is_central && central) || (!is_central && local) {
                let start = at + if is_central { 46 } else { 30 };
                bytes[start..start + to.len()].copy_from_slice(to);
            }
        }
        bytes
    }

    /// Give entry `name` a made-by `host` and `external` attributes in its
    /// central header.
    pub fn set_attributes(mut bytes: Vec<u8>, name: &str, host: u8, external: u32) -> Vec<u8> {
        for (at, central) in headers(&bytes, name.as_bytes()) {
            if central {
                bytes[at + 5] = host;
                bytes[at + 38..at + 42].copy_from_slice(&external.to_le_bytes());
            }
        }
        bytes
    }

    /// Give entry `name` the Unix `mode` (Unix-made, central attributes).
    pub fn set_mode(bytes: Vec<u8>, name: &str, mode: u32) -> Vec<u8> {
        set_attributes(bytes, name, 3, mode << 16)
    }

    /// Break the local header signature of entry `name`.
    pub fn break_local_header(mut bytes: Vec<u8>, name: &str) -> Vec<u8> {
        for (at, central) in headers(&bytes, name.as_bytes()) {
            if !central {
                bytes[at + 3] = 0x09;
            }
        }
        bytes
    }

    /// CRC-32 (IEEE), for Unicode Path fields the reader honours.
    fn crc32(bytes: &[u8]) -> u32 {
        let mut crc = !0u32;
        for b in bytes {
            crc ^= u32::from(*b);
            for _ in 0..8 {
                crc = (crc >> 1) ^ (0xEDB8_8320 & (crc & 1).wrapping_neg());
            }
        }
        !crc
    }

    /// A bundle whose second entry `name` carries an Info-ZIP Unicode Path
    /// field naming `path` (with the CRC of `name` when `crc_ok`), in both
    /// headers or only the central one; `local_only` then hides the central
    /// copy by renaming its field id.
    pub fn with_unicode_path(
        name: &str,
        path: &str,
        crc_ok: bool,
        central_only: bool,
        local_only: bool,
    ) -> Vec<u8> {
        let crc = if crc_ok { crc32(name.as_bytes()) } else { 0 };
        let mut field = vec![1u8];
        field.extend_from_slice(&crc.to_le_bytes());
        field.extend_from_slice(path.as_bytes());
        let mut options = zip::write::FullFileOptions::default();
        options
            .add_extra_field(0x7075, &field, central_only)
            .unwrap();
        let mut buf = std::io::Cursor::new(Vec::new());
        {
            let mut z = zip::ZipWriter::new(&mut buf);
            z.start_file("manifest.json", zip::write::SimpleFileOptions::default())
                .unwrap();
            std::io::Write::write_all(&mut z, MANIFEST).unwrap();
            z.start_file(name, options).unwrap();
            std::io::Write::write_all(&mut z, b"x").unwrap();
            z.finish().unwrap();
        }
        let mut bytes = buf.into_inner();
        if local_only {
            for (at, central) in headers(&bytes, name.as_bytes()) {
                if central {
                    let extra = at + 46 + name.len();
                    assert_eq!(&bytes[extra..extra + 2], &[0x75, 0x70]);
                    bytes[extra] = 0x76;
                }
            }
        }
        bytes
    }

    /// Set the UTF-8 (language encoding) flag of entry `name` in both headers.
    pub fn set_utf8_flag(mut bytes: Vec<u8>, name: &[u8]) -> Vec<u8> {
        for (at, central) in headers(&bytes, name) {
            let flags = at + if central { 8 } else { 6 };
            bytes[flags + 1] |= 0x08; // bit 11
        }
        bytes
    }

    /// `(case, archive, detail the refusal must contain)`; every archive is
    /// otherwise a valid bundle with a root `manifest.json`.
    pub fn cases() -> Vec<(&'static str, Vec<u8>, &'static str)> {
        let with = |name: &'static str| zip(&[("manifest.json", MANIFEST), (name, b"x")]);
        let renamed = |from: &'static str, to: &[u8]| rename(with(from), from, to, true, true);
        vec![
            // #5468: duplicate manifests, duplicate names, duplicate keys.
            (
                "duplicate-manifest",
                rename(
                    zip(&[
                        ("manifest.json", MANIFEST),
                        ("manifesX.json", br#"{"name":"y","version":"2"}"#),
                    ]),
                    "manifesX.json",
                    b"manifest.json",
                    true,
                    true,
                ),
                "duplicate entry manifest.json",
            ),
            (
                "case-variant-manifest",
                with("MANIFEST.JSON"),
                "duplicate entry manifest.json",
            ),
            (
                "dot-segment-manifest",
                with("./manifest.json"),
                "duplicate entry manifest.json",
            ),
            (
                "duplicate-file",
                rename(
                    zip(&[
                        ("manifest.json", MANIFEST),
                        ("a.txt", b"1"),
                        ("b.txt", b"2"),
                    ]),
                    "b.txt",
                    b"a.txt",
                    true,
                    true,
                ),
                "duplicate entry a.txt",
            ),
            (
                "duplicate-json-key",
                zip(&[("manifest.json", br#"{"name":"x","version":"1","name":"y"}"#)]),
                "duplicate key `name`",
            ),
            (
                "duplicate-nested-json-key",
                zip(&[(
                    "manifest.json",
                    br#"{"name":"x","version":"1","server":{"a":1,"a":2}}"#,
                )]),
                "duplicate key `a`",
            ),
            (
                "duplicate-json-key-escaped-in-detail",
                zip(&[(
                    "manifest.json",
                    br#"{"name":"x","version":"1","a\u001b[31m\n":1,"a\u001b[31m\n":2}"#,
                )]),
                r"duplicate key `a\u{1b}[31m\n`",
            ),
            // #5469: traversal, absolute, drive, backslash, links, devices.
            (
                "parent-traversal",
                renamed("AAAA", b"../x"),
                "unsafe entry name: ../x",
            ),
            (
                "nested-traversal",
                renamed("AAAAAAA", b"a/../.."),
                "unsafe entry name: a/../..",
            ),
            (
                "absolute",
                renamed("AAAA", b"/etc"),
                "unsafe entry name: /etc",
            ),
            ("drive", renamed("AAAA", b"C:/x"), "unsafe entry name: C:/x"),
            (
                "backslash",
                renamed("AAA", b"a\\b"),
                r"unsafe entry name: a\\b",
            ),
            (
                "backslash-root",
                renamed("AAA", b"\\ab"),
                r"unsafe entry name: \\ab",
            ),
            (
                "symlink",
                set_mode(with("link"), "link", 0o120777),
                "symlink entry: link",
            ),
            (
                "fifo",
                set_mode(with("fifo"), "fifo", 0o010644),
                "special file entry: fifo",
            ),
            (
                "char-device",
                set_mode(with("tty0"), "tty0", 0o020644),
                "special file entry: tty0",
            ),
            (
                "symlink-fat-made",
                set_attributes(with("link"), "link", 0, (0o120777 << 16) | 0x20),
                "symlink entry: link",
            ),
            (
                "socket",
                set_mode(with("sock"), "sock", 0o140644),
                "special file entry: sock",
            ),
            (
                "ntfs-alternate-stream",
                with("manifest.json::$DATA"),
                "unsafe entry name: manifest.json::$DATA",
            ),
            (
                "colon-inside",
                with("server/C:evil"),
                "unsafe entry name: server/C:evil",
            ),
            (
                "control-char",
                renamed("AAA", b"a\x07b"),
                r"unsafe entry name: a\u{7}b",
            ),
            (
                "long-s-manifest",
                with("manife\u{17f}t.json"),
                "duplicate entry manifest.json",
            ),
            (
                "nfc-duplicate",
                zip(&[
                    ("manifest.json", MANIFEST),
                    ("caf\u{e9}.txt", b"1"),
                    ("cafe\u{301}.txt", b"2"),
                ]),
                "duplicate entry cafe",
            ),
            // #5470: malformed names and central/local disagreement.
            (
                "unicode-path-override",
                with_unicode_path("plain.txt", "other.txt", true, false, false),
                "entry 1 has a Unicode path extra field naming another path",
            ),
            (
                "unicode-path-bad-crc",
                with_unicode_path("plain.txt", "other.txt", false, true, false),
                "entry 1 has a Unicode path extra field naming another path",
            ),
            (
                "unicode-path-local-only",
                with_unicode_path("aaaaaaaaaaaaa", "manifest.json", true, false, true),
                "entry 1 has a Unicode path extra field naming another path",
            ),
            (
                "no-local-header",
                break_local_header(with("plain"), "plain"),
                "entry 1 has no local header",
            ),
            (
                "non-utf8-name",
                renamed("AAA", b"a\xffb"),
                "entry 1 name is not UTF-8",
            ),
            (
                "non-utf8-name-flagged-utf8",
                set_utf8_flag(renamed("AAA", b"a\xffb"), b"a\xffb"),
                "entry 1 name is not UTF-8",
            ),
            (
                "central-local-mismatch",
                rename(with("PLAIN"), "PLAIN", b"OTHER", true, false),
                "central/local header name mismatch for entry 1",
            ),
            (
                "local-central-mismatch",
                rename(with("PLAIN"), "PLAIN", b"OTHER", false, true),
                "central/local header name mismatch for entry 1",
            ),
            (
                "manifest-local-name-differs",
                rename(
                    zip(&[("manifest.json", MANIFEST)]),
                    "manifest.json",
                    b"evil00000.exe",
                    false,
                    true,
                ),
                "central/local header name mismatch for entry 0",
            ),
        ]
    }

    /// A benign bundle with directories and nested files, for the controls.
    pub fn benign() -> Vec<u8> {
        zip(&[
            ("manifest.json", MANIFEST),
            ("server/index.js", b"console.log(1)"),
            ("server/lib/a..b.js", b"1"),
            ("README.md", b"hi"),
        ])
    }
}

#[cfg(ak_test_shard = "services-1")]
#[cfg(test)]
mod tests {
    use super::*;

    const UNSIGNED: &[u8] = include_bytes!("../../tests/fixtures/mcpb/echo-unsigned.mcpb");
    const SIGNED: &[u8] = include_bytes!("../../tests/fixtures/mcpb/echo-signed.mcpb");
    const LEGACY: &[u8] = include_bytes!("../../tests/fixtures/mcpb/echo-signed-legacy.mcpb");
    const TAMPERED: &[u8] = include_bytes!("../../tests/fixtures/mcpb/echo-tampered.mcpb");

    #[test]
    fn unsigned_bundle_is_read_and_labelled_unsigned() {
        let facts = inspect(UNSIGNED).unwrap();
        assert_eq!(facts.signature.state, SignatureState::Unsigned);
        assert_eq!(facts.manifest["name"], "echo-mcpb");
        assert_eq!(facts.manifest["tools"][0]["name"], "echo");
        assert_eq!(facts.size, UNSIGNED.len() as u64);
        assert_eq!(facts.file_sha256, hex::encode(Sha256::digest(UNSIGNED)));
    }

    #[test]
    fn signed_bundles_verify_in_both_layouts() {
        for (label, bytes) in [("current", SIGNED), ("legacy", LEGACY)] {
            // Verified, but the signer is on no trusted list: self_signed.
            let untrusted = inspect_with(bytes, &[]).unwrap();
            assert_eq!(
                untrusted.signature.state,
                SignatureState::SelfSigned,
                "{label}: {:?}",
                untrusted.signature.reason
            );
            let fp = untrusted.signature.fingerprint.clone().unwrap();
            let facts = inspect_with(bytes, &[fp]).unwrap();
            let sig = &facts.signature;
            assert_eq!(
                sig.state,
                SignatureState::Valid,
                "{label}: {:?}",
                sig.reason
            );
            assert_eq!(sig.signer.as_deref(), Some("Acme Test Signer"));
            assert_eq!(sig.issuer.as_deref(), Some("Acme Test Signer"));
            assert_eq!(sig.self_signed, Some(true));
            assert_eq!(sig.fingerprint.as_ref().map(String::len), Some(64));
            assert!(sig.signed_at.is_some());
            assert_eq!(facts.manifest["version"], "1.0.0");
        }
        let json = serde_json::to_value(inspect_with(SIGNED, &[]).unwrap().signature).unwrap();
        assert_eq!(json["state"], "self_signed");
        assert!(json.get("reason").is_none());
    }

    /// Review finding 9: trust is the operator's fingerprint allowlist, and
    /// recorded facts are re-judged against the list as it is now.
    #[test]
    fn trusted_signer_list() {
        let fp = inspect_with(SIGNED, &[])
            .unwrap()
            .signature
            .fingerprint
            .unwrap();
        let colons: String = fp
            .as_bytes()
            .chunks(2)
            .map(|c| std::str::from_utf8(c).unwrap().to_ascii_uppercase())
            .collect::<Vec<_>>()
            .join(":");
        let list = parse_trusted_signers(&format!("nothex, {colons}\n{}", "ab".repeat(31)));
        assert_eq!(list, vec![fp.clone()]);
        assert!(is_trusted(Some(&fp), &list));
        assert!(!is_trusted(None, &list));
        let facts = serde_json::json!({"state": "valid", "fingerprint": fp});
        assert_eq!(recorded_state(Some(&facts), &list), SignatureState::Valid);
        assert_eq!(
            recorded_state(Some(&facts), &[]),
            SignatureState::SelfSigned
        );
        let unsigned = serde_json::json!({"state": "unsigned"});
        assert_eq!(
            recorded_state(Some(&unsigned), &list),
            SignatureState::Unsigned
        );
        assert_eq!(recorded_state(None, &list), SignatureState::Unsigned);
        let mut info = SignatureInfo::unsigned();
        apply_trust(&mut info, &list);
        assert_eq!(info.state, SignatureState::Unsigned);
    }

    /// DER element `tag` around `content`.
    fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        let n = content.len();
        if n < 0x80 {
            out.push(n as u8);
        } else {
            let b = (n as u32).to_be_bytes();
            let skip = b.iter().take_while(|x| **x == 0).count();
            out.push(0x80 | (4 - skip) as u8);
            out.extend_from_slice(&b[skip..]);
        }
        out.extend_from_slice(content);
        out
    }

    /// The legacy fixture with its SignedData rewritten by `edit`, which gets
    /// the SignedData's elements and returns them changed.
    fn resigned(edit: impl Fn(Vec<Vec<u8>>) -> Vec<Vec<u8>>) -> Vec<u8> {
        let split = split_signature(LEGACY);
        let der = split.signature.unwrap();
        let (ci, _) = read_tlv(der).unwrap();
        let ci = children(ci.value).unwrap();
        let (inner, _) = read_tlv(ci[1].value).unwrap();
        let sd: Vec<Vec<u8>> = children(inner.value)
            .unwrap()
            .iter()
            .map(|t| t.raw.to_vec())
            .collect();
        let sd = tlv(0x30, &edit(sd).concat());
        let new_der = tlv(0x30, &[ci[0].raw.to_vec(), tlv(0xA0, &sd)].concat());
        let mut out = split.archive.to_vec();
        out.extend_from_slice(SIG_HEADER);
        out.extend_from_slice(&(new_der.len() as u32).to_le_bytes());
        out.extend_from_slice(&new_der);
        out.extend_from_slice(SIG_FOOTER);
        out
    }

    /// Review finding 7: signature wrapping. Unsigned attributes, a
    /// certificate set holding something other than certificates, extra
    /// SignedData fields, and ZIP records inside the block are refused.
    #[test]
    fn signature_wrapping_is_refused() {
        // The rewrite itself round-trips.
        let same = resigned(|sd| sd);
        assert_eq!(
            inspect_with(&same, &[]).unwrap().signature.state,
            SignatureState::SelfSigned
        );
        let reason = |bytes: &[u8]| inspect_with(bytes, &[]).unwrap().signature.reason.unwrap();
        // An unsigned attribute appended to the SignerInfo.
        let unsigned_attr = resigned(|mut sd| {
            let last = sd.pop().unwrap();
            let (set, _) = read_tlv(&last).unwrap();
            let (si, _) = read_tlv(set.value).unwrap();
            let mut si_body = si.value.to_vec();
            si_body.extend_from_slice(&tlv(0xA1, &tlv(0x30, &[0x06, 0x01, 0x2A])));
            sd.push(tlv(0x31, &tlv(0x30, &si_body)));
            sd
        });
        assert!(reason(&unsigned_attr).contains("unsigned attributes"));
        // A non-certificate entry in the certificate set.
        let odd_cert = resigned(|mut sd| {
            let (certs, _) = read_tlv(&sd[3]).unwrap();
            let mut body = certs.value.to_vec();
            body.extend_from_slice(&tlv(0x04, b"blob"));
            sd[3] = tlv(0xA0, &body);
            sd
        });
        assert!(reason(&odd_cert).contains("non-certificate"));
        // A CRL set ([1]) between the certificates and the signer infos.
        let crls = resigned(|mut sd| {
            let at = sd.len() - 1;
            sd.insert(at, tlv(0xA1, &[]));
            sd
        });
        assert!(reason(&crls).contains("other than certificates"));
        // A forged end record / central directory inside the block.
        for magic in [EOCD_MAGIC, CDIR_MAGIC] {
            let forged = resigned(|mut sd| {
                let (certs, _) = read_tlv(&sd[3]).unwrap();
                let mut body = certs.value.to_vec();
                body.extend_from_slice(&tlv(0x04, magic));
                sd[3] = tlv(0xA0, &body);
                sd
            });
            let err = inspect_with(&forged, &[]).unwrap_err();
            assert!(err.0.contains("ZIP records"), "{err}");
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("f.mcpb");
            std::fs::write(&path, &forged).unwrap();
            assert!(inspect_file_with(&path, "x", &[]).is_err());
        }
    }

    #[test]
    fn tampered_or_broken_signatures_are_invalid() {
        let sig = inspect(TAMPERED).unwrap().signature;
        assert_eq!(sig.state, SignatureState::Invalid);
        assert!(sig.reason.unwrap().contains("changed after it was signed"));

        // A block whose length does not reach its footer.
        let mut broken = SIGNED.to_vec();
        let h = rfind(&broken, SIG_HEADER).unwrap() + SIG_HEADER.len();
        broken[h] = broken[h].wrapping_add(1);
        let split = split_signature(&broken);
        assert!(split.malformed);
        assert_eq!(verify_signature(&split).state, SignatureState::Invalid);

        // A signature value flipped: framing intact, RSA check fails.
        let mut flipped = SIGNED.to_vec();
        let footer = rfind(&flipped, SIG_FOOTER).unwrap();
        flipped[footer - 3] ^= 0xFF;
        let sig = verify_signature(&split_signature(&flipped));
        assert_eq!(sig.state, SignatureState::Invalid);

        // Garbage DER inside a well-framed block.
        let mut garbage = UNSIGNED.to_vec();
        garbage.extend_from_slice(SIG_HEADER);
        garbage.extend_from_slice(&3u32.to_le_bytes());
        garbage.extend_from_slice(&[0x30, 0x01, 0x00]);
        garbage.extend_from_slice(SIG_FOOTER);
        assert_eq!(
            verify_signature(&split_signature(&garbage)).state,
            SignatureState::Invalid
        );
    }

    /// A ZIP holding `entries` entries, the last of which is a valid
    /// root `manifest.json`, built to exercise the entry-count boundary.
    fn zip_with_entries(entries: usize) -> Vec<u8> {
        let mut buf = std::io::Cursor::new(Vec::new());
        {
            let mut z = zip::ZipWriter::new(&mut buf);
            let options = zip::write::SimpleFileOptions::default();
            for i in 0..entries.saturating_sub(1) {
                z.start_file(format!("filler/{i}"), options).unwrap();
            }
            z.start_file("manifest.json", options).unwrap();
            std::io::Write::write_all(&mut z, br#"{"name":"x","version":"1"}"#).unwrap();
            z.finish().unwrap();
        }
        buf.into_inner()
    }

    /// #5467: opening a bundle applies the shared ingest entry ceiling before
    /// the manifest lookup, on both the in-memory and staged-file paths.
    /// Exactly the cap is accepted; one more is refused and a valid bundle
    /// still inspects afterwards.
    #[test]
    fn manifest_lookup_enforces_shared_entry_ceiling() {
        let max = crate::util::bounded_archive::max_ingest_archive_entries() as usize;
        assert!(read_manifest(&zip_with_entries(max)).is_ok());

        let over = zip_with_entries(max + 1);
        let err = read_manifest(&over).unwrap_err();
        assert!(err.0.contains("too many entries"), "{err}");
        assert_eq!(
            inspect_with(&over, &[]).unwrap_err().0,
            err.0,
            "in-memory inspection must refuse the same archive"
        );

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("over.mcpb");
        std::fs::write(&path, &over).unwrap();
        let sha = hex::encode(Sha256::digest(&over));
        let file_err = inspect_file_with(&path, &sha, &[]).unwrap_err();
        assert!(file_err.0.contains("too many entries"), "{file_err}");

        assert!(inspect(UNSIGNED).is_ok());
    }

    /// #5468, #5469, #5470: every hostile archive is refused, in memory and
    /// from a staged file, with a detail naming its defect; the benign
    /// control and the fixtures still inspect.
    #[test]
    fn hostile_archive_entries_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        for (case, bytes, detail) in super::hostile_zips::cases() {
            let err = inspect_with(&bytes, &[]).expect_err(case);
            assert!(err.0.contains(detail), "{case}: {err}");
            let path = dir.path().join(format!("{case}.mcpb"));
            std::fs::write(&path, &bytes).unwrap();
            let file_err = inspect_file_with(&path, "x", &[]).expect_err(case);
            assert_eq!(file_err, err, "{case}: both paths refuse alike");
        }
        let benign = inspect_with(&super::hostile_zips::benign(), &[]).unwrap();
        assert_eq!(benign.manifest["name"], "x");
        for fixture in [UNSIGNED, SIGNED, LEGACY] {
            assert!(inspect_with(fixture, &[]).is_ok());
        }
        assert!(check_entry_type("f", None, 0).is_ok());
        assert!(check_entry_type("d/", Some(0o040755), 0o040755 << 16).is_ok());
        assert!(check_entry_type("f", Some(0o100644), 0x20).is_ok());
        let identical =
            super::hostile_zips::with_unicode_path("a.txt", "a.txt", true, false, false);
        assert!(
            inspect_with(&identical, &[]).is_ok(),
            "an identical Unicode path is fine"
        );
        assert!(check_entry_name("").is_err());
        assert!(check_entry_name("a\u{7}b").is_err());
    }

    #[test]
    fn manifests_are_required_and_bounded() {
        assert!(read_manifest(b"not a zip").is_err());
        let zip_of = |name: &str, body: &[u8]| {
            let mut buf = std::io::Cursor::new(Vec::new());
            {
                let mut z = zip::ZipWriter::new(&mut buf);
                z.start_file(name, zip::write::SimpleFileOptions::default())
                    .unwrap();
                std::io::Write::write_all(&mut z, body).unwrap();
                z.finish().unwrap();
            }
            buf.into_inner()
        };
        assert!(read_manifest(&zip_of("other.json", b"{}"))
            .unwrap_err()
            .0
            .contains("no manifest.json"));
        assert!(read_manifest(&zip_of("manifest.json", b"[1]")).is_err());
        assert!(read_manifest(&zip_of("manifest.json", br#"{"name":"x"}"#)).is_err());
        assert!(read_manifest(&zip_of("manifest.json", b"{nope")).is_err());
        let deep = format!("{}{}", "[".repeat(40), "]".repeat(40));
        assert!(read_manifest(&zip_of("manifest.json", deep.as_bytes())).is_err());
        assert!(read_manifest(&zip_of("manifest.json", br#"{"name":"x","version":"1"}"#)).is_ok());

        let big = serde_json::json!({
            "name": "x", "version": "1", "tools": [{"name": "t"}],
            "long_description": "a".repeat(MANIFEST_KEEP_MAX_BYTES + 1),
        });
        let kept = manifest_for_metadata(&big);
        assert_eq!(kept["truncated"], true);
        assert_eq!(kept["tools"][0]["name"], "t");
        assert!(kept.get("long_description").is_none());
    }

    #[test]
    fn der_helpers() {
        assert!(read_tlv(&[]).is_err());
        assert!(read_tlv(&[0x1F, 0x00]).is_err());
        assert!(read_tlv(&[0x30, 0x85, 0, 0, 0, 0, 1]).is_err());
        assert!(read_tlv(&[0x30, 0x05, 0x00]).is_err());
        let (t, rest) = read_tlv(&[0x04, 0x81, 0x01, 0xAA, 0x01]).unwrap();
        assert_eq!((t.tag, t.value, rest), (0x04, &[0xAA][..], &[0x01][..]));
        let utc = Tlv {
            tag: 0x17,
            value: b"261104023227Z",
            raw: &[],
        };
        assert_eq!(
            parse_der_time(&utc).unwrap().to_rfc3339(),
            "2026-11-04T02:32:27+00:00"
        );
        let gen = Tlv {
            tag: 0x18,
            value: b"19991231235959Z",
            raw: &[],
        };
        assert_eq!(parse_der_time(&gen).unwrap().timestamp(), 946684799);
        let bad_time = Tlv {
            tag: 0x17,
            value: b"2611",
            raw: &[],
        };
        assert!(parse_der_time(&bad_time).is_none());
        assert!(parse_signed_data(&[0x30, 0x00, 0x00]).is_err());
        assert_eq!(as_der_set(&[1, 2]), vec![0x31, 2, 1, 2]);
        let long = as_der_set(&[0u8; 300]);
        assert_eq!(&long[..4], &[0x31, 0x82, 0x01, 0x2C]);
    }

    #[test]
    fn inspect_file_matches_in_memory_inspection() {
        let dir = tempfile::tempdir().unwrap();
        for (label, bytes) in [
            ("unsigned", UNSIGNED),
            ("signed", SIGNED),
            ("legacy", LEGACY),
            ("tampered", TAMPERED),
        ] {
            let path = dir.path().join(format!("{label}.mcpb"));
            std::fs::write(&path, bytes).unwrap();
            let sha = hex::encode(Sha256::digest(bytes));
            let from_file = inspect_file_with(&path, &sha, &[]).unwrap();
            assert_eq!(from_file, inspect_with(bytes, &[]).unwrap(), "{label}");
        }
        let path = dir.path().join("junk.mcpb");
        std::fs::write(&path, b"junk").unwrap();
        assert!(inspect_file(&path, "x").is_err());
        assert!(inspect_file(&dir.path().join("missing"), "x").is_err());
    }

    #[test]
    fn file_names() {
        for ok in ["echo.mcpb", "echo-1.0.0_linux.mcpb"] {
            assert!(valid_file_name(ok), "{ok}");
        }
        for bad in [
            ".mcpb",
            ".x.mcpb",
            "echo.zip",
            "server.json",
            "a/b.mcpb",
            "a b.mcpb",
            "..mcpb",
        ] {
            assert!(!valid_file_name(bad), "{bad}");
        }
        assert!(!valid_file_name(&format!("{}.mcpb", "a".repeat(200))));
    }
}
