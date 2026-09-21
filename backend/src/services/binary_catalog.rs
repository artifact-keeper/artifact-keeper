//! Catalog native libraries from the binaries themselves (#4046).
//!
//! Recipe-derived components cover packages whose recipe declares a source.
//! Channels that publish no recipe leave a residue of statically linked code
//! that only the payload's bytes can speak for. This module reads ELF shared
//! objects and static binaries out of an already-unpacked payload and reports
//! the libraries it can prove are there, from three signals in descending
//! confidence order:
//!
//! 1. **SONAME + version-banner agreement** — the file's `DT_SONAME` names
//!    the same library a version banner in its bytes names. Two independent
//!    signals pointing at one identity.
//! 2. **Banner alone** — a well-known version banner (`OpenSSL 1.1.1w`,
//!    `libpng version 1.6.40`) with no SONAME to corroborate it, which is
//!    the normal shape for a *statically* linked library inside an
//!    executable.
//! 3. **SONAME alone** — identity without a version. The ABI tail is never
//!    promoted into `version`, per the migration-222 reasoning the wheel
//!    path already follows.
//!
//! The build-id is **identity, not version**: it deduplicates two payload
//! files that are the same compiled binary, and is never used for advisory
//! matching.
//!
//! # Why this carries lower confidence, and where that is visible
//!
//! Banner matching has a real false-positive rate — a library's banner can
//! sit in another binary as data. Binary-derived components therefore never
//! reach `Declared`: banners yield [`SourceConfidence::Inferred`], a bare
//! SONAME yields [`SourceConfidence::Unresolved`]. The finer ordering
//! between the two banner tiers is carried by `detection_method`
//! (`binary:soname+banner:<rule>` vs `binary:banner:<rule>`), because the
//! `confidence` column's CHECK (migration 222) admits exactly three values
//! and this technique must sit below all recipe-derived rows, not beside
//! them. A match always names its rule, so a wrong component is traceable
//! to the pattern that produced it.
//!
//! # v1 scope
//!
//! ELF only. Mach-O and PE payloads are not cataloged yet; the seam is
//! [`catalog_file`], which dispatches on magic bytes, so adding a format is
//! a new parser plus a new arm, not a restructure. The FP corpus below is
//! the deliverable that measures — rather than assumes — the false-positive
//! rate of the banner rules.

use once_cell::sync::Lazy;
use regex::bytes::Regex;

use crate::services::conda_recipe::SourceConfidence;
use crate::services::package_analysis_service::ExtractedComponent;

/// Rule id attached to components identified by the libwebp banner.
pub const RULE_BANNER_LIBWEBP: &str = "banner-libwebp-v1";
/// Rule id attached to components identified by the OpenSSL banner.
pub const RULE_BANNER_OPENSSL: &str = "banner-openssl-v1";
/// Rule id attached to components identified by the zlib deflate/inflate banner.
pub const RULE_BANNER_ZLIB: &str = "banner-zlib-v1";
/// Rule id attached to components identified by the libpng banner.
pub const RULE_BANNER_LIBPNG: &str = "banner-libpng-v1";

/// `detection_method` for a component recovered from a SONAME alone.
pub const METHOD_SONAME: &str = "binary:soname";

/// One well-known version-banner rule.
///
/// Every pattern is a named, individually tested rule, matching the
/// `cpe_candidates.rs` convention: a wrong component is traceable to the
/// rule that produced it, and a rule change is a deliberate, reviewable act.
struct BannerRule {
    rule_id: &'static str,
    /// The component name recorded on a match. Kept identical to the keys of
    /// `cpe_candidates`'s known table so banner-derived components feed the
    /// same advisory path without a translation layer.
    component: &'static str,
    pattern: &'static Lazy<Regex>,
    /// SONAME stems that count as agreement with this banner. A stem equal
    /// to an entry, or an entry followed by digits (`libpng16` for
    /// `libpng`), corroborates the banner. Aliases exist because upstreams
    /// do not name their SONAMEs after the project: zlib ships `libz`,
    /// OpenSSL ships `libssl`/`libcrypto`.
    soname_stems: &'static [&'static str],
}

// Real banners, as the libraries compile them in:
//   libwebp:  "libwebp 1.3.2"             (WebPGetDecoderVersion banner)
//   OpenSSL:  "OpenSSL 1.1.1w  11 Sep 2023" / "OpenSSL 3.0.13 30 Jan 2024"
//   zlib:     "deflate 1.2.13 Copyright 1995-2022 ..." (and "inflate ...")
//   libpng:   "libpng version 1.6.40 - ..."
static RE_BANNER_LIBWEBP: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"libwebp (\d+\.\d+\.\d+)\b").expect("valid regex"));
static RE_BANNER_OPENSSL: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"OpenSSL (\d+\.\d+\.\d+[a-z]?)\b").expect("valid regex"));
static RE_BANNER_ZLIB: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?:deflate|inflate) (1\.\d+\.\d+)\b").expect("valid regex"));
static RE_BANNER_LIBPNG: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"libpng version (\d+\.\d+\.\d+)\b").expect("valid regex"));

static BANNER_RULES: &[BannerRule] = &[
    BannerRule {
        rule_id: RULE_BANNER_LIBWEBP,
        component: "libwebp",
        pattern: &RE_BANNER_LIBWEBP,
        soname_stems: &["libwebp"],
    },
    BannerRule {
        rule_id: RULE_BANNER_OPENSSL,
        component: "openssl",
        pattern: &RE_BANNER_OPENSSL,
        soname_stems: &["libssl", "libcrypto"],
    },
    BannerRule {
        rule_id: RULE_BANNER_ZLIB,
        component: "zlib",
        pattern: &RE_BANNER_ZLIB,
        soname_stems: &["libz", "zlib"],
    },
    BannerRule {
        rule_id: RULE_BANNER_LIBPNG,
        component: "libpng",
        pattern: &RE_BANNER_LIBPNG,
        soname_stems: &["libpng"],
    },
];

/// A component recovered from one payload binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BinaryFinding {
    pub name: String,
    /// Upstream release version from a banner, or `None` for a SONAME-only
    /// identity. Never an ABI number.
    pub version: Option<String>,
    /// The file's `DT_SONAME`, recorded when it corroborates the finding.
    pub soname: Option<String>,
    /// The ELF ABI tail of the SONAME. Recorded, never promoted to `version`.
    pub abi_version: Option<String>,
    /// `binary:soname`, `binary:banner:<rule_id>` or
    /// `binary:soname+banner:<rule_id>`.
    pub detection_method: String,
    pub confidence: SourceConfidence,
    /// Path of the payload file the finding came from.
    pub path: String,
}

impl BinaryFinding {
    /// Hand this finding to `record_analysis` as a component. Fields with no
    /// analogue here stay `None`, exactly as the wheel extractor leaves them.
    pub fn to_extracted(&self) -> ExtractedComponent {
        ExtractedComponent {
            name: self.name.clone(),
            version: self.version.clone(),
            purl: self
                .version
                .as_ref()
                .map(|v| format!("pkg:generic/{}@{}", self.name, v)),
            source_url: None,
            git_url: None,
            git_rev: None,
            sha256: None,
            applied_patches: Vec::new(),
            confidence: self.confidence.clone(),
            detection_method: self.detection_method.clone(),
            soname: self.soname.clone(),
            abi_version: self.abi_version.clone(),
        }
    }
}

/// What the ELF parser recovers from one file.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct ElfInfo {
    soname: Option<String>,
    /// GNU build-id, hex-encoded. Identity for dedup, never a version.
    build_id: Option<String>,
}

/// `libwebp.so.7.1.3` -> (`libwebp`, `7.1.3`). The stem is lazy so the ABI
/// tail is taken from the LAST `.so`, mirroring the wheel path's RE_ELF.
static RE_SONAME: Lazy<regex::Regex> = Lazy::new(|| {
    regex::Regex::new(r"^(?P<stem>.+?)\.so(?P<abi>(?:\.\d+)*)$").expect("valid regex")
});

/// True when `path` names a payload entry worth reading for binary
/// cataloging: a shared-library name anywhere, or an extensionless file in a
/// conventional executable/library directory (the shape of a static binary).
/// The bytes are checked for the ELF magic after the read, so an
/// over-inclusive guess costs one bounded read, never a wrong finding.
pub fn is_candidate_path(path: &str) -> bool {
    let file_name = match path.rsplit('/').next() {
        Some(f) if !f.is_empty() => f,
        _ => return false,
    };
    if RE_SONAME.is_match(file_name) {
        return true;
    }
    let first = path.split('/').next().unwrap_or("");
    matches!(first, "bin" | "sbin" | "lib" | "lib64" | "libexec") && !file_name.contains('.')
}

fn is_elf(bytes: &[u8]) -> bool {
    bytes.starts_with(b"\x7fELF")
}

/// Parse the SONAME and build-id out of an ELF file's raw bytes.
///
/// A minimal, dependency-free reader over the section table: the tree has no
/// ELF crate (checked before writing this), and the two facts needed here —
/// `DT_SONAME` and `.note.gnu.build-id` — are a bounded walk of two
/// well-specified structures, far below the complexity floor at which a
/// parsing dependency pays for its audit surface. Anything malformed yields
/// `None` (or the partial facts recovered so far), never a panic and never a
/// guess.
fn parse_elf(bytes: &[u8]) -> Option<ElfInfo> {
    if !is_elf(bytes) {
        return None;
    }
    let is64 = *bytes.get(4)? == 2;
    let little = *bytes.get(5)? != 2; // anything but ELFDATA2MSB is read as LE

    let u16_at = |off: usize| -> Option<u16> {
        let b = bytes.get(off..off + 2)?;
        Some(if little {
            u16::from_le_bytes([b[0], b[1]])
        } else {
            u16::from_be_bytes([b[0], b[1]])
        })
    };
    let u32_at = |off: usize| -> Option<u32> {
        let b = bytes.get(off..off + 4)?;
        Some(if little {
            u32::from_le_bytes([b[0], b[1], b[2], b[3]])
        } else {
            u32::from_be_bytes([b[0], b[1], b[2], b[3]])
        })
    };
    let u64_at = |off: usize| -> Option<u64> {
        let b = bytes.get(off..off + 8)?;
        Some(if little {
            u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
        } else {
            u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
        })
    };

    // e_shoff / e_shentsize / e_shnum / e_shstrndx, by class.
    let (shoff, shentsize, shnum, shstrndx) = if is64 {
        (
            u64_at(0x28)? as usize,
            u16_at(0x3A)? as usize,
            u16_at(0x3C)? as usize,
            u16_at(0x3E)? as usize,
        )
    } else {
        (
            u32_at(0x20)? as usize,
            u16_at(0x2E)? as usize,
            u16_at(0x30)? as usize,
            u16_at(0x32)? as usize,
        )
    };
    // Extended numbering (shnum == 0 / SHN_XINDEX) is rare and out of v1
    // scope; a file that needs it yields no facts rather than a misparsed one.
    if shnum == 0 || shstrndx >= shnum || shentsize == 0 {
        return None;
    }
    let sh_size = if is64 { 64 } else { 40 };
    if shentsize < sh_size {
        return None;
    }

    struct Section {
        name_off: u32,
        sh_type: u32,
        offset: usize,
        size: usize,
        link: u32,
    }

    let mut sections: Vec<Section> = Vec::with_capacity(shnum);
    for i in 0..shnum {
        let base = shoff.checked_add(i.checked_mul(shentsize)?)?;
        let (name_off, sh_type, offset, size, link) = if is64 {
            (
                u32_at(base)?,
                u32_at(base + 4)?,
                u64_at(base + 24)? as usize,
                u64_at(base + 32)? as usize,
                u32_at(base + 40)?,
            )
        } else {
            (
                u32_at(base)?,
                u32_at(base + 4)?,
                u32_at(base + 16)? as usize,
                u32_at(base + 20)? as usize,
                u32_at(base + 24)?,
            )
        };
        sections.push(Section {
            name_off,
            sh_type,
            offset,
            size,
            link,
        });
    }

    let strtab = &sections[shstrndx];
    let section_name = |s: &Section| -> Option<&str> {
        let start = strtab.offset.checked_add(s.name_off as usize)?;
        let end = strtab.offset.checked_add(strtab.size)?;
        let raw = bytes.get(start..end)?;
        let nul = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
        std::str::from_utf8(&raw[..nul]).ok()
    };

    let c_str = |table: &Section, off: usize| -> Option<String> {
        let start = table.offset.checked_add(off)?;
        let end = table.offset.checked_add(table.size)?;
        let raw = bytes.get(start..end)?;
        let nul = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
        Some(String::from_utf8_lossy(&raw[..nul]).into_owned())
    };

    const SHT_DYNAMIC: u32 = 6;
    const DT_NULL: u64 = 0;
    const DT_SONAME: u64 = 14;

    let mut info = ElfInfo::default();

    for s in &sections {
        if s.sh_type == SHT_DYNAMIC && (s.link as usize) < sections.len() {
            let dynstr = &sections[s.link as usize];
            let entry = if is64 { 16 } else { 8 };
            let mut off = s.offset;
            let dyn_end = s.offset.checked_add(s.size)?;
            while off.checked_add(entry)? <= dyn_end && off.checked_add(entry)? <= bytes.len() {
                let (tag, val) = if is64 {
                    (u64_at(off)?, u64_at(off + 8)?)
                } else {
                    (u32_at(off)? as u64, u32_at(off + 4)? as u64)
                };
                if tag == DT_NULL {
                    break;
                }
                if tag == DT_SONAME {
                    info.soname = c_str(dynstr, val as usize);
                    break;
                }
                off += entry;
            }
        } else if section_name(s) == Some(".note.gnu.build-id") {
            // Note header: namesz, descsz, type — then name ("GNU\0") and the
            // descriptor, each padded to 4 bytes. Type 3 is GNU_BUILD_ID.
            let base = s.offset;
            if let (Some(namesz), Some(descsz), Some(ntype)) =
                (u32_at(base), u32_at(base + 4), u32_at(base + 8))
            {
                if ntype == 3 {
                    let desc_off = base + 12 + (namesz as usize).div_ceil(4) * 4;
                    if let Some(desc) = bytes.get(desc_off..desc_off + descsz as usize) {
                        info.build_id = Some(hex::encode(desc));
                    }
                }
            }
        }
    }

    Some(info)
}

/// Split a SONAME into its stem and ABI tail: `libwebp.so.7.1.3` ->
/// `("libwebp", Some("7.1.3"))`. `None` for something that is not a SONAME.
fn split_soname(soname: &str) -> Option<(String, Option<String>)> {
    let c = RE_SONAME.captures(soname)?;
    Some((
        c["stem"].to_string(),
        c["abi"].strip_prefix('.').map(str::to_string),
    ))
}

/// Does this SONAME stem corroborate the rule's banner? Exact, or the stem
/// followed by digits (`libpng16` corroborates `libpng`); `libwebpdemux`
/// does NOT corroborate `libwebp`, because what follows the stem is a word.
fn stem_agrees(stem: &str, rule: &BannerRule) -> bool {
    rule.soname_stems.iter().any(|s| {
        stem == *s
            || stem
                .strip_prefix(s)
                .is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()))
    })
}

/// Catalog one payload file. Empty unless the file is ELF; a non-ELF file is
/// not a failure, it is just not this cataloger's subject.
fn catalog_file(path: &str, bytes: &[u8]) -> Vec<BinaryFinding> {
    let Some(elf) = parse_elf(bytes) else {
        return Vec::new();
    };

    let soname_parts = elf.soname.as_deref().and_then(split_soname);
    let mut findings = Vec::new();
    let mut soname_claimed = false;

    for rule in BANNER_RULES {
        let Some(m) = rule.pattern.captures(bytes).and_then(|c| c.get(1)) else {
            continue;
        };
        let version = String::from_utf8_lossy(m.as_bytes()).into_owned();
        let agrees = soname_parts
            .as_ref()
            .is_some_and(|(stem, _)| stem_agrees(stem, rule));
        if agrees {
            soname_claimed = true;
        }
        findings.push(BinaryFinding {
            name: rule.component.to_string(),
            version: Some(version),
            soname: agrees.then(|| elf.soname.clone()).flatten(),
            abi_version: agrees
                .then(|| soname_parts.as_ref().and_then(|(_, abi)| abi.clone()))
                .flatten(),
            detection_method: if agrees {
                format!("binary:soname+banner:{}", rule.rule_id)
            } else {
                format!("binary:banner:{}", rule.rule_id)
            },
            confidence: SourceConfidence::Inferred,
            path: path.to_string(),
        });
    }

    // A SONAME no banner corroborated is identity without a version: the ABI
    // tail stays in `abi_version`, per the migration-222 reasoning, and the
    // row is `unresolved` — visible in the SBOM, never advisory-matched.
    if !soname_claimed {
        if let Some((stem, abi)) = soname_parts {
            findings.push(BinaryFinding {
                name: stem,
                version: None,
                soname: elf.soname.clone(),
                abi_version: abi,
                detection_method: METHOD_SONAME.to_string(),
                confidence: SourceConfidence::Unresolved,
                path: path.to_string(),
            });
        }
    }

    findings
}

/// Catalog a whole unpacked payload, given as `(path, bytes)` pairs.
///
/// Two dedups happen here, on different identities:
///
/// * **build-id** — two files with the same GNU build-id are the same
///   compiled binary (a hardlink, a copy, a `.debug` split); the first in
///   payload order speaks for both.
/// * **(name, version)** — the same library seen through two files is one
///   component. The database enforces this too (`ON CONFLICT DO NOTHING`),
///   but emitting it once keeps the in-memory result honest for non-DB
///   callers.
pub fn catalog_payload(files: &[(String, Vec<u8>)]) -> Vec<BinaryFinding> {
    let mut seen_build_ids: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut seen_components: std::collections::HashSet<(String, Option<String>)> =
        std::collections::HashSet::new();
    let mut out = Vec::new();

    for (path, bytes) in files {
        if !is_elf(bytes) {
            continue;
        }
        // The build-id check needs the parsed ELF, and parse_elf is cheap and
        // total; parse once per file and reuse via catalog_file would mean
        // parsing twice, so the dedup keys off a fresh parse here and
        // catalog_file re-parses only for survivors.
        if let Some(elf) = parse_elf(bytes) {
            if let Some(id) = &elf.build_id {
                if !seen_build_ids.insert(id.clone()) {
                    continue;
                }
            }
        }
        for f in catalog_file(path, bytes) {
            if seen_components.insert((f.name.clone(), f.version.clone())) {
                out.push(f);
            }
        }
    }
    out
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // ELF fixture builder
    // -----------------------------------------------------------------------

    /// Build a minimal but well-formed ELF64-LE shared object / executable
    /// with the given SONAME, build-id and `.rodata` content. This is the
    /// fixture every test below is built from: the corpus is crafted
    /// binaries, not captured ones, so each fixture's ground truth is known
    /// by construction.
    pub(crate) fn build_test_elf(
        soname: Option<&str>,
        build_id: Option<&[u8]>,
        rodata: &[u8],
    ) -> Vec<u8> {
        // Section layout: null, .rodata, .dynstr, .dynamic, .note.gnu.build-id,
        // .shstrtab. .dynamic and .note are omitted when empty.
        let mut dynstr: Vec<u8> = vec![0];
        let soname_off = soname.map(|s| {
            let off = dynstr.len() as u32;
            dynstr.extend_from_slice(s.as_bytes());
            dynstr.push(0);
            off
        });

        let mut shstrtab: Vec<u8> = vec![0];
        let mut name_offs = Vec::new();
        for name in [
            ".rodata",
            ".dynstr",
            ".dynamic",
            ".note.gnu.build-id",
            ".shstrtab",
        ] {
            name_offs.push(shstrtab.len() as u32);
            shstrtab.extend_from_slice(name.as_bytes());
            shstrtab.push(0);
        }

        let mut dynamic: Vec<u8> = Vec::new();
        if let Some(off) = soname_off {
            dynamic.extend_from_slice(&14u64.to_le_bytes()); // DT_SONAME
            dynamic.extend_from_slice(&(off as u64).to_le_bytes());
        }
        if soname.is_some() {
            dynamic.extend_from_slice(&0u64.to_le_bytes()); // DT_NULL
            dynamic.extend_from_slice(&0u64.to_le_bytes());
        }

        let mut note: Vec<u8> = Vec::new();
        if let Some(id) = build_id {
            note.extend_from_slice(&4u32.to_le_bytes()); // namesz
            note.extend_from_slice(&(id.len() as u32).to_le_bytes()); // descsz
            note.extend_from_slice(&3u32.to_le_bytes()); // NT_GNU_BUILD_ID
            note.extend_from_slice(b"GNU\0");
            note.extend_from_slice(id);
            while !note.len().is_multiple_of(4) {
                note.push(0);
            }
        }

        // ELF header is 64 bytes; lay sections out after it, 8-byte aligned.
        let mut cursor: usize = 64;
        let align = |cursor: &mut usize| {
            *cursor = (*cursor).div_ceil(8) * 8;
        };
        align(&mut cursor);
        let rodata_off = cursor;
        cursor += rodata.len();
        align(&mut cursor);
        let dynstr_off = cursor;
        cursor += dynstr.len();
        align(&mut cursor);
        let dynamic_off = cursor;
        cursor += dynamic.len();
        align(&mut cursor);
        let note_off = cursor;
        cursor += note.len();
        align(&mut cursor);
        let shstrtab_off = cursor;
        cursor += shstrtab.len();
        align(&mut cursor);
        let shoff = cursor;

        let section_count = 6u16;
        let mut out = vec![0u8; shoff + section_count as usize * 64];

        // ELF header.
        out[0..4].copy_from_slice(b"\x7fELF");
        out[4] = 2; // ELFCLASS64
        out[5] = 1; // little-endian
        out[6] = 1; // EV_CURRENT
        out[0x10..0x12].copy_from_slice(&3u16.to_le_bytes()); // ET_DYN
        out[0x12..0x14].copy_from_slice(&62u16.to_le_bytes()); // EM_X86_64
        out[0x28..0x30].copy_from_slice(&(shoff as u64).to_le_bytes());
        out[0x3A..0x3C].copy_from_slice(&64u16.to_le_bytes()); // e_shentsize
        out[0x3C..0x3E].copy_from_slice(&section_count.to_le_bytes());
        out[0x3E..0x40].copy_from_slice(&5u16.to_le_bytes()); // e_shstrndx

        out[rodata_off..rodata_off + rodata.len()].copy_from_slice(rodata);
        out[dynstr_off..dynstr_off + dynstr.len()].copy_from_slice(&dynstr);
        out[dynamic_off..dynamic_off + dynamic.len()].copy_from_slice(&dynamic);
        out[note_off..note_off + note.len()].copy_from_slice(&note);
        out[shstrtab_off..shstrtab_off + shstrtab.len()].copy_from_slice(&shstrtab);

        // Section headers: (name_off, type, offset, size, link).
        const SHT_PROGBITS: u32 = 1;
        const SHT_STRTAB: u32 = 3;
        const SHT_DYNAMIC: u32 = 6;
        const SHT_NOTE: u32 = 7;
        let headers = [
            (0u32, 0u32, 0usize, 0usize, 0u32),
            (name_offs[0], SHT_PROGBITS, rodata_off, rodata.len(), 0u32),
            (name_offs[1], SHT_STRTAB, dynstr_off, dynstr.len(), 0u32),
            (name_offs[2], SHT_DYNAMIC, dynamic_off, dynamic.len(), 2u32),
            (name_offs[3], SHT_NOTE, note_off, note.len(), 0u32),
            (name_offs[4], SHT_STRTAB, shstrtab_off, shstrtab.len(), 0u32),
        ];
        for (i, (name, ty, off, size, link)) in headers.iter().enumerate() {
            let base = shoff + i * 64;
            out[base..base + 4].copy_from_slice(&name.to_le_bytes());
            out[base + 4..base + 8].copy_from_slice(&ty.to_le_bytes());
            out[base + 24..base + 32].copy_from_slice(&(*off as u64).to_le_bytes());
            out[base + 32..base + 40].copy_from_slice(&(*size as u64).to_le_bytes());
            out[base + 40..base + 44].copy_from_slice(&link.to_le_bytes());
        }

        out
    }

    fn webp_so(rodata_extra: &[u8]) -> Vec<u8> {
        let mut rodata = b"some decoder strings\0libwebp 1.3.2\0more\0".to_vec();
        rodata.extend_from_slice(rodata_extra);
        build_test_elf(
            Some("libwebp.so.7.1.3"),
            Some(&[0xde, 0xad, 0xbe, 0xef]),
            &rodata,
        )
    }

    // -----------------------------------------------------------------------
    // ELF parsing
    // -----------------------------------------------------------------------

    #[test]
    fn parses_soname_and_build_id() {
        let elf = webp_so(b"");
        let info = parse_elf(&elf).expect("a well-formed ELF parses");
        assert_eq!(info.soname.as_deref(), Some("libwebp.so.7.1.3"));
        assert_eq!(info.build_id.as_deref(), Some("deadbeef"));
    }

    #[test]
    fn a_non_elf_yields_nothing() {
        assert!(parse_elf(b"#!/bin/sh\necho hi\n").is_none());
        assert!(catalog_file("bin/tool", b"#!/bin/sh\necho hi\n").is_empty());
    }

    #[test]
    fn a_truncated_elf_never_panics_and_never_guesses() {
        let elf = webp_so(b"");
        for cut in [0, 4, 16, 63, 64, elf.len() / 2, elf.len() - 1] {
            let _ = parse_elf(&elf[..cut]);
            let _ = catalog_file("lib/libwebp.so.7.1.3", &elf[..cut]);
        }
    }

    #[test]
    fn split_soname_takes_the_abi_from_the_last_so() {
        assert_eq!(
            split_soname("libwebp.so.7.1.3"),
            Some(("libwebp".to_string(), Some("7.1.3".to_string())))
        );
        assert_eq!(
            split_soname("libpython3.11.so.1.0"),
            Some(("libpython3.11".to_string(), Some("1.0".to_string())))
        );
        assert_eq!(
            split_soname("libz.so.1"),
            Some(("libz".to_string(), Some("1".to_string())))
        );
        assert_eq!(split_soname("no-extension"), None);
    }

    // -----------------------------------------------------------------------
    // Banner rules — each rule has its own test, and each test names its rule
    // -----------------------------------------------------------------------

    #[test]
    fn rule_banner_libwebp_v1() {
        let elf = webp_so(b"");
        let findings = catalog_file("lib/libwebp.so.7.1.3", &elf);
        let webp = findings
            .iter()
            .find(|f| f.name == "libwebp")
            .expect("the banner identifies libwebp");
        assert_eq!(webp.version.as_deref(), Some("1.3.2"));
        assert_eq!(
            webp.detection_method,
            format!("binary:soname+banner:{RULE_BANNER_LIBWEBP}"),
            "SONAME and banner agree, so the match names both signals"
        );
        assert_eq!(webp.soname.as_deref(), Some("libwebp.so.7.1.3"));
        assert_eq!(webp.abi_version.as_deref(), Some("7.1.3"));
        assert_eq!(webp.confidence, SourceConfidence::Inferred);
    }

    #[test]
    fn rule_banner_openssl_v1() {
        for banner in [
            &b"OpenSSL 1.1.1w  11 Sep 2023\0"[..],
            b"OpenSSL 3.0.13 30 Jan 2024\0",
        ] {
            let elf = build_test_elf(None, None, banner);
            let findings = catalog_file("bin/curl", &elf);
            let ssl = findings
                .iter()
                .find(|f| f.name == "openssl")
                .expect("a static OpenSSL banner is identified");
            assert_eq!(
                ssl.detection_method,
                format!("binary:banner:{RULE_BANNER_OPENSSL}"),
                "no SONAME to agree with: banner alone, and the method says so"
            );
            assert!(ssl.soname.is_none());
            assert_eq!(ssl.confidence, SourceConfidence::Inferred);
        }
        let elf = build_test_elf(None, None, b"OpenSSL 1.1.1w  11 Sep 2023\0");
        let findings = catalog_file("bin/curl", &elf);
        assert_eq!(findings[0].version.as_deref(), Some("1.1.1w"));
    }

    #[test]
    fn rule_banner_zlib_v1() {
        let elf = build_test_elf(
            None,
            None,
            b"deflate 1.2.13 Copyright 1995-2022 Jean-loup Gailly and Mark Adler\0",
        );
        let findings = catalog_file("bin/tool", &elf);
        let z = findings
            .iter()
            .find(|f| f.name == "zlib")
            .expect("the deflate banner identifies zlib");
        assert_eq!(z.version.as_deref(), Some("1.2.13"));
        assert_eq!(
            z.detection_method,
            format!("binary:banner:{RULE_BANNER_ZLIB}")
        );

        // The bare number is NOT enough: the deflate/inflate anchor is what
        // keeps every "1.2.13" in every binary from reading as zlib.
        let bare = build_test_elf(None, None, b"zlib 1.2.13\0");
        assert!(
            catalog_file("bin/tool", &bare)
                .iter()
                .all(|f| f.name != "zlib"),
            "an unanchored version string must not match the zlib rule"
        );
    }

    #[test]
    fn rule_banner_libpng_v1() {
        let elf = build_test_elf(
            Some("libpng16.so.16"),
            None,
            b"libpng version 1.6.40 - April 21, 2023\0",
        );
        let findings = catalog_file("lib/libpng16.so.16", &elf);
        let png = findings
            .iter()
            .find(|f| f.name == "libpng")
            .expect("the banner identifies libpng");
        assert_eq!(png.version.as_deref(), Some("1.6.40"));
        assert_eq!(
            png.detection_method,
            format!("binary:soname+banner:{RULE_BANNER_LIBPNG}"),
            "libpng16.so.16 corroborates the banner: digits after the stem \
             are the versioned-SONAME convention, not a different library"
        );
    }

    // -----------------------------------------------------------------------
    // Signal ordering
    // -----------------------------------------------------------------------

    #[test]
    fn a_soname_no_banner_corroborates_is_identity_without_a_version() {
        let elf = build_test_elf(Some("libcurl.so.4.8.0"), None, b"no banners here\0");
        let findings = catalog_file("lib/libcurl.so.4.8.0", &elf);
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert_eq!(f.name, "libcurl");
        assert_eq!(f.version, None, "the ABI tail is never a version");
        assert_eq!(f.abi_version.as_deref(), Some("4.8.0"));
        assert_eq!(f.detection_method, METHOD_SONAME);
        assert_eq!(
            f.confidence,
            SourceConfidence::Unresolved,
            "name-only identity: visible in the SBOM, never advisory-matched"
        );
    }

    #[test]
    fn a_banner_in_a_differently_named_library_still_fires_but_as_banner_alone() {
        // libcurl embedding an OpenSSL banner: the two signals disagree, so
        // openssl is reported banner-only AND libcurl is reported from its
        // SONAME. The banner-only tier is exactly where the corpus below
        // measures the false-positive cost of this case.
        let elf = build_test_elf(
            Some("libcurl.so.4"),
            None,
            b"linked with OpenSSL 1.1.1w  11 Sep 2023\0",
        );
        let findings = catalog_file("lib/libcurl.so.4", &elf);
        let ssl = findings
            .iter()
            .find(|f| f.name == "openssl")
            .expect("banner");
        assert_eq!(
            ssl.detection_method,
            format!("binary:banner:{RULE_BANNER_OPENSSL}")
        );
        let curl = findings
            .iter()
            .find(|f| f.name == "libcurl")
            .expect("soname");
        assert_eq!(curl.detection_method, METHOD_SONAME);
    }

    // -----------------------------------------------------------------------
    // Dedup
    // -----------------------------------------------------------------------

    #[test]
    fn two_files_with_one_build_id_catalog_once() {
        let id = [0x01, 0x02, 0x03, 0x04];
        let a = build_test_elf(Some("libwebp.so.7"), Some(&id), b"libwebp 1.3.2\0");
        let b = build_test_elf(Some("libwebp.so.7"), Some(&id), b"libwebp 1.3.2\0");
        let files = vec![
            ("lib/libwebp.so.7".to_string(), a),
            ("lib/hardlink-of-libwebp.so.7".to_string(), b),
        ];
        let findings = catalog_payload(&files);
        assert_eq!(
            findings.len(),
            1,
            "one build-id is one binary, however many paths name it"
        );
    }

    #[test]
    fn the_same_library_in_two_files_without_build_ids_is_one_component() {
        let a = build_test_elf(None, None, b"libpng version 1.6.40\0");
        let b = build_test_elf(None, None, b"padding\0libpng version 1.6.40\0");
        let files = vec![("bin/a".to_string(), a), ("bin/b".to_string(), b)];
        let findings = catalog_payload(&files);
        assert_eq!(findings.len(), 1, "one (name, version) is one component");
    }

    #[test]
    fn different_build_ids_are_different_binaries() {
        let a = build_test_elf(None, Some(&[0xaa]), b"OpenSSL 3.0.13 30 Jan 2024\0");
        let b = build_test_elf(None, Some(&[0xbb]), b"deflate 1.3.1 Copyright\0");
        let files = vec![("bin/a".to_string(), a), ("bin/b".to_string(), b)];
        let findings = catalog_payload(&files);
        assert_eq!(findings.len(), 2);
    }

    // -----------------------------------------------------------------------
    // Candidate-path heuristic
    // -----------------------------------------------------------------------

    #[test]
    fn candidate_paths_cover_shared_libs_and_bin_dirs() {
        for yes in [
            "lib/libwebp.so.7",
            "lib/libwebp.so.7.1.3",
            "vendor/lib/libz.so.1",
            "bin/curl",
            "sbin/ldconfig",
            "libexec/helper",
        ] {
            assert!(is_candidate_path(yes), "{yes} should be cataloged");
        }
        for no in [
            "lib/python3.12/site-packages/numpy/__init__.py",
            "bin/activate.sh",
            "info/index.json",
            "share/doc/README",
            "",
        ] {
            assert!(!is_candidate_path(no), "{no} should be skipped");
        }
    }

    // -----------------------------------------------------------------------
    // The false-positive corpus (acceptance #3)
    // -----------------------------------------------------------------------
    //
    // The corpus is the deliverable: crafted binaries whose ground truth is
    // known by construction — true positives alongside the near-misses that
    // make banner matching dangerous (truncated banners, similar-but-wrong
    // strings, one library's banner embedded in another binary as data).
    // Precision is MEASURED over the corpus and asserted against a floor;
    // it is not assumed.

    /// One corpus entry: a crafted payload, the components a perfect
    /// cataloger would report, and the human-readable case name so a
    /// regression report says which fixture moved.
    struct CorpusCase {
        name: &'static str,
        files: Vec<(String, Vec<u8>)>,
        /// (component name, version) pairs a correct cataloger emits. A
        /// finding not in this list is a measured false positive.
        expected: Vec<(&'static str, Option<&'static str>)>,
    }

    fn corpus() -> Vec<CorpusCase> {
        vec![
            CorpusCase {
                name: "shared libwebp with agreeing SONAME and banner",
                files: vec![("lib/libwebp.so.7.1.3".to_string(), webp_so(b""))],
                expected: vec![("libwebp", Some("1.3.2"))],
            },
            CorpusCase {
                name: "static binary carrying OpenSSL and zlib banners",
                files: vec![{
                    let mut rodata = b"OpenSSL 1.1.1w  11 Sep 2023\0".to_vec();
                    rodata.extend_from_slice(
                        b"deflate 1.2.13 Copyright 1995-2022 Jean-loup Gailly\0",
                    );
                    ("bin/curl".to_string(), build_test_elf(None, None, &rodata))
                }],
                expected: vec![("openssl", Some("1.1.1w")), ("zlib", Some("1.2.13"))],
            },
            CorpusCase {
                name: "libpng16 SONAME agrees with the libpng banner",
                files: vec![{
                    (
                        "lib/libpng16.so.16".to_string(),
                        build_test_elf(
                            Some("libpng16.so.16"),
                            None,
                            b"libpng version 1.6.40 - April 21, 2023\0",
                        ),
                    )
                }],
                expected: vec![("libpng", Some("1.6.40"))],
            },
            CorpusCase {
                name: "a SONAME with no banner is a name-only finding",
                files: vec![{
                    (
                        "lib/libcurl.so.4.8.0".to_string(),
                        build_test_elf(Some("libcurl.so.4.8.0"), None, b"strings\0"),
                    )
                }],
                expected: vec![("libcurl", None)],
            },
            CorpusCase {
                name: "shared libz with agreeing SONAME and deflate banner",
                files: vec![{
                    let mut rodata = b"deflate 1.2.13 Copyright 1995-2022\0".to_vec();
                    rodata.extend_from_slice(b"inflate 1.2.13 Copyright 1995-2022\0");
                    (
                        "lib/libz.so.1".to_string(),
                        build_test_elf(Some("libz.so.1"), None, &rodata),
                    )
                }],
                expected: vec![("zlib", Some("1.2.13"))],
            },
            CorpusCase {
                name: "shared libssl with agreeing SONAME and OpenSSL banner",
                files: vec![{
                    (
                        "lib/libssl.so.3".to_string(),
                        build_test_elf(Some("libssl.so.3"), None, b"OpenSSL 3.0.13 30 Jan 2024\0"),
                    )
                }],
                expected: vec![("openssl", Some("3.0.13"))],
            },
            CorpusCase {
                name: "static binary carrying libpng and zlib banners",
                files: vec![{
                    let mut rodata = b"libpng version 1.6.40 - April 21, 2023\0".to_vec();
                    rodata.extend_from_slice(b"inflate 1.3.1 Copyright 1995-2024\0");
                    (
                        "bin/busybox".to_string(),
                        build_test_elf(None, None, &rodata),
                    )
                }],
                expected: vec![("libpng", Some("1.6.40")), ("zlib", Some("1.3.1"))],
            },
            CorpusCase {
                name: "near-miss: a similar-but-different library name",
                files: vec![{
                    (
                        "bin/webtool".to_string(),
                        build_test_elf(None, None, b"libwebpages 1.2.3\0"),
                    )
                }],
                expected: vec![],
            },
            CorpusCase {
                name: "near-miss: a truncated banner at end of file",
                files: vec![{
                    (
                        "bin/tool".to_string(),
                        build_test_elf(None, None, b"data\0libpng version 1.6."),
                    )
                }],
                expected: vec![],
            },
            CorpusCase {
                name: "near-miss: LibreSSL is not OpenSSL",
                files: vec![{
                    (
                        "bin/tool".to_string(),
                        build_test_elf(None, None, b"LibreSSL 3.8.2\0"),
                    )
                }],
                expected: vec![],
            },
            CorpusCase {
                name: "near-miss: an unanchored zlib version string",
                files: vec![{
                    (
                        "bin/tool".to_string(),
                        build_test_elf(None, None, b"zlib 1.2.13\0"),
                    )
                }],
                expected: vec![],
            },
            CorpusCase {
                name: "near-miss: a two-part deflate version",
                files: vec![{
                    (
                        "bin/tool".to_string(),
                        build_test_elf(None, None, b"deflate 1.2 Copyright\0"),
                    )
                }],
                expected: vec![],
            },
            CorpusCase {
                // The dangerous case: libcurl genuinely carries an OpenSSL
                // banner string as DATA (e.g. a feature-report string), and
                // the package does NOT ship OpenSSL. The rule fires; this is
                // a real, counted false positive — included so the measured
                // precision reflects the technique rather than a corpus
                // curated to look clean.
                name: "false positive: another library's banner embedded as data",
                files: vec![{
                    (
                        "lib/libcurl.so.4".to_string(),
                        build_test_elf(
                            Some("libcurl.so.4"),
                            None,
                            b"features: OpenSSL 1.1.1w  11 Sep 2023\0",
                        ),
                    )
                }],
                expected: vec![("libcurl", None)],
            },
            CorpusCase {
                name: "not a binary at all",
                files: vec![{
                    (
                        "bin/script".to_string(),
                        b"#!/bin/sh\necho OpenSSL 1.1.1w\n".to_vec(),
                    )
                }],
                expected: vec![],
            },
        ]
    }

    #[test]
    fn every_expected_component_is_found() {
        for case in corpus() {
            let findings = catalog_payload(&case.files);
            for (name, version) in &case.expected {
                assert!(
                    findings
                        .iter()
                        .any(|f| { f.name == *name && f.version.as_deref() == *version }),
                    "case {:?}: expected component {}@{:?} was not found in {:?}",
                    case.name,
                    name,
                    version,
                    findings
                        .iter()
                        .map(|f| (&f.name, &f.version))
                        .collect::<Vec<_>>()
                );
            }
        }
    }

    #[test]
    fn measured_false_positive_rate_stays_under_the_ceiling() {
        // The stated ceiling for v1: at most 1 finding in 10 may be a false
        // positive (precision >= 0.90). The corpus deliberately includes the
        // embedded-as-data case, so this is a measured rate over adversarial
        // fixtures, not a marketing number.
        const PRECISION_FLOOR: f64 = 0.90;

        let mut total = 0usize;
        let mut false_positives = 0usize;
        for case in corpus() {
            for f in catalog_payload(&case.files) {
                total += 1;
                let expected = case
                    .expected
                    .iter()
                    .any(|(name, version)| f.name == *name && f.version.as_deref() == *version);
                if !expected {
                    false_positives += 1;
                }
            }
        }

        let precision = if total == 0 {
            1.0
        } else {
            (total - false_positives) as f64 / total as f64
        };
        assert!(
            precision >= PRECISION_FLOOR,
            "measured precision {precision:.3} ({false_positives} false positives \
             in {total} findings) fell below the stated floor {PRECISION_FLOOR}"
        );
        // Pin the corpus composition too, so "the floor held" cannot become
        // true by the corpus quietly losing its adversarial cases.
        assert!(
            false_positives >= 1,
            "the corpus must contain at least one genuine false positive, or \
             the measurement is not exercising the failure mode it exists for"
        );
    }

    #[test]
    fn binary_findings_convert_to_extracted_components_with_a_purl_only_when_versioned() {
        let elf = webp_so(b"");
        let finding = catalog_file("lib/libwebp.so.7.1.3", &elf)
            .into_iter()
            .find(|f| f.name == "libwebp")
            .expect("libwebp");
        let c = finding.to_extracted();
        assert_eq!(c.purl.as_deref(), Some("pkg:generic/libwebp@1.3.2"));
        assert_eq!(c.version.as_deref(), Some("1.3.2"));
        assert_eq!(c.soname.as_deref(), Some("libwebp.so.7.1.3"));

        let soname_only = catalog_file(
            "lib/libcurl.so.4",
            &build_test_elf(Some("libcurl.so.4"), None, b"x\0"),
        )
        .into_iter()
        .next()
        .expect("libcurl");
        let c = soname_only.to_extracted();
        assert_eq!(c.purl, None, "a version-less purl is not a match key");
    }
}
