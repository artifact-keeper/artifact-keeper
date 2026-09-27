//! RPM format handler.
//!
//! Implements YUM/DNF repository for RPM packages.
//! Supports parsing RPM headers and generating repodata.

use async_trait::async_trait;
use bytes::Bytes;
use quick_xml::se::to_string as xml_to_string;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::error::{AppError, Result};
use crate::formats::FormatHandler;
use crate::models::repository::RepositoryFormat;
use crate::services::curation_sync::{RpmEntry, RpmFileEntry};

/// RPM format handler
pub struct RpmHandler;

// RPM header magic numbers
const RPM_MAGIC: [u8; 4] = [0xed, 0xab, 0xee, 0xdb];
const RPM_HEADER_MAGIC: [u8; 3] = [0x8e, 0xad, 0xe8];

// RPM header tags
const RPMTAG_NAME: u32 = 1000;
const RPMTAG_VERSION: u32 = 1001;
const RPMTAG_RELEASE: u32 = 1002;
const RPMTAG_SUMMARY: u32 = 1004;
const RPMTAG_DESCRIPTION: u32 = 1005;
const RPMTAG_SIZE: u32 = 1009;
const RPMTAG_LICENSE: u32 = 1014;
const RPMTAG_GROUP: u32 = 1016;
const RPMTAG_URL: u32 = 1020;
const RPMTAG_ARCH: u32 = 1022;
// Scriptlets (#4033). Each body tag has a sibling `*PROG` tag naming the
// interpreter it runs under; all four run as root during `dnf install`.
const RPMTAG_PREIN: u32 = 1023;
const RPMTAG_POSTIN: u32 = 1024;
const RPMTAG_PREUN: u32 = 1025;
const RPMTAG_POSTUN: u32 = 1026;
const RPMTAG_PREINPROG: u32 = 1085;
const RPMTAG_POSTINPROG: u32 = 1086;
const RPMTAG_PREUNPROG: u32 = 1087;
const RPMTAG_POSTUNPROG: u32 = 1088;
const RPMTAG_SOURCERPM: u32 = 1044;
const RPMTAG_PROVIDENAME: u32 = 1047;
const RPMTAG_REQUIRENAME: u32 = 1049;
// Repodata (`primary.xml`/`filelists.xml`) tags (#3801).
const RPMTAG_EPOCH: u32 = 1003;
const RPMTAG_BUILDTIME: u32 = 1006;
const RPMTAG_BUILDHOST: u32 = 1007;
const RPMTAG_VENDOR: u32 = 1011;
const RPMTAG_PACKAGER: u32 = 1015;
const RPMTAG_OLDFILENAMES: u32 = 1027;
const RPMTAG_FILEMODES: u32 = 1030;
const RPMTAG_FILEFLAGS: u32 = 1037;
const RPMTAG_ARCHIVESIZE: u32 = 1046;
const RPMTAG_REQUIREFLAGS: u32 = 1048;
const RPMTAG_REQUIREVERSION: u32 = 1050;
const RPMTAG_CONFLICTFLAGS: u32 = 1053;
const RPMTAG_CONFLICTNAME: u32 = 1054;
const RPMTAG_CONFLICTVERSION: u32 = 1055;
const RPMTAG_OBSOLETENAME: u32 = 1090;
const RPMTAG_PROVIDEFLAGS: u32 = 1112;
const RPMTAG_PROVIDEVERSION: u32 = 1113;
const RPMTAG_OBSOLETEFLAGS: u32 = 1114;
const RPMTAG_OBSOLETEVERSION: u32 = 1115;
const RPMTAG_DIRINDEXES: u32 = 1116;
const RPMTAG_BASENAMES: u32 = 1117;
const RPMTAG_DIRNAMES: u32 = 1118;
const RPMTAG_LONGARCHIVESIZE: u32 = 271;
const RPMTAG_LONGSIZE: u32 = 5009;
const RPMTAG_RECOMMENDNAME: u32 = 5046;
const RPMTAG_RECOMMENDVERSION: u32 = 5047;
const RPMTAG_RECOMMENDFLAGS: u32 = 5048;
const RPMTAG_SUGGESTNAME: u32 = 5049;
const RPMTAG_SUGGESTVERSION: u32 = 5050;
const RPMTAG_SUGGESTFLAGS: u32 = 5051;
const RPMTAG_SUPPLEMENTNAME: u32 = 5052;
const RPMTAG_SUPPLEMENTVERSION: u32 = 5053;
const RPMTAG_SUPPLEMENTFLAGS: u32 = 5054;
const RPMTAG_ENHANCENAME: u32 = 5055;
const RPMTAG_ENHANCEVERSION: u32 = 5056;
const RPMTAG_ENHANCEFLAGS: u32 = 5057;
// Signature-header tags carrying the payload (archive) size.
const RPMSIGTAG_LONGARCHIVESIZE: u32 = 271;
const RPMSIGTAG_PAYLOADSIZE: u32 = 1007;

impl RpmHandler {
    pub fn new() -> Self {
        Self
    }

    /// Parse RPM path
    /// Formats:
    ///   repodata/repomd.xml           - Repository metadata
    ///   repodata/primary.xml.gz       - Primary package metadata
    ///   repodata/filelists.xml.gz     - File listings
    ///   repodata/other.xml.gz         - Changelogs
    ///   Packages/<name>-<version>-<release>.<arch>.rpm
    ///   <name>-<version>-<release>.<arch>.rpm
    pub fn parse_path(path: &str) -> Result<RpmPathInfo> {
        let path = path.trim_start_matches('/');

        // Repodata files
        if path == "repodata/repomd.xml" || path.ends_with("/repomd.xml") {
            return Ok(RpmPathInfo {
                name: None,
                version: None,
                release: None,
                arch: None,
                operation: RpmOperation::RepoMd,
            });
        }

        if path.contains("repodata/") {
            let filename = path.rsplit('/').next().unwrap_or(path);
            return Ok(RpmPathInfo {
                name: None,
                version: None,
                release: None,
                arch: None,
                operation: Self::parse_repodata_operation(filename),
            });
        }

        // RPM package
        if path.ends_with(".rpm") {
            let filename = path.rsplit('/').next().unwrap_or(path);
            return Self::parse_rpm_filename(filename);
        }

        Err(AppError::Validation(format!(
            "Invalid RPM repository path: {}",
            path
        )))
    }

    /// Parse repodata filename to determine operation
    fn parse_repodata_operation(filename: &str) -> RpmOperation {
        if filename.contains("primary") {
            RpmOperation::Primary
        } else if filename.contains("filelists") {
            RpmOperation::Filelists
        } else if filename.contains("other") {
            RpmOperation::Other
        } else if filename.contains("comps") {
            RpmOperation::Comps
        } else if filename.contains("updateinfo") {
            RpmOperation::UpdateInfo
        } else {
            RpmOperation::RepoMd
        }
    }

    /// Parse RPM filename
    /// Format: <name>-<version>-<release>.<arch>.rpm
    pub fn parse_rpm_filename(filename: &str) -> Result<RpmPathInfo> {
        let name = filename.trim_end_matches(".rpm");

        // Split off architecture
        let (name_ver_rel, arch) = name
            .rsplit_once('.')
            .ok_or_else(|| AppError::Validation(format!("Invalid RPM filename: {}", filename)))?;

        // Split name-version-release
        // Find the last two hyphens
        let parts: Vec<&str> = name_ver_rel.rsplitn(3, '-').collect();

        if parts.len() != 3 {
            return Err(AppError::Validation(format!(
                "Invalid RPM filename format: {}",
                filename
            )));
        }

        let release = parts[0].to_string();
        let version = parts[1].to_string();
        let pkg_name = parts[2].to_string();

        Ok(RpmPathInfo {
            name: Some(pkg_name),
            version: Some(version),
            release: Some(release),
            arch: Some(arch.to_string()),
            operation: RpmOperation::Package,
        })
    }

    /// Parse RPM package header
    pub fn parse_rpm_header(content: &[u8]) -> Result<RpmMetadata> {
        // Verify RPM magic
        if content.len() < 96 {
            return Err(AppError::Validation("RPM file too small".to_string()));
        }

        if content[..4] != RPM_MAGIC {
            return Err(AppError::Validation("Invalid RPM magic number".to_string()));
        }

        // Read lead
        let _major = content[4];
        let _minor = content[5];
        let _type = u16::from_be_bytes([content[6], content[7]]);
        let _archnum = u16::from_be_bytes([content[8], content[9]]);

        // Read package name from lead (66 bytes starting at offset 10)
        let name_bytes = &content[10..76];
        let lead_name = String::from_utf8_lossy(
            &name_bytes[..name_bytes.iter().position(|&b| b == 0).unwrap_or(66)],
        )
        .to_string();

        // Skip the signature header (at offset 96) to the main header.
        let offset = Self::main_header_offset(content);

        // Parse main header
        let metadata = if content.len() > offset.saturating_add(16)
            && content[offset..offset + 3] == RPM_HEADER_MAGIC
        {
            Self::parse_header_section(&content[offset..])?
        } else {
            // Fallback to lead name
            RpmMetadata {
                name: lead_name,
                version: String::new(),
                release: String::new(),
                arch: String::new(),
                summary: None,
                description: None,
                license: None,
                group: None,
                url: None,
                size: None,
                source_rpm: None,
                provides: vec![],
                requires: vec![],
                pre_install: None,
                post_install: None,
                pre_uninstall: None,
                post_uninstall: None,
                pre_install_prog: None,
                post_install_prog: None,
                pre_uninstall_prog: None,
                post_uninstall_prog: None,
            }
        };

        Ok(metadata)
    }

    /// Parse RPM header section
    fn parse_header_section(data: &[u8]) -> Result<RpmMetadata> {
        let h = HeaderIndex::parse(data).map_err(|e| AppError::Validation(e.to_string()))?;
        // Same element budget as the repodata extraction; over it, the lists
        // are left empty rather than materialized.
        let names = |tag: u32| -> Vec<String> {
            if h.count(RPMTAG_PROVIDENAME) + h.count(RPMTAG_REQUIRENAME) > RPM_MAX_LIST_ELEMENTS {
                return Vec::new();
            }
            h.string_array(tag)
                .unwrap_or_default()
                .into_iter()
                .filter(|s| !s.is_empty())
                .collect()
        };

        let get_string = |tag: u32| -> String { h.string(tag).unwrap_or_default() };
        let get_optional = |tag: u32| -> Option<String> { h.string(tag) };

        Ok(RpmMetadata {
            name: get_string(RPMTAG_NAME),
            version: get_string(RPMTAG_VERSION),
            release: get_string(RPMTAG_RELEASE),
            arch: get_string(RPMTAG_ARCH),
            summary: get_optional(RPMTAG_SUMMARY),
            description: get_optional(RPMTAG_DESCRIPTION),
            license: get_optional(RPMTAG_LICENSE),
            group: get_optional(RPMTAG_GROUP),
            url: get_optional(RPMTAG_URL),
            size: h.int(RPMTAG_LONGSIZE).or_else(|| h.int(RPMTAG_SIZE)),
            source_rpm: get_optional(RPMTAG_SOURCERPM),
            provides: names(RPMTAG_PROVIDENAME),
            requires: names(RPMTAG_REQUIRENAME),
            pre_install: get_optional(RPMTAG_PREIN),
            post_install: get_optional(RPMTAG_POSTIN),
            pre_uninstall: get_optional(RPMTAG_PREUN),
            post_uninstall: get_optional(RPMTAG_POSTUN),
            pre_install_prog: get_optional(RPMTAG_PREINPROG),
            post_install_prog: get_optional(RPMTAG_POSTINPROG),
            pre_uninstall_prog: get_optional(RPMTAG_PREUNPROG),
            post_uninstall_prog: get_optional(RPMTAG_POSTUNPROG),
        })
    }

    /// Byte offset of the main header structure: past the 96-byte lead and
    /// the signature header, whose store is padded to an 8-byte boundary.
    /// Saturates instead of overflowing on hostile signature sizes; the
    /// caller's magic/length checks then reject the package.
    fn main_header_offset(content: &[u8]) -> usize {
        let offset: usize = 96;
        if content.len() > offset.saturating_add(16)
            && content[offset..offset + 3] == RPM_HEADER_MAGIC
        {
            let nindex = be_u32(&content[offset + 8..]) as usize;
            let hsize = be_u32(&content[offset + 12..]) as usize;
            let end = nindex
                .saturating_mul(16)
                .saturating_add(hsize)
                .saturating_add(offset + 16);
            end.saturating_add(7) & !7
        } else {
            offset
        }
    }

    /// Number of leading bytes of a package needed to read everything
    /// [`Self::parse_rpm_repodata_info`] consumes (lead + signature header +
    /// main header), or `None` when `prefix` is too short to tell yet. A
    /// caller holding only a prefix grows it until this is satisfied.
    pub fn header_bytes_needed(prefix: &[u8]) -> Option<usize> {
        if prefix.len() < 96 + 16 {
            return None;
        }
        let main = Self::main_header_offset(prefix);
        if prefix.len() < main.saturating_add(16) {
            return Some(main.saturating_add(16));
        }
        let data = &prefix[main..];
        if data[..3] != RPM_HEADER_MAGIC {
            // Not a well-formed package: the parse will fail regardless of
            // how many more bytes we fetch.
            return Some(prefix.len());
        }
        let nindex = be_u32(&data[8..]) as usize;
        let hsize = be_u32(&data[12..]) as usize;
        Some(
            nindex
                .saturating_mul(16)
                .saturating_add(hsize)
                .saturating_add(main + 16),
        )
    }

    /// Extract everything `createrepo_c` writes into a package's
    /// `primary.xml`/`filelists.xml` entry beyond the basic NEVRA and text
    /// fields (#3801): epoch, packager/vendor/buildhost, build time, installed
    /// and archive sizes, the header byte range, the dependency lists and the
    /// file list. Dependency lists follow `createrepo_c`'s rules exactly — see
    /// [`requires_entries`].
    ///
    /// The header is untrusted: it is bounded by rpm's own header limits
    /// (see [`HeaderIndex::parse`]) and by [`RPM_MAX_LIST_ELEMENTS`] before
    /// any list is materialized, so work and memory are linear in a capped
    /// input.
    pub fn parse_rpm_repodata_info(
        content: &[u8],
    ) -> std::result::Result<RpmRepodataInfo, RpmHeaderError> {
        if content.len() < 96 + 16 || content[..4] != RPM_MAGIC {
            return Err(RpmHeaderError::Malformed("not an RPM package".into()));
        }
        let sig = if content[96..99] == RPM_HEADER_MAGIC {
            HeaderIndex::parse(&content[96..]).ok()
        } else {
            None
        };
        let start = Self::main_header_offset(content);
        if content.len() < start.saturating_add(16) {
            return Err(RpmHeaderError::Malformed("RPM header truncated".into()));
        }
        let h = HeaderIndex::parse(&content[start..])?;
        let end = start + h.len;

        // Budget every list before materializing any of it: tags may alias
        // the same bytes, so per-tag bounds alone do not bound the total.
        let declared: usize = REPODATA_LIST_TAGS.iter().map(|&t| h.count(t)).sum();
        if declared > RPM_MAX_LIST_ELEMENTS {
            return Err(RpmHeaderError::OverLimit(format!(
                "RPM header declares {declared} dependency/file entries \
                 (limit {RPM_MAX_LIST_ELEMENTS})"
            )));
        }

        let files = file_entries(&h)?;
        let provides_raw = raw_deps(
            &h,
            RPMTAG_PROVIDENAME,
            RPMTAG_PROVIDEFLAGS,
            RPMTAG_PROVIDEVERSION,
        )?;
        // createrepo_c's `provided_hashtable`: provides that survived the
        // bad-epoch filter, keyed by name + flag string + RAW version string.
        let provided: std::collections::HashSet<String> = provides_raw
            .iter()
            .filter(|d| d.entry().is_some())
            .map(RawDep::nfv_key)
            .collect();
        let own_files: std::collections::HashSet<&str> =
            files.iter().map(|f| f.path.as_str()).collect();
        let requires = requires_entries(
            raw_deps(
                &h,
                RPMTAG_REQUIRENAME,
                RPMTAG_REQUIREFLAGS,
                RPMTAG_REQUIREVERSION,
            )?,
            &provided,
            &own_files,
        );
        let dep = |n, f, v| -> std::result::Result<Vec<RpmEntry>, RpmHeaderError> {
            Ok(plain_entries(raw_deps(&h, n, f, v)?))
        };

        let archive_size = h
            .int(RPMTAG_LONGARCHIVESIZE)
            .or_else(|| h.int(RPMTAG_ARCHIVESIZE))
            .or_else(|| sig.as_ref().and_then(|s| s.int(RPMSIGTAG_LONGARCHIVESIZE)))
            .or_else(|| sig.as_ref().and_then(|s| s.int(RPMSIGTAG_PAYLOADSIZE)));

        Ok(RpmRepodataInfo {
            epoch: h.int(RPMTAG_EPOCH),
            packager: h.string(RPMTAG_PACKAGER),
            vendor: h.string(RPMTAG_VENDOR),
            buildhost: h.string(RPMTAG_BUILDHOST),
            build_time: h.int(RPMTAG_BUILDTIME),
            installed_size: h.int(RPMTAG_LONGSIZE).or_else(|| h.int(RPMTAG_SIZE)),
            archive_size,
            header_start: start as u64,
            header_end: end as u64,
            conflicts: dep(
                RPMTAG_CONFLICTNAME,
                RPMTAG_CONFLICTFLAGS,
                RPMTAG_CONFLICTVERSION,
            )?,
            obsoletes: dep(
                RPMTAG_OBSOLETENAME,
                RPMTAG_OBSOLETEFLAGS,
                RPMTAG_OBSOLETEVERSION,
            )?,
            suggests: dep(
                RPMTAG_SUGGESTNAME,
                RPMTAG_SUGGESTFLAGS,
                RPMTAG_SUGGESTVERSION,
            )?,
            enhances: dep(
                RPMTAG_ENHANCENAME,
                RPMTAG_ENHANCEFLAGS,
                RPMTAG_ENHANCEVERSION,
            )?,
            recommends: dep(
                RPMTAG_RECOMMENDNAME,
                RPMTAG_RECOMMENDFLAGS,
                RPMTAG_RECOMMENDVERSION,
            )?,
            supplements: dep(
                RPMTAG_SUPPLEMENTNAME,
                RPMTAG_SUPPLEMENTFLAGS,
                RPMTAG_SUPPLEMENTVERSION,
            )?,
            provides: plain_entries(provides_raw),
            requires,
            files,
        })
    }
}

/// Why a package's header could not be indexed (#3801).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RpmHeaderError {
    /// Not a well-formed RPM header (rpm itself would refuse it). Uploads
    /// are still accepted, as before, with filename-derived metadata only.
    Malformed(String),
    /// Well-formed but beyond the resource limits this server indexes.
    /// Uploads are rejected; stored packages are marked unparseable.
    OverLimit(String),
}

impl std::fmt::Display for RpmHeaderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(m) => write!(f, "malformed RPM header: {m}"),
            Self::OverLimit(m) => write!(f, "RPM header over limit: {m}"),
        }
    }
}

/// rpm's own cap on header index entries (`HEADER_TAGS_MAX`, 0xffff, in
/// rpm's `lib/header.cc`; `hdrchkTags`).
pub const RPM_HEADER_TAGS_MAX: usize = 0xffff;
/// rpm's cap on the element count of one non-BIN tag (`HEADER_ARRAY_MAX`,
/// 0xfffff, `lib/header.cc`; `hdrchkArray`).
const RPM_HEADER_ARRAY_MAX: usize = 0xf_ffff;
/// Largest header data store indexed. rpm accepts up to 256 MiB
/// (`HEADER_DATA_MAX`); real headers are kilobytes to a few MiB, so the
/// practical cap matches the ranged-read cap used to heal stored packages.
pub const RPM_HEADER_DATA_MAX: usize = 32 * 1024 * 1024;
/// Total dependency + file-list entries one package may declare. Tags can
/// alias the same bytes, so this bounds the materialized lists (and the
/// persisted/rendered metadata) independently of the per-tag limits. Far
/// above real packages (the largest distribution packages list tens of
/// thousands of files).
pub const RPM_MAX_LIST_ELEMENTS: usize = 262_144;

/// Every string-array tag [`RpmHandler::parse_rpm_repodata_info`]
/// materializes as a list; their declared counts share one budget.
const REPODATA_LIST_TAGS: [u32; 11] = [
    RPMTAG_PROVIDENAME,
    RPMTAG_REQUIRENAME,
    RPMTAG_CONFLICTNAME,
    RPMTAG_OBSOLETENAME,
    RPMTAG_SUGGESTNAME,
    RPMTAG_ENHANCENAME,
    RPMTAG_RECOMMENDNAME,
    RPMTAG_SUPPLEMENTNAME,
    RPMTAG_BASENAMES,
    RPMTAG_DIRNAMES,
    RPMTAG_OLDFILENAMES,
];

fn be_u32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

// RPM header tag data types (rpmTagType).
const RPM_INT8_TYPE: u32 = 2;
const RPM_INT16_TYPE: u32 = 3;
const RPM_INT32_TYPE: u32 = 4;
const RPM_INT64_TYPE: u32 = 5;
const RPM_STRING_ARRAY_TYPE: u32 = 8;
const RPM_I18NSTRING_TYPE: u32 = 9;

struct HeaderEntry {
    data_type: u32,
    offset: usize,
    count: usize,
}

/// Typed, bounds-checked view over one RPM header structure (magic, index,
/// data store). Replaces the earlier "first NUL-terminated string of every
/// tag" reader, which could not see integer tags (installed size, epoch,
/// dependency flags) or more than the first element of an array (#3801).
struct HeaderIndex<'a> {
    store: &'a [u8],
    entries: HashMap<u32, HeaderEntry>,
    /// Total byte length of the header structure (intro + index + store).
    len: usize,
}

/// Minimum bytes one element of `data_type` occupies in the store; `None`
/// for a type outside rpm's range (`hdrchkType`).
fn element_width(data_type: u32) -> Option<usize> {
    match data_type {
        0 => Some(0), // RPM_NULL_TYPE
        1 | RPM_INT8_TYPE | 7 => Some(1),
        RPM_INT16_TYPE => Some(2),
        RPM_INT32_TYPE => Some(4),
        RPM_INT64_TYPE => Some(8),
        // Strings: at least the terminating NUL each.
        6 | RPM_STRING_ARRAY_TYPE | RPM_I18NSTRING_TYPE => Some(1),
        _ => None,
    }
}

impl<'a> HeaderIndex<'a> {
    /// Parse and validate one header structure the way rpm's
    /// `hdrblobVerifyInfo` does (`lib/header.cc`): at most
    /// [`RPM_HEADER_TAGS_MAX`] entries, a store of at most
    /// [`RPM_HEADER_DATA_MAX`] bytes, and for every entry a known type, a
    /// count in `1..=`[`RPM_HEADER_ARRAY_MAX`] (BIN excepted), an offset
    /// inside the store, and element data that fits in the remaining bytes.
    /// Any violation rejects the whole header, as rpm would.
    fn parse(data: &'a [u8]) -> std::result::Result<Self, RpmHeaderError> {
        let malformed = |m: &str| RpmHeaderError::Malformed(m.to_string());
        if data.len() < 16 || data[..3] != RPM_HEADER_MAGIC {
            return Err(malformed("Invalid RPM header magic"));
        }
        let nindex = be_u32(&data[8..]) as usize;
        let hsize = be_u32(&data[12..]) as usize;
        if nindex > RPM_HEADER_TAGS_MAX {
            return Err(RpmHeaderError::OverLimit(format!(
                "{nindex} header entries (rpm allows {RPM_HEADER_TAGS_MAX})"
            )));
        }
        if hsize > RPM_HEADER_DATA_MAX {
            return Err(RpmHeaderError::OverLimit(format!(
                "{hsize}-byte header data (limit {RPM_HEADER_DATA_MAX})"
            )));
        }
        let store_start = 16 + nindex * 16;
        let len = store_start + hsize;
        if len > data.len() {
            return Err(malformed("RPM header truncated"));
        }

        let store = &data[store_start..len];
        let mut entries = HashMap::with_capacity(nindex);
        for i in 0..nindex {
            let e = &data[16 + i * 16..16 + i * 16 + 16];
            let tag = be_u32(e);
            let data_type = be_u32(&e[4..]);
            let offset = be_u32(&e[8..]) as usize;
            let count = be_u32(&e[12..]) as usize;
            let width = element_width(data_type)
                .ok_or_else(|| malformed("header entry with an unknown data type"))?;
            if count == 0 || (data_type != 7 && count > RPM_HEADER_ARRAY_MAX) {
                return Err(malformed("header entry count out of range"));
            }
            if offset >= store.len() || count * width > store.len() - offset {
                return Err(malformed("header entry data outside the store"));
            }
            entries.insert(
                tag,
                HeaderEntry {
                    data_type,
                    offset,
                    count,
                },
            );
        }
        Ok(Self {
            store,
            entries,
            len,
        })
    }

    /// Declared element count of `tag` (0 when absent).
    fn count(&self, tag: u32) -> usize {
        self.entries.get(&tag).map_or(0, |e| e.count)
    }

    /// The tag's (first) string value; `None` when absent or empty. For an
    /// I18N string this is the untranslated (C locale) value.
    fn string(&self, tag: u32) -> Option<String> {
        let e = self.entries.get(&tag)?;
        self.store[e.offset..]
            .split(|&b| b == 0)
            .next()
            .map(|s| String::from_utf8_lossy(s).into_owned())
            .filter(|s| !s.is_empty())
    }

    /// Every string of a STRING_ARRAY/I18NSTRING tag (a plain STRING yields
    /// one element), at most `max`. Empty when absent. Every returned string
    /// must be NUL-terminated inside the store — as rpm's `dataLength`
    /// demands — or the header is malformed.
    fn string_array_n(
        &self,
        tag: u32,
        max: usize,
    ) -> std::result::Result<Vec<String>, RpmHeaderError> {
        let Some(e) = self.entries.get(&tag) else {
            return Ok(Vec::new());
        };
        let n = match e.data_type {
            RPM_STRING_ARRAY_TYPE | RPM_I18NSTRING_TYPE => e.count,
            _ => 1,
        }
        .min(max);
        let mut out = Vec::with_capacity(n);
        let mut rest = &self.store[e.offset..];
        while out.len() < n {
            let Some(nul) = rest.iter().position(|&b| b == 0) else {
                return Err(RpmHeaderError::Malformed(
                    "string array runs past the header store".into(),
                ));
            };
            out.push(String::from_utf8_lossy(&rest[..nul]).into_owned());
            rest = &rest[nul + 1..];
        }
        Ok(out)
    }

    fn string_array(&self, tag: u32) -> std::result::Result<Vec<String>, RpmHeaderError> {
        self.string_array_n(tag, usize::MAX)
    }

    /// Up to `max` values of an integer tag, widened to u64. Empty when
    /// absent or not an integer type (bounds were verified by `parse`).
    fn ints_n(&self, tag: u32, max: usize) -> Vec<u64> {
        let Some(e) = self.entries.get(&tag) else {
            return Vec::new();
        };
        let width = match e.data_type {
            RPM_INT8_TYPE => 1,
            RPM_INT16_TYPE => 2,
            RPM_INT32_TYPE => 4,
            RPM_INT64_TYPE => 8,
            _ => return Vec::new(),
        };
        let n = e.count.min(max);
        self.store[e.offset..e.offset + n * width]
            .chunks_exact(width)
            .map(|c| c.iter().fold(0u64, |acc, &b| (acc << 8) | u64::from(b)))
            .collect()
    }

    fn int(&self, tag: u32) -> Option<u64> {
        self.ints_n(tag, 1).into_iter().next()
    }
}

// Dependency sense flags (rpmsenseFlags) used by createrepo_c's mapping.
const RPMSENSE_LESS: u64 = 1 << 1;
const RPMSENSE_GREATER: u64 = 1 << 2;
const RPMSENSE_EQUAL: u64 = 1 << 3;
const RPMSENSE_POSTTRANS: u64 = 1 << 5;
const RPMSENSE_PREREQ: u64 = 1 << 6;
const RPMSENSE_PRETRANS: u64 = 1 << 7;
const RPMSENSE_SCRIPT_PRE: u64 = 1 << 9;
const RPMSENSE_SCRIPT_POST: u64 = 1 << 10;
/// Requirements `createrepo_c` marks `pre="1"` — exactly the mask in its
/// `src/parsehdr.c` ("Calculate pre value"): PREREQ | SCRIPT_PRE |
/// POSTTRANS | PRETRANS | SCRIPT_POST. `%preun`/`%postun` and
/// RPMSENSE_KEYRING are NOT in it (rpm's own `isInstallPreReq` differs;
/// the repodata contract is createrepo_c's).
const RPMSENSE_PRE_MASK: u64 = RPMSENSE_PREREQ
    | RPMSENSE_SCRIPT_PRE
    | RPMSENSE_SCRIPT_POST
    | RPMSENSE_PRETRANS
    | RPMSENSE_POSTTRANS;

/// `createrepo_c`'s `cr_flag_to_str` over the comparison bits.
fn sense_flag_str(flags: u64) -> Option<&'static str> {
    match flags & (RPMSENSE_LESS | RPMSENSE_GREATER | RPMSENSE_EQUAL) {
        f if f == RPMSENSE_LESS => Some("LT"),
        f if f == RPMSENSE_GREATER => Some("GT"),
        f if f == RPMSENSE_EQUAL => Some("EQ"),
        f if f == RPMSENSE_LESS | RPMSENSE_EQUAL => Some("LE"),
        f if f == RPMSENSE_GREATER | RPMSENSE_EQUAL => Some("GE"),
        _ => None,
    }
}

/// Split `[epoch:]version[-release]` the way `createrepo_c`'s
/// `cr_str_to_evr` (`src/misc.c`) does: an epoch is the text before the
/// first `:` and must be numeric (`None` = bad epoch, which createrepo_c
/// answers by skipping the dependency); a missing or empty epoch is `"0"`;
/// the release is whatever follows the FIRST `-` after the epoch. Empty
/// version/release parts are absent.
fn split_evr(evr: &str) -> Option<(String, Option<String>, Option<String>)> {
    let (epoch, rest) = match evr.split_once(':') {
        Some((e, rest)) => {
            // strtol semantics: optional leading whitespace and sign.
            let digits = e.trim_start().trim_start_matches(['+', '-']);
            if !e.is_empty() && (digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit())) {
                return None;
            }
            (if e.is_empty() { "0" } else { e }.to_string(), rest)
        }
        None => ("0".to_string(), evr),
    };
    let (ver, rel) = match rest.split_once('-') {
        Some((v, r)) => (v, Some(r.to_string()).filter(|r| !r.is_empty())),
        None => (rest, None),
    };
    Some((epoch, Some(ver.to_string()).filter(|v| !v.is_empty()), rel))
}

/// `createrepo_c`'s primary-file predicate: files that go into
/// `primary.xml` (so file requirements resolve without `filelists.xml`).
pub fn is_primary_file(path: &str) -> bool {
    path.starts_with("/etc/") || path == "/usr/lib/sendmail" || path.contains("bin/")
}

/// One dependency exactly as the header states it.
struct RawDep {
    name: String,
    flags: u64,
    evr: String,
}

impl RawDep {
    /// createrepo_c's `depnfv` key: name, flag string and the RAW version
    /// string concatenated (so `= 1.0` and `= 0:1.0` are different keys).
    fn nfv_key(&self) -> String {
        format!(
            "{}{}{}",
            self.name,
            sense_flag_str(self.flags).unwrap_or(""),
            self.evr
        )
    }

    /// The `<rpm:entry>`; `None` for a bad (non-numeric) epoch, which
    /// createrepo_c skips. Version attributes only accompany a flag.
    fn entry(&self) -> Option<RpmEntry> {
        let flag_str = sense_flag_str(self.flags);
        let mut entry = RpmEntry {
            name: self.name.clone(),
            flags: flag_str.map(str::to_string),
            ..Default::default()
        };
        if !self.evr.is_empty() {
            let (epoch, ver, rel) = split_evr(&self.evr)?;
            if flag_str.is_some() {
                entry.epoch = Some(epoch);
                entry.ver = ver;
                entry.rel = rel;
            }
        }
        Some(entry)
    }
}

/// Read one dependency list (names plus the parallel flags and versions,
/// never more of those than there are names). Empty names are dropped.
fn raw_deps(
    h: &HeaderIndex<'_>,
    name_tag: u32,
    flags_tag: u32,
    version_tag: u32,
) -> std::result::Result<Vec<RawDep>, RpmHeaderError> {
    let names = h.string_array(name_tag)?;
    let flags = h.ints_n(flags_tag, names.len());
    let versions = h.string_array_n(version_tag, names.len())?;
    Ok(names
        .into_iter()
        .enumerate()
        .filter(|(_, name)| !name.is_empty())
        .map(|(i, name)| RawDep {
            name,
            flags: flags.get(i).copied().unwrap_or(0),
            evr: versions.get(i).cloned().unwrap_or_default(),
        })
        .collect())
}

/// A non-requires list: every well-formed entry, header order.
fn plain_entries(raw: Vec<RawDep>) -> Vec<RpmEntry> {
    raw.iter().filter_map(RawDep::entry).collect()
}

/// The requires list, with `createrepo_c`'s filters in its order
/// (`src/parsehdr.c`): `rpmlib(...)` pseudo-requirements dropped; a
/// requirement on one of the package's own primary files dropped; a
/// requirement whose name+flags+raw-version key the package itself provides
/// dropped; `pre` computed; a requirement identical (flags, raw version,
/// pre) to the LAST one emitted under the same name dropped; bad epochs
/// dropped. All lookups are hashed, so the cost is linear in the list.
fn requires_entries(
    raw: Vec<RawDep>,
    provided: &std::collections::HashSet<String>,
    own_files: &std::collections::HashSet<&str>,
) -> Vec<RpmEntry> {
    let mut last_by_name: HashMap<String, (Option<&'static str>, String, bool)> = HashMap::new();
    let mut out = Vec::with_capacity(raw.len());
    for d in raw {
        if d.name.starts_with("rpmlib(") {
            continue;
        }
        if d.name.starts_with('/')
            && own_files.contains(d.name.as_str())
            && is_primary_file(&d.name)
        {
            continue;
        }
        if provided.contains(&d.nfv_key()) {
            continue;
        }
        let pre = d.flags & RPMSENSE_PRE_MASK != 0;
        let flag_str = sense_flag_str(d.flags);
        if last_by_name
            .get(&d.name)
            .is_some_and(|(f, v, p)| *f == flag_str && *v == d.evr && *p == pre)
        {
            continue;
        }
        let Some(mut entry) = d.entry() else {
            continue;
        };
        if pre {
            entry.pre = Some("1".to_string());
        }
        last_by_name.insert(d.name, (flag_str, d.evr, pre));
        out.push(entry);
    }
    out
}

/// The package's file list in header order, typed the way `createrepo_c`
/// types `<file>` elements (`dir`, `ghost`, or plain). Entries with an
/// empty basename are dropped.
fn file_entries(h: &HeaderIndex<'_>) -> std::result::Result<Vec<RpmFileEntry>, RpmHeaderError> {
    const S_IFMT: u64 = 0o170000;
    const S_IFDIR: u64 = 0o040000;
    const RPMFILE_GHOST: u64 = 1 << 6;

    let basenames = h.string_array(RPMTAG_BASENAMES)?;
    let n;
    let paths: Vec<Option<String>> = if basenames.is_empty() {
        let old = h.string_array(RPMTAG_OLDFILENAMES)?;
        n = old.len();
        old.into_iter()
            .map(|p| Some(p).filter(|p| !p.is_empty()))
            .collect()
    } else {
        n = basenames.len();
        let dirnames = h.string_array(RPMTAG_DIRNAMES)?;
        let dirindexes = h.ints_n(RPMTAG_DIRINDEXES, n);
        basenames
            .into_iter()
            .enumerate()
            .map(|(i, base)| {
                if base.is_empty() {
                    return None;
                }
                let dir = dirindexes
                    .get(i)
                    .and_then(|&d| dirnames.get(d as usize))
                    .map(String::as_str)
                    .unwrap_or("");
                Some(format!("{dir}{base}"))
            })
            .collect()
    };
    let modes = h.ints_n(RPMTAG_FILEMODES, n);
    let fflags = h.ints_n(RPMTAG_FILEFLAGS, n);
    Ok(paths
        .into_iter()
        .enumerate()
        .filter_map(|(i, path)| {
            let path = path?;
            let kind = if modes.get(i).is_some_and(|m| m & S_IFMT == S_IFDIR) {
                Some("dir")
            } else if fflags.get(i).is_some_and(|f| f & RPMFILE_GHOST != 0) {
                Some("ghost")
            } else {
                None
            };
            Some(RpmFileEntry {
                path,
                kind: kind.map(str::to_string),
            })
        })
        .collect())
}

/// Repodata-only fields of an RPM header, beyond [`RpmMetadata`] (#3801).
/// Stored under the `repodata` key of the artifact's `artifact_metadata` so
/// `primary.xml`/`filelists.xml` can be rendered without re-reading packages.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct RpmRepodataInfo {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epoch: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub packager: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub buildhost: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build_time: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub installed_size: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub archive_size: Option<u64>,
    pub header_start: u64,
    pub header_end: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub provides: Vec<RpmEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requires: Vec<RpmEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conflicts: Vec<RpmEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub obsoletes: Vec<RpmEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub suggests: Vec<RpmEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub enhances: Vec<RpmEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub recommends: Vec<RpmEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub supplements: Vec<RpmEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub files: Vec<RpmFileEntry>,
}

impl Default for RpmHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl FormatHandler for RpmHandler {
    fn format(&self) -> RepositoryFormat {
        RepositoryFormat::Rpm
    }

    async fn parse_metadata(&self, path: &str, content: &Bytes) -> Result<serde_json::Value> {
        let info = Self::parse_path(path)?;

        let mut metadata = serde_json::json!({
            "operation": format!("{:?}", info.operation),
        });

        if let Some(name) = &info.name {
            metadata["name"] = serde_json::Value::String(name.clone());
        }

        if let Some(version) = &info.version {
            metadata["version"] = serde_json::Value::String(version.clone());
        }

        if let Some(release) = &info.release {
            metadata["release"] = serde_json::Value::String(release.clone());
        }

        if let Some(arch) = &info.arch {
            metadata["arch"] = serde_json::Value::String(arch.clone());
        }

        // Parse RPM header if this is a package
        if !content.is_empty() && matches!(info.operation, RpmOperation::Package) {
            if let Ok(rpm_meta) = Self::parse_rpm_header(content) {
                metadata["rpm"] = serde_json::to_value(&rpm_meta)?;
            }
        }

        Ok(metadata)
    }

    async fn validate(&self, path: &str, content: &Bytes) -> Result<()> {
        let info = Self::parse_path(path)?;

        // Validate RPM packages
        if !content.is_empty() && matches!(info.operation, RpmOperation::Package) {
            let rpm_meta = Self::parse_rpm_header(content)?;

            // Verify name matches
            if let Some(path_name) = &info.name {
                if !rpm_meta.name.is_empty() && &rpm_meta.name != path_name {
                    return Err(AppError::Validation(format!(
                        "Package name mismatch: path says '{}' but RPM says '{}'",
                        path_name, rpm_meta.name
                    )));
                }
            }
        }

        Ok(())
    }

    async fn generate_index(&self) -> Result<Option<Vec<(String, Bytes)>>> {
        // Repodata is generated on demand
        Ok(None)
    }
}

/// RPM path info
#[derive(Debug)]
pub struct RpmPathInfo {
    pub name: Option<String>,
    pub version: Option<String>,
    pub release: Option<String>,
    pub arch: Option<String>,
    pub operation: RpmOperation,
}

/// RPM operation type
#[derive(Debug)]
pub enum RpmOperation {
    RepoMd,
    Primary,
    Filelists,
    Other,
    Comps,
    UpdateInfo,
    Package,
}

/// RPM package metadata
#[derive(Debug, Serialize, Deserialize)]
pub struct RpmMetadata {
    pub name: String,
    pub version: String,
    pub release: String,
    pub arch: String,
    #[serde(default)]
    pub summary: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub license: Option<String>,
    #[serde(default)]
    pub group: Option<String>,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub size: Option<u64>,
    #[serde(default)]
    pub source_rpm: Option<String>,
    #[serde(default)]
    pub provides: Vec<String>,
    #[serde(default)]
    pub requires: Vec<String>,
    // Scriptlet bodies and their interpreters (#4033). Skipped by serde: the
    // whole struct is stored as artifact metadata by `parse_metadata`, and
    // script text belongs in `package_install_scripts`, not there.
    #[serde(skip)]
    pub pre_install: Option<String>,
    #[serde(skip)]
    pub post_install: Option<String>,
    #[serde(skip)]
    pub pre_uninstall: Option<String>,
    #[serde(skip)]
    pub post_uninstall: Option<String>,
    #[serde(skip)]
    pub pre_install_prog: Option<String>,
    #[serde(skip)]
    pub post_install_prog: Option<String>,
    #[serde(skip)]
    pub pre_uninstall_prog: Option<String>,
    #[serde(skip)]
    pub post_uninstall_prog: Option<String>,
}

/// Repomd.xml structure
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename = "repomd")]
pub struct RepoMd {
    #[serde(rename = "@xmlns")]
    pub xmlns: String,
    #[serde(rename = "@xmlns:rpm")]
    pub xmlns_rpm: String,
    pub revision: String,
    #[serde(rename = "data")]
    pub data: Vec<RepoMdData>,
}

/// Repomd data entry
#[derive(Debug, Serialize, Deserialize)]
pub struct RepoMdData {
    #[serde(rename = "@type")]
    pub data_type: String,
    pub checksum: RepoMdChecksum,
    #[serde(rename = "open-checksum")]
    pub open_checksum: Option<RepoMdChecksum>,
    pub location: RepoMdLocation,
    pub timestamp: i64,
    pub size: u64,
    #[serde(rename = "open-size")]
    pub open_size: Option<u64>,
}

/// Repomd checksum
#[derive(Debug, Serialize, Deserialize)]
pub struct RepoMdChecksum {
    #[serde(rename = "@type")]
    pub checksum_type: String,
    #[serde(rename = "$value")]
    pub value: String,
}

/// Repomd location
#[derive(Debug, Serialize, Deserialize)]
pub struct RepoMdLocation {
    #[serde(rename = "@href")]
    pub href: String,
}

/// Generate repomd.xml
pub fn generate_repomd(data: Vec<RepoMdData>) -> Result<String> {
    let repomd = RepoMd {
        xmlns: "http://linux.duke.edu/metadata/repo".to_string(),
        xmlns_rpm: "http://linux.duke.edu/metadata/rpm".to_string(),
        revision: chrono::Utc::now().timestamp().to_string(),
        data,
    };

    xml_to_string(&repomd)
        .map_err(|e| AppError::Internal(format!("Failed to generate repomd.xml: {}", e)))
}

/// Primary.xml package entry
#[derive(Debug, Serialize, Deserialize)]
pub struct PrimaryPackage {
    #[serde(rename = "@type")]
    pub pkg_type: String,
    pub name: String,
    pub arch: String,
    pub version: PrimaryVersion,
    pub checksum: RepoMdChecksum,
    pub summary: String,
    pub description: String,
    pub packager: Option<String>,
    pub url: Option<String>,
    pub time: PrimaryTime,
    pub size: PrimarySize,
    pub location: RepoMdLocation,
    pub format: PrimaryFormat,
}

/// Primary version
#[derive(Debug, Serialize, Deserialize)]
pub struct PrimaryVersion {
    #[serde(rename = "@epoch")]
    pub epoch: String,
    #[serde(rename = "@ver")]
    pub ver: String,
    #[serde(rename = "@rel")]
    pub rel: String,
}

/// Primary time
#[derive(Debug, Serialize, Deserialize)]
pub struct PrimaryTime {
    #[serde(rename = "@file")]
    pub file: i64,
    #[serde(rename = "@build")]
    pub build: i64,
}

/// Primary size
#[derive(Debug, Serialize, Deserialize)]
pub struct PrimarySize {
    #[serde(rename = "@package")]
    pub package: u64,
    #[serde(rename = "@installed")]
    pub installed: u64,
    #[serde(rename = "@archive")]
    pub archive: u64,
}

/// Primary format section
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct PrimaryFormat {
    #[serde(rename = "rpm:license")]
    pub license: Option<String>,
    #[serde(rename = "rpm:vendor")]
    pub vendor: Option<String>,
    #[serde(rename = "rpm:group")]
    pub group: Option<String>,
    #[serde(rename = "rpm:buildhost")]
    pub buildhost: Option<String>,
    #[serde(rename = "rpm:sourcerpm")]
    pub sourcerpm: Option<String>,
}

#[cfg(ak_test_shard = "services-2")]
#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // parse_rpm_filename tests
    // ========================================================================

    #[test]
    fn test_parse_rpm_filename() {
        let info = RpmHandler::parse_rpm_filename("nginx-1.24.0-1.el9.x86_64.rpm").unwrap();
        assert_eq!(info.name, Some("nginx".to_string()));
        assert_eq!(info.version, Some("1.24.0".to_string()));
        assert_eq!(info.release, Some("1.el9".to_string()));
        assert_eq!(info.arch, Some("x86_64".to_string()));
        assert!(matches!(info.operation, RpmOperation::Package));
    }

    #[test]
    fn test_parse_rpm_filename_complex() {
        let info = RpmHandler::parse_rpm_filename("python3-numpy-1.24.2-4.el9.x86_64.rpm").unwrap();
        assert_eq!(info.name, Some("python3-numpy".to_string()));
        assert_eq!(info.version, Some("1.24.2".to_string()));
        assert_eq!(info.release, Some("4.el9".to_string()));
    }

    #[test]
    fn test_parse_rpm_filename_noarch() {
        let info = RpmHandler::parse_rpm_filename("bash-completion-2.11-5.el9.noarch.rpm").unwrap();
        assert_eq!(info.name, Some("bash-completion".to_string()));
        assert_eq!(info.version, Some("2.11".to_string()));
        assert_eq!(info.release, Some("5.el9".to_string()));
        assert_eq!(info.arch, Some("noarch".to_string()));
    }

    #[test]
    fn test_parse_rpm_filename_src() {
        let info = RpmHandler::parse_rpm_filename("nginx-1.24.0-1.el9.src.rpm").unwrap();
        assert_eq!(info.name, Some("nginx".to_string()));
        assert_eq!(info.arch, Some("src".to_string()));
    }

    #[test]
    fn test_parse_rpm_filename_i686() {
        let info = RpmHandler::parse_rpm_filename("glibc-2.34-60.el9.i686.rpm").unwrap();
        assert_eq!(info.name, Some("glibc".to_string()));
        assert_eq!(info.arch, Some("i686".to_string()));
    }

    #[test]
    fn test_parse_rpm_filename_aarch64() {
        let info = RpmHandler::parse_rpm_filename("kernel-5.14.0-1.el9.aarch64.rpm").unwrap();
        assert_eq!(info.name, Some("kernel".to_string()));
        assert_eq!(info.arch, Some("aarch64".to_string()));
    }

    #[test]
    fn test_parse_rpm_filename_no_arch_dot() {
        // Missing dot before arch means rsplit_once('.') returns None
        let result = RpmHandler::parse_rpm_filename("invalidname.rpm");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_rpm_filename_too_few_hyphens() {
        // Only 1 hyphen after removing arch: rsplitn(3, '-') gives 2 parts, not 3
        let result = RpmHandler::parse_rpm_filename("name-1.0.x86_64.rpm");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_rpm_filename_many_hyphens_in_name() {
        let info = RpmHandler::parse_rpm_filename("a-b-c-d-1.0-1.el9.x86_64.rpm").unwrap();
        assert_eq!(info.name, Some("a-b-c-d".to_string()));
        assert_eq!(info.version, Some("1.0".to_string()));
        assert_eq!(info.release, Some("1.el9".to_string()));
    }

    // ========================================================================
    // parse_path tests
    // ========================================================================

    #[test]
    fn test_parse_path_repomd() {
        let info = RpmHandler::parse_path("repodata/repomd.xml").unwrap();
        assert!(matches!(info.operation, RpmOperation::RepoMd));
        assert!(info.name.is_none());
        assert!(info.version.is_none());
        assert!(info.release.is_none());
        assert!(info.arch.is_none());
    }

    #[test]
    fn test_parse_path_repomd_nested() {
        let info = RpmHandler::parse_path("centos/9/repodata/repomd.xml").unwrap();
        assert!(matches!(info.operation, RpmOperation::RepoMd));
    }

    #[test]
    fn test_parse_path_primary() {
        let info = RpmHandler::parse_path("repodata/abc123-primary.xml.gz").unwrap();
        assert!(matches!(info.operation, RpmOperation::Primary));
    }

    #[test]
    fn test_parse_path_filelists() {
        let info = RpmHandler::parse_path("repodata/abc123-filelists.xml.gz").unwrap();
        assert!(matches!(info.operation, RpmOperation::Filelists));
    }

    #[test]
    fn test_parse_path_other() {
        let info = RpmHandler::parse_path("repodata/abc123-other.xml.gz").unwrap();
        assert!(matches!(info.operation, RpmOperation::Other));
    }

    #[test]
    fn test_parse_path_comps() {
        let info = RpmHandler::parse_path("repodata/comps.xml").unwrap();
        assert!(matches!(info.operation, RpmOperation::Comps));
    }

    #[test]
    fn test_parse_path_updateinfo() {
        let info = RpmHandler::parse_path("repodata/updateinfo.xml.gz").unwrap();
        assert!(matches!(info.operation, RpmOperation::UpdateInfo));
    }

    #[test]
    fn test_parse_path_repodata_unknown_defaults_to_repomd() {
        let info = RpmHandler::parse_path("repodata/something-unknown.xml").unwrap();
        assert!(matches!(info.operation, RpmOperation::RepoMd));
    }

    #[test]
    fn test_parse_path_package() {
        let info = RpmHandler::parse_path("Packages/nginx-1.24.0-1.el9.x86_64.rpm").unwrap();
        assert!(matches!(info.operation, RpmOperation::Package));
        assert_eq!(info.name, Some("nginx".to_string()));
    }

    #[test]
    fn test_parse_path_direct_rpm() {
        let info = RpmHandler::parse_path("nginx-1.24.0-1.el9.x86_64.rpm").unwrap();
        assert!(matches!(info.operation, RpmOperation::Package));
        assert_eq!(info.name, Some("nginx".to_string()));
    }

    #[test]
    fn test_parse_path_leading_slash() {
        let info = RpmHandler::parse_path("/repodata/repomd.xml").unwrap();
        assert!(matches!(info.operation, RpmOperation::RepoMd));
    }

    #[test]
    fn test_parse_path_invalid() {
        let result = RpmHandler::parse_path("some/random/path.txt");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_path_empty_after_strip() {
        let result = RpmHandler::parse_path("just/a/dir/");
        assert!(result.is_err());
    }

    // ========================================================================
    // parse_repodata_operation tests (indirectly via parse_path)
    // ========================================================================

    #[test]
    fn test_parse_repodata_operation_primary_with_hash() {
        let info = RpmHandler::parse_path("repodata/a1b2c3d4e5f6-primary.xml.gz").unwrap();
        assert!(matches!(info.operation, RpmOperation::Primary));
    }

    #[test]
    fn test_parse_repodata_operation_filelists_sqlite() {
        let info = RpmHandler::parse_path("repodata/hash-filelists.sqlite.bz2").unwrap();
        assert!(matches!(info.operation, RpmOperation::Filelists));
    }

    // ========================================================================
    // parse_rpm_header tests
    // ========================================================================

    #[test]
    fn test_parse_rpm_header_too_small() {
        let result = RpmHandler::parse_rpm_header(&[0u8; 50]);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("too small"));
    }

    #[test]
    fn test_parse_rpm_header_invalid_magic() {
        let mut data = vec![0u8; 200];
        // Wrong magic
        data[0] = 0x00;
        data[1] = 0x00;
        data[2] = 0x00;
        data[3] = 0x00;
        let result = RpmHandler::parse_rpm_header(&data);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("Invalid RPM magic"));
    }

    #[test]
    fn test_parse_rpm_header_valid_magic_fallback() {
        // Create a minimal RPM with valid magic but no header section after signature
        let mut data = vec![0u8; 200];
        // RPM magic
        data[0] = 0xed;
        data[1] = 0xab;
        data[2] = 0xee;
        data[3] = 0xdb;
        // Major/minor
        data[4] = 3;
        data[5] = 0;
        // Lead name at offset 10: "test-package"
        let name = b"test-package";
        data[10..10 + name.len()].copy_from_slice(name);
        // No valid signature header at offset 96 (leave as zeros)
        // No valid main header either, so it falls back to lead name
        let metadata = RpmHandler::parse_rpm_header(&data).unwrap();
        assert_eq!(metadata.name, "test-package");
        assert_eq!(metadata.version, "");
    }

    #[test]
    fn test_parse_rpm_header_with_signature_and_main_header() {
        // Build a synthetic RPM with magic, signature header, and main header
        let mut data = vec![0u8; 2048];

        // RPM magic
        data[0] = 0xed;
        data[1] = 0xab;
        data[2] = 0xee;
        data[3] = 0xdb;
        data[4] = 3; // major
        data[5] = 0; // minor

        // Lead name at offset 10
        let lead_name = b"pkg-from-lead";
        data[10..10 + lead_name.len()].copy_from_slice(lead_name);

        // Signature header at offset 96
        let sig_offset = 96;
        data[sig_offset] = 0x8e; // RPM_HEADER_MAGIC
        data[sig_offset + 1] = 0xad;
        data[sig_offset + 2] = 0xe8;
        data[sig_offset + 3] = 1; // version
                                  // nindex = 0 (no signature entries)
        data[sig_offset + 8] = 0;
        data[sig_offset + 9] = 0;
        data[sig_offset + 10] = 0;
        data[sig_offset + 11] = 0;
        // hsize = 0
        data[sig_offset + 12] = 0;
        data[sig_offset + 13] = 0;
        data[sig_offset + 14] = 0;
        data[sig_offset + 15] = 0;

        // After signature: offset = 96 + 16 + 0 + 0 = 112, aligned to 8 = 112
        let main_offset = 112;

        // Main header magic
        data[main_offset] = 0x8e;
        data[main_offset + 1] = 0xad;
        data[main_offset + 2] = 0xe8;
        data[main_offset + 3] = 1; // version

        // nindex = 2 (name and version tags)
        data[main_offset + 8] = 0;
        data[main_offset + 9] = 0;
        data[main_offset + 10] = 0;
        data[main_offset + 11] = 2;

        // Store: "mypackage\0" at offset 0, "2.0.1\0" at offset 10
        let store_data = b"mypackage\x002.0.1\x00";
        let hsize = store_data.len();
        data[main_offset + 12] = 0;
        data[main_offset + 13] = 0;
        data[main_offset + 14] = 0;
        data[main_offset + 15] = hsize as u8;

        let index_start = main_offset + 16;

        // Index entry 0: RPMTAG_NAME (1000), type=6 (STRING), offset=0, count=1
        let tag_name: u32 = 1000;
        data[index_start..index_start + 4].copy_from_slice(&tag_name.to_be_bytes());
        data[index_start + 4..index_start + 8].copy_from_slice(&6u32.to_be_bytes());
        data[index_start + 8..index_start + 12].copy_from_slice(&0u32.to_be_bytes());
        data[index_start + 12..index_start + 16].copy_from_slice(&1u32.to_be_bytes());

        // Index entry 1: RPMTAG_VERSION (1001), type=6, offset=10, count=1
        let idx1_start = index_start + 16;
        let tag_version: u32 = 1001;
        data[idx1_start..idx1_start + 4].copy_from_slice(&tag_version.to_be_bytes());
        data[idx1_start + 4..idx1_start + 8].copy_from_slice(&6u32.to_be_bytes());
        data[idx1_start + 8..idx1_start + 12].copy_from_slice(&10u32.to_be_bytes());
        data[idx1_start + 12..idx1_start + 16].copy_from_slice(&1u32.to_be_bytes());

        // Store starts after index entries
        let store_start = index_start + 2 * 16;
        data[store_start..store_start + store_data.len()].copy_from_slice(store_data);

        let metadata = RpmHandler::parse_rpm_header(&data).unwrap();
        assert_eq!(metadata.name, "mypackage");
        assert_eq!(metadata.version, "2.0.1");
    }

    // ========================================================================
    // parse_header_section tests
    // ========================================================================

    #[test]
    fn test_parse_header_section_too_short() {
        let result = RpmHandler::parse_header_section(&[0u8; 10]);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_header_section_invalid_magic() {
        let mut data = vec![0u8; 100];
        data[0] = 0x00;
        let result = RpmHandler::parse_header_section(&data);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("Invalid RPM header"));
    }

    #[test]
    fn test_parse_header_section_truncated() {
        let mut data = vec![0u8; 20];
        // Valid magic
        data[0] = 0x8e;
        data[1] = 0xad;
        data[2] = 0xe8;
        data[3] = 1;
        // nindex = 1
        data[11] = 1;
        // hsize = 255 (bigger than available data)
        data[15] = 255;
        let result = RpmHandler::parse_header_section(&data);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("truncated"));
    }

    #[test]
    fn test_parse_header_section_no_entries() {
        let mut data = vec![0u8; 20];
        data[0] = 0x8e;
        data[1] = 0xad;
        data[2] = 0xe8;
        data[3] = 1;
        // nindex = 0, hsize = 0
        let metadata = RpmHandler::parse_header_section(&data).unwrap();
        assert_eq!(metadata.name, "");
        assert_eq!(metadata.version, "");
    }

    #[test]
    fn test_parse_header_section_with_summary_and_license() {
        // Build a header section with multiple tags
        let store_data = b"pkg\x001.0\x00rel1\x00x86_64\x00A summary\x00MIT\x00";
        let nindex: u32 = 6;
        let hsize = store_data.len() as u32;
        let header_size = 16 + (nindex as usize * 16) + store_data.len();
        let mut data = vec![0u8; header_size];

        // Magic + version
        data[0] = 0x8e;
        data[1] = 0xad;
        data[2] = 0xe8;
        data[3] = 1;
        data[8..12].copy_from_slice(&nindex.to_be_bytes());
        data[12..16].copy_from_slice(&hsize.to_be_bytes());

        // Offsets: "pkg\0" = 0, "1.0\0" = 4, "rel1\0" = 8, "x86_64\0" = 13, "A summary\0" = 20, "MIT\0" = 30
        let offsets = [0u32, 4, 8, 13, 20, 30];
        let tags = [
            RPMTAG_NAME,
            RPMTAG_VERSION,
            RPMTAG_RELEASE,
            RPMTAG_ARCH,
            RPMTAG_SUMMARY,
            RPMTAG_LICENSE,
        ];

        for i in 0..nindex as usize {
            let idx_off = 16 + i * 16;
            data[idx_off..idx_off + 4].copy_from_slice(&tags[i].to_be_bytes());
            data[idx_off + 4..idx_off + 8].copy_from_slice(&6u32.to_be_bytes());
            data[idx_off + 8..idx_off + 12].copy_from_slice(&offsets[i].to_be_bytes());
            data[idx_off + 12..idx_off + 16].copy_from_slice(&1u32.to_be_bytes());
        }

        let store_start = 16 + nindex as usize * 16;
        data[store_start..store_start + store_data.len()].copy_from_slice(store_data);

        let metadata = RpmHandler::parse_header_section(&data).unwrap();
        assert_eq!(metadata.name, "pkg");
        assert_eq!(metadata.version, "1.0");
        assert_eq!(metadata.release, "rel1");
        assert_eq!(metadata.arch, "x86_64");
        assert_eq!(metadata.summary, Some("A summary".to_string()));
        assert_eq!(metadata.license, Some("MIT".to_string()));
    }

    #[test]
    fn test_parse_header_section_empty_optional_fields_become_none() {
        // Only name tag, all others missing -> optional fields should be None
        let store_data = b"mypkg\x00";
        let nindex: u32 = 1;
        let hsize = store_data.len() as u32;
        let header_size = 16 + 16 + store_data.len();
        let mut data = vec![0u8; header_size];

        data[0] = 0x8e;
        data[1] = 0xad;
        data[2] = 0xe8;
        data[3] = 1;
        data[8..12].copy_from_slice(&nindex.to_be_bytes());
        data[12..16].copy_from_slice(&hsize.to_be_bytes());

        let idx_off = 16;
        data[idx_off..idx_off + 4].copy_from_slice(&RPMTAG_NAME.to_be_bytes());
        data[idx_off + 4..idx_off + 8].copy_from_slice(&6u32.to_be_bytes());
        data[idx_off + 8..idx_off + 12].copy_from_slice(&0u32.to_be_bytes());
        data[idx_off + 12..idx_off + 16].copy_from_slice(&1u32.to_be_bytes());

        let store_start = 16 + 16;
        data[store_start..store_start + store_data.len()].copy_from_slice(store_data);

        let metadata = RpmHandler::parse_header_section(&data).unwrap();
        assert_eq!(metadata.name, "mypkg");
        assert!(metadata.summary.is_none());
        assert!(metadata.description.is_none());
        assert!(metadata.license.is_none());
        assert!(metadata.group.is_none());
        assert!(metadata.url.is_none());
        assert!(metadata.size.is_none());
        assert!(metadata.source_rpm.is_none());
        assert!(metadata.provides.is_empty());
        assert!(metadata.requires.is_empty());
    }

    // ========================================================================
    // RpmHandler::new / Default tests
    // ========================================================================

    #[test]
    fn test_rpm_handler_new() {
        let _handler = RpmHandler::new();
    }

    #[test]
    fn test_rpm_handler_default() {
        let _handler = RpmHandler;
    }

    // ========================================================================
    // generate_repomd tests
    // ========================================================================

    #[test]
    fn test_generate_repomd_empty_data() {
        let result = generate_repomd(vec![]);
        assert!(result.is_ok());
        let xml = result.unwrap();
        assert!(xml.contains("repomd"));
    }

    #[test]
    fn test_generate_repomd_with_data() {
        let data = vec![RepoMdData {
            data_type: "primary".to_string(),
            checksum: RepoMdChecksum {
                checksum_type: "sha256".to_string(),
                value: "abc123".to_string(),
            },
            open_checksum: None,
            location: RepoMdLocation {
                href: "repodata/primary.xml.gz".to_string(),
            },
            timestamp: 1700000000,
            size: 1024,
            open_size: Some(4096),
        }];
        let result = generate_repomd(data);
        assert!(result.is_ok());
        let xml = result.unwrap();
        assert!(xml.contains("primary"));
        assert!(xml.contains("abc123"));
    }

    // ========================================================================
    // parse_rpm_repodata_info (#3801)
    // ========================================================================

    /// See `tests/fixtures/ak-deps-test.spec`.
    const DEPS_RPM: &[u8] = include_bytes!("../../tests/fixtures/ak-deps-test-1.5-3.noarch.rpm");
    const META_RPM: &[u8] = include_bytes!("../../tests/fixtures/ak-meta-test-1.0-1.noarch.rpm");

    fn entry(name: &str) -> RpmEntry {
        RpmEntry {
            name: name.to_string(),
            ..Default::default()
        }
    }

    fn versioned(name: &str, flags: &str, epoch: &str, ver: &str, rel: Option<&str>) -> RpmEntry {
        RpmEntry {
            name: name.to_string(),
            flags: Some(flags.to_string()),
            epoch: Some(epoch.to_string()),
            ver: Some(ver.to_string()),
            rel: rel.map(str::to_string),
            pre: None,
        }
    }

    fn pre(mut e: RpmEntry) -> RpmEntry {
        e.pre = Some("1".to_string());
        e
    }

    #[test]
    fn test_repodata_info_requires_follow_createrepo_c_rules() {
        let info = RpmHandler::parse_rpm_repodata_info(DEPS_RPM).unwrap();
        // Header order; rpmlib() dropped; the requirement on the package's
        // own /usr/bin file dropped; the self-satisfied config() requirement
        // dropped; pre="1" for pre/post/pretrans/posttrans but not preun; the
        // plain and the (post) coreutils requirement both kept.
        assert_eq!(
            info.requires,
            vec![
                pre(entry("/bin/sh")),
                entry("/usr/bin/sh"),
                pre(entry("ak-posttrans-dep")),
                pre(entry("ak-pretrans-dep")),
                entry("ak-preun-dep"),
                versioned("bash", "GE", "0", "4.2", None),
                entry("coreutils"),
                pre(entry("coreutils")),
                versioned("glibc-common", "LT", "3", "2.40", Some("1")),
                entry("openssl11-custom-libs"),
                pre(entry("shadow-utils")),
            ]
        );
    }

    #[test]
    fn test_repodata_info_provides_conflicts_obsoletes_weak() {
        let info = RpmHandler::parse_rpm_repodata_info(DEPS_RPM).unwrap();
        assert_eq!(
            info.provides,
            vec![
                versioned("ak-deps-test", "EQ", "2", "1.5", Some("3")),
                versioned("ak-deps-virtual", "EQ", "0", "1.0", None),
                versioned("config(ak-deps-test)", "EQ", "2", "1.5", Some("3")),
                entry("webserver"),
            ]
        );
        assert_eq!(
            info.conflicts,
            vec![versioned("ak-old-conflict", "LE", "0", "0.9", None)]
        );
        assert_eq!(
            info.obsoletes,
            vec![versioned("ak-legacy-tool", "LT", "0", "1.0", Some("5"))]
        );
        assert_eq!(info.recommends, vec![entry("ak-extra")]);
        assert_eq!(info.suggests, vec![entry("ak-docs")]);
        assert!(info.supplements.is_empty() && info.enhances.is_empty());
    }

    #[test]
    fn test_repodata_info_scalars_files_and_header_range() {
        let info = RpmHandler::parse_rpm_repodata_info(DEPS_RPM).unwrap();
        assert_eq!(info.epoch, Some(2));
        assert_eq!(info.vendor.as_deref(), Some("Artifact Keeper"));
        assert_eq!(info.buildhost.as_deref(), Some("ak-fixture-host"));
        assert_eq!(
            info.packager.as_deref(),
            Some("AK Tests <tests@example.invalid>")
        );
        assert_eq!(info.build_time, Some(1_790_000_000));
        assert_eq!(info.installed_size, Some(30));
        assert_eq!(info.archive_size, Some(688));
        assert_eq!((info.header_start, info.header_end), (4504, 8081));
        let files: Vec<(&str, Option<&str>)> = info
            .files
            .iter()
            .map(|f| (f.path.as_str(), f.kind.as_deref()))
            .collect();
        assert_eq!(
            files,
            vec![
                ("/etc/ak-deps", Some("dir")),
                ("/etc/ak-deps/ak.conf", None),
                ("/etc/ak-deps/state.db", Some("ghost")),
                ("/usr/bin/ak-deps-tool", None),
                ("/usr/share/ak-deps/README", None),
            ]
        );
    }

    #[test]
    fn test_repodata_info_package_without_deps() {
        // Only rpmlib() requires, which are all omitted; the self-provide stays.
        let info = RpmHandler::parse_rpm_repodata_info(META_RPM).unwrap();
        assert!(info.requires.is_empty(), "{:?}", info.requires);
        assert_eq!(
            info.provides,
            vec![versioned("ak-meta-test", "EQ", "0", "1.0", Some("1"))]
        );
        assert!(info.files.is_empty());
        assert_eq!(info.epoch, None);
    }

    #[test]
    fn test_parse_rpm_header_reads_full_dependency_arrays_and_size() {
        // The old reader returned only the first element of each array and
        // could not read integer tags at all.
        let meta = RpmHandler::parse_rpm_header(DEPS_RPM).unwrap();
        assert_eq!(meta.provides.len(), 4, "{:?}", meta.provides);
        assert!(meta.requires.iter().any(|r| r == "openssl11-custom-libs"));
        assert_eq!(meta.size, Some(30));
    }

    #[test]
    fn test_header_bytes_needed() {
        assert_eq!(RpmHandler::header_bytes_needed(&DEPS_RPM[..50]), None);
        // Knowing only the signature header tells us where the main header
        // intro ends; knowing the intro tells us where the header ends.
        let partial = RpmHandler::header_bytes_needed(&DEPS_RPM[..200]).unwrap();
        assert!(partial > 200);
        assert_eq!(
            RpmHandler::header_bytes_needed(&DEPS_RPM[..partial]),
            Some(8081)
        );
        assert_eq!(RpmHandler::header_bytes_needed(DEPS_RPM), Some(8081));
        // The header prefix alone is enough to parse.
        assert!(RpmHandler::parse_rpm_repodata_info(&DEPS_RPM[..8081]).is_ok());
        assert!(RpmHandler::parse_rpm_repodata_info(&DEPS_RPM[..8000]).is_err());
    }

    #[test]
    fn test_split_evr_and_sense_flags() {
        let evr = |e: &str, v: &str, r: Option<&str>| {
            Some((e.to_string(), Some(v.to_string()), r.map(str::to_string)))
        };
        assert_eq!(split_evr("3:2.40-1"), evr("3", "2.40", Some("1")));
        assert_eq!(split_evr("1.0"), evr("0", "1.0", None));
        // createrepo_c's cr_str_to_evr splits at the FIRST hyphen.
        assert_eq!(split_evr("1.0-2-3"), evr("0", "1.0", Some("2-3")));
        assert_eq!(split_evr(":1.0"), evr("0", "1.0", None));
        assert_eq!(split_evr("1.0-"), evr("0", "1.0", None));
        // Non-numeric epoch: createrepo_c skips the whole dependency.
        assert_eq!(split_evr("x:1.0"), None);
        assert_eq!(split_evr("1a:1.0"), None);
        assert_eq!(sense_flag_str(RPMSENSE_LESS | RPMSENSE_EQUAL), Some("LE"));
        assert_eq!(sense_flag_str(RPMSENSE_GREATER), Some("GT"));
        assert_eq!(sense_flag_str(0), None);
    }

    #[test]
    fn test_hostile_header_sizes_do_not_panic() {
        let mut data = DEPS_RPM[..200].to_vec();
        // Signature header nindex = u32::MAX.
        data[104..108].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(RpmHandler::parse_rpm_repodata_info(&data).is_err());
        let _ = RpmHandler::parse_rpm_header(&data);
        let _ = RpmHandler::header_bytes_needed(&data);
    }

    // ========================================================================
    // Hostile headers: rpm's own limits (lib/header.cc hdrblobVerifyInfo)
    // plus a total element budget bound the work; every guard answers with
    // a clean Err, never a panic, an out-of-bounds read or unbounded output.
    // ========================================================================

    /// One header structure: intro (magic, version, nindex, hsize), index
    /// entries `(tag, type, offset, count)`, then `store` verbatim.
    fn hostile_header(entries: &[(u32, u32, u32, u32)], store: &[u8]) -> Vec<u8> {
        let mut h = vec![0x8e, 0xad, 0xe8, 1, 0, 0, 0, 0];
        h.extend_from_slice(&(entries.len() as u32).to_be_bytes());
        h.extend_from_slice(&(store.len() as u32).to_be_bytes());
        for &(tag, ty, off, count) in entries {
            for v in [tag, ty, off, count] {
                h.extend_from_slice(&v.to_be_bytes());
            }
        }
        h.extend_from_slice(store);
        h
    }

    /// Lead + empty signature header + `main` (which lands at offset 112).
    fn hostile_package(main: &[u8]) -> Vec<u8> {
        let mut p = vec![0u8; 96];
        p[..4].copy_from_slice(&RPM_MAGIC);
        p[4] = 3;
        p.extend_from_slice(&hostile_header(&[], &[]));
        p.extend_from_slice(main);
        p
    }

    fn assert_malformed(main: &[u8]) {
        assert!(
            matches!(HeaderIndex::parse(main), Err(RpmHeaderError::Malformed(_))),
            "header must be rejected as malformed"
        );
        let pkg = hostile_package(main);
        assert!(matches!(
            RpmHandler::parse_rpm_repodata_info(&pkg),
            Err(RpmHeaderError::Malformed(_))
        ));
        assert!(RpmHandler::parse_rpm_header(&pkg).is_err());
    }

    #[test]
    fn test_hostile_entry_offset_past_store_is_rejected() {
        // Offset exactly at the end of the store (offset == hsize), and far
        // past it: rpm's hdrchkRange / dataLength reject both.
        let store = b"pkg\0";
        assert_malformed(&hostile_header(&[(RPMTAG_NAME, 6, 4, 1)], store));
        assert_malformed(&hostile_header(&[(RPMTAG_VERSION, 6, u32::MAX, 1)], store));
    }

    #[test]
    fn test_hostile_counts_are_rejected() {
        let store = [0u8, 0, 0, 7, 0, 0, 0, 9];
        // INT32 array running past the store; u32::MAX count; zero count;
        // unknown type; string array count > remaining bytes.
        assert_malformed(&hostile_header(
            &[(RPMTAG_EPOCH, RPM_INT32_TYPE, 0, 3)],
            &store,
        ));
        assert_malformed(&hostile_header(
            &[(RPMTAG_REQUIREFLAGS, RPM_INT32_TYPE, 4, u32::MAX)],
            &store,
        ));
        assert_malformed(&hostile_header(
            &[(RPMTAG_REQUIRENAME, RPM_STRING_ARRAY_TYPE, 0, u32::MAX)],
            &store,
        ));
        assert_malformed(&hostile_header(
            &[(RPMTAG_EPOCH, RPM_INT32_TYPE, 0, 0)],
            &store,
        ));
        assert_malformed(&hostile_header(&[(RPMTAG_EPOCH, 42, 0, 1)], &store));
        assert_malformed(&hostile_header(
            &[(RPMTAG_LONGSIZE, RPM_INT64_TYPE, 4, 1)],
            &store,
        ));
        // A string array whose declared strings are not all NUL-terminated
        // inside the store (count fits the byte bound, strings do not).
        let pkg = hostile_package(&hostile_header(
            &[(RPMTAG_REQUIRENAME, RPM_STRING_ARRAY_TYPE, 0, 3)],
            b"ab\0cd",
        ));
        assert!(matches!(
            RpmHandler::parse_rpm_repodata_info(&pkg),
            Err(RpmHeaderError::Malformed(_))
        ));
    }

    #[test]
    fn test_hostile_rpm_header_limits_are_over_limit() {
        // nindex over rpm's HEADER_TAGS_MAX, hsize over the data cap: both
        // decided from the 16-byte intro, before anything else is read.
        let mut many = vec![0x8e, 0xad, 0xe8, 1, 0, 0, 0, 0];
        many.extend_from_slice(&(RPM_HEADER_TAGS_MAX as u32 + 1).to_be_bytes());
        many.extend_from_slice(&0u32.to_be_bytes());
        assert!(matches!(
            HeaderIndex::parse(&many),
            Err(RpmHeaderError::OverLimit(_))
        ));
        let mut big = vec![0x8e, 0xad, 0xe8, 1, 0, 0, 0, 0, 0, 0, 0, 0];
        big.extend_from_slice(&(RPM_HEADER_DATA_MAX as u32 + 1).to_be_bytes());
        assert!(matches!(
            HeaderIndex::parse(&big),
            Err(RpmHeaderError::OverLimit(_))
        ));
        let pkg = hostile_package(&many);
        assert!(matches!(
            RpmHandler::parse_rpm_repodata_info(&pkg),
            Err(RpmHeaderError::OverLimit(_))
        ));
    }

    /// Every list tag aliasing the SAME bytes: each tag is individually in
    /// bounds, but together they would materialize millions of entries. The
    /// shared budget rejects the header before any list is built.
    #[test]
    fn test_hostile_aliased_tags_hit_the_element_budget() {
        // 8 MiB zero-filled store: 8M empty strings available to EVERY tag.
        let store = vec![0u8; 8 * 1024 * 1024];
        let n = store.len() as u32;
        let entries: Vec<(u32, u32, u32, u32)> = REPODATA_LIST_TAGS
            .iter()
            .map(|&t| {
                (
                    t,
                    RPM_STRING_ARRAY_TYPE,
                    0,
                    n.min(RPM_HEADER_ARRAY_MAX as u32),
                )
            })
            .collect();
        let pkg = hostile_package(&hostile_header(&entries, &store));
        match RpmHandler::parse_rpm_repodata_info(&pkg) {
            Err(RpmHeaderError::OverLimit(m)) => assert!(m.contains("entries"), "{m}"),
            other => panic!("expected the element budget to reject, got {other:?}"),
        }
        // A single tag just over the budget is enough on its own.
        let one = [(
            RPMTAG_BASENAMES,
            RPM_STRING_ARRAY_TYPE,
            0,
            RPM_MAX_LIST_ELEMENTS as u32 + 1,
        )];
        let pkg = hostile_package(&hostile_header(&one, &store));
        assert!(matches!(
            RpmHandler::parse_rpm_repodata_info(&pkg),
            Err(RpmHeaderError::OverLimit(_))
        ));
        // parse_rpm_header does not materialize over-budget lists either.
        let meta = RpmHandler::parse_rpm_header(&hostile_package(&hostile_header(
            &[
                (
                    RPMTAG_PROVIDENAME,
                    RPM_STRING_ARRAY_TYPE,
                    0,
                    RPM_MAX_LIST_ELEMENTS as u32,
                ),
                (RPMTAG_REQUIRENAME, RPM_STRING_ARRAY_TYPE, 0, 1),
            ],
            &store,
        )))
        .unwrap();
        assert!(meta.provides.is_empty() && meta.requires.is_empty());
    }

    /// Within budget, empty names and basenames are dropped rather than
    /// emitted as `<rpm:entry name=""/>` / `<file></file>`.
    #[test]
    fn test_empty_names_and_basenames_are_dropped() {
        let store = b"\0\0real\0/d/\0";
        let pkg = hostile_package(&hostile_header(
            &[
                (RPMTAG_REQUIRENAME, RPM_STRING_ARRAY_TYPE, 0, 3),
                (RPMTAG_BASENAMES, RPM_STRING_ARRAY_TYPE, 0, 3),
                (RPMTAG_DIRNAMES, RPM_STRING_ARRAY_TYPE, 7, 1),
            ],
            store,
        ));
        let info = RpmHandler::parse_rpm_repodata_info(&pkg).unwrap();
        assert_eq!(info.requires, vec![entry("real")]);
        let files: Vec<&str> = info.files.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(files, vec!["real"], "no dirindexes: bare basename");
    }

    /// createrepo_c 1.2.1 on `ak-selfprov-test.spec`: a requirement is
    /// dropped only when a provide has the identical name + flags + RAW
    /// version string (`= 1.0` dropped, `= 0:1.0` kept); a duplicate is
    /// judged against the last one kept under that name; `(pre,preun)` is
    /// pre; the own non-primary file requirement stays.
    #[test]
    fn test_self_provided_requires_match_createrepo_c() {
        const SELFPROV_RPM: &[u8] =
            include_bytes!("../../tests/fixtures/ak-selfprov-test-2.0-1.noarch.rpm");
        let info = RpmHandler::parse_rpm_repodata_info(SELFPROV_RPM).unwrap();
        assert_eq!(
            info.requires,
            vec![
                entry("/usr/bin/sh"),
                entry("/usr/share/ak-selfprov/README"),
                entry("ak-dup"),
                pre(entry("ak-mixed-dep")),
                entry("ak-selfprov-test"),
                entry("ak-virt"),
                versioned("ak-virt", "EQ", "0", "1.0", None),
            ]
        );
    }

    /// The quadratic-dedup scenario: requires and provides alias one list of
    /// distinct names. With hashed lookups this is linear; every require is
    /// satisfied by the identical provide and dropped.
    #[test]
    fn test_aliased_requires_and_provides_dedup_linearly() {
        let mut store = Vec::new();
        let n = 100_000u32;
        for i in 0..n {
            store.extend_from_slice(format!("{i:07}\0").as_bytes());
        }
        let pkg = hostile_package(&hostile_header(
            &[
                (RPMTAG_PROVIDENAME, RPM_STRING_ARRAY_TYPE, 0, n),
                (RPMTAG_REQUIRENAME, RPM_STRING_ARRAY_TYPE, 0, n),
            ],
            &store,
        ));
        let info = RpmHandler::parse_rpm_repodata_info(&pkg).unwrap();
        assert_eq!(info.provides.len(), n as usize);
        assert!(info.requires.is_empty());
    }

    #[test]
    fn test_hostile_type_mismatch_yields_nothing() {
        // EPOCH/SIZE declared as strings, a flags array declared as BIN, and
        // a provides list declared INT32 (read as one string, not `count`).
        let store = b"12\0abc\0";
        let main = hostile_header(
            &[
                (RPMTAG_EPOCH, 6, 0, 1),
                (RPMTAG_SIZE, RPM_STRING_ARRAY_TYPE, 0, 2),
                (RPMTAG_PROVIDEFLAGS, 7, 0, 2),
                (RPMTAG_PROVIDENAME, RPM_INT32_TYPE, 3, 1),
            ],
            store,
        );
        let h = HeaderIndex::parse(&main).unwrap();
        assert!(h.ints_n(RPMTAG_EPOCH, usize::MAX).is_empty());
        assert!(h.ints_n(RPMTAG_SIZE, usize::MAX).is_empty());
        assert!(h.ints_n(RPMTAG_PROVIDEFLAGS, usize::MAX).is_empty());
        assert_eq!(
            h.string_array(RPMTAG_PROVIDENAME).unwrap(),
            vec!["abc".to_string()]
        );

        let info = RpmHandler::parse_rpm_repodata_info(&hostile_package(&main)).unwrap();
        assert_eq!(info.epoch, None);
        assert_eq!(info.installed_size, None);
        assert_eq!(info.provides, vec![entry("abc")]);
    }

    #[test]
    fn test_header_bytes_needed_stops_on_corrupt_main_magic() {
        // Valid lead + signature, then 16 bytes that are not a header: no
        // amount of extra bytes can help, so report what we already have.
        let mut pkg = hostile_package(&[]);
        pkg.extend_from_slice(&[
            0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 0, 0, 0, 0, 1, 0xff, 0xff, 0xff, 0xff,
        ]);
        pkg.extend_from_slice(&[0u8; 32]);
        assert_eq!(RpmHandler::header_bytes_needed(&pkg), Some(pkg.len()));
        assert!(RpmHandler::parse_rpm_repodata_info(&pkg).is_err());
        let meta = RpmHandler::parse_rpm_header(&pkg).unwrap();
        assert_eq!(meta.name, "", "falls back to the (empty) lead name");
    }
}
