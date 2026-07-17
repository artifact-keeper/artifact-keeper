//! Upstream metadata sync adapters for curation.
//!
//! Each adapter knows how to fetch and parse a format's upstream package index
//! into a list of CurationPackageEntry records for insertion into curation_packages.

use quick_xml::events::Event;
use quick_xml::reader::Reader;
use quick_xml::XmlVersion;
use serde::{Deserialize, Serialize};

/// Per-`<package>` raw-byte ceiling enforced BEFORE a block is trusted (#2358
/// A-hardened). A single hostile `<package>` cannot force an unbounded parse.
const MAX_PACKAGE_BYTES: u64 = 256 * 1024;

/// Per-list entry ceiling (`<rpm:provides>`, `<file>`, …). A hostile package
/// declaring millions of dependency entries is dropped rather than parsed into
/// an unbounded Vec.
const MAX_LIST_ENTRIES: usize = 20_000;

/// A parsed package entry from an upstream index.
#[derive(Debug, Clone)]
pub struct CurationPackageEntry {
    pub format: String,
    pub package_name: String,
    pub version: String,
    pub release: Option<String>,
    pub architecture: Option<String>,
    pub checksum_sha256: Option<String>,
    pub upstream_path: String,
    pub metadata: serde_json::Value,
    /// The STRUCTURED, validated package metadata this entry was parsed from
    /// (#2358 RPM Phase-3, A-hardened). Captured as a typed [`RpmPackageMetadata`]
    /// (serialized to JSONB) rather than a raw upstream XML string, so a curated
    /// snapshot publish re-serializes it CANONICALLY under AK's escaping and AK's
    /// `<location>` — attacker-influenced upstream markup can never be signed
    /// verbatim. `None` for formats that carry no reusable RPM metadata (e.g.
    /// Debian `Packages` index entries).
    pub primary_metadata: Option<serde_json::Value>,
}

// ---------------------------------------------------------------------------
// Structured RPM primary.xml metadata (#2358 A-hardened)
//
// Everything dnf needs for depsolve + install, captured as typed fields so the
// publish path can re-serialize it canonically. NOTHING attacker-controlled is
// ever re-emitted as raw markup: every field below is escaped on the way out,
// and the upstream `<location href>` is deliberately NOT captured here (the
// `upstream_path` column keeps it for the fetch step; the published location is
// rebuilt purely from validated NEVRA).
// ---------------------------------------------------------------------------

fn default_epoch() -> String {
    "0".to_string()
}

/// A single `<rpm:entry>` in a provides/requires/… list.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RpmEntry {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flags: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epoch: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ver: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rel: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pre: Option<String>,
}

/// A `<file>` entry inside `<format>`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RpmFileEntry {
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
}

/// The `<checksum type=… pkgid=…>value</checksum>` element.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RpmChecksum {
    #[serde(rename = "type")]
    pub checksum_type: String,
    #[serde(default)]
    pub pkgid: bool,
    pub value: String,
}

/// The `<size package=… installed=… archive=…/>` element.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RpmSize {
    #[serde(default)]
    pub package: u64,
    #[serde(default)]
    pub installed: u64,
    #[serde(default)]
    pub archive: u64,
}

/// The `<time file=… build=…/>` element.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RpmTime {
    #[serde(default)]
    pub file: i64,
    #[serde(default)]
    pub build: i64,
}

/// The `<format>` subtree.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RpmFormat {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub license: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub buildhost: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sourcerpm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header_range: Option<(u64, u64)>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub provides: Vec<RpmEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requires: Vec<RpmEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conflicts: Vec<RpmEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub obsoletes: Vec<RpmEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub recommends: Vec<RpmEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub suggests: Vec<RpmEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub supplements: Vec<RpmEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub enhances: Vec<RpmEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub files: Vec<RpmFileEntry>,
}

/// Everything dnf needs to depsolve + install a package, captured structurally.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RpmPackageMetadata {
    pub name: String,
    pub arch: String,
    #[serde(default = "default_epoch")]
    pub epoch: String,
    pub version: String,
    pub release: String,
    #[serde(default)]
    pub summary: String,
    #[serde(default)]
    pub description: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub packager: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    pub checksum: RpmChecksum,
    #[serde(default)]
    pub size: RpmSize,
    #[serde(default)]
    pub time: RpmTime,
    #[serde(default)]
    pub format: RpmFormat,
}

/// Which dependency list a stream of `<rpm:entry>` elements belongs to.
#[derive(Clone, Copy)]
enum ListKind {
    Provides,
    Requires,
    Conflicts,
    Obsoletes,
    Recommends,
    Suggests,
    Supplements,
    Enhances,
}

impl ListKind {
    fn from_local(name: &[u8]) -> Option<Self> {
        match name {
            b"provides" => Some(Self::Provides),
            b"requires" => Some(Self::Requires),
            b"conflicts" => Some(Self::Conflicts),
            b"obsoletes" => Some(Self::Obsoletes),
            b"recommends" => Some(Self::Recommends),
            b"suggests" => Some(Self::Suggests),
            b"supplements" => Some(Self::Supplements),
            b"enhances" => Some(Self::Enhances),
            _ => None,
        }
    }
}

/// Which simple text element is currently being collected.
#[derive(Clone, Copy, PartialEq)]
enum TextTarget {
    Name,
    Arch,
    Summary,
    Description,
    Packager,
    Url,
    Checksum,
    License,
    Vendor,
    Group,
    BuildHost,
    SourceRpm,
    File,
}

/// Accumulates a single package as its subtree is walked.
#[derive(Default)]
struct PkgBuilder {
    name: String,
    arch: String,
    epoch: String,
    version: String,
    release: String,
    summary: String,
    description: String,
    packager: Option<String>,
    url: Option<String>,
    checksum_type: String,
    checksum_pkgid: bool,
    checksum_value: String,
    size: RpmSize,
    time: RpmTime,
    format: RpmFormat,
    /// The upstream `<location href>` — retained ONLY to populate the
    /// `upstream_path` column (the fetch step needs it). It is deliberately kept
    /// out of the trusted [`RpmPackageMetadata`] so it can never be re-emitted
    /// into the AK-signed primary.xml.
    location_href: String,
}

impl PkgBuilder {
    fn finish(self) -> Option<CurationPackageEntry> {
        // Fail closed: the security- and install-critical fields must all be
        // present, or the package is dropped (never stored/published).
        if self.name.is_empty()
            || self.version.is_empty()
            || self.arch.is_empty()
            || self.release.is_empty()
            || self.checksum_value.is_empty()
        {
            return None;
        }

        let meta = RpmPackageMetadata {
            name: self.name,
            arch: self.arch,
            epoch: if self.epoch.is_empty() {
                default_epoch()
            } else {
                self.epoch
            },
            version: self.version,
            release: self.release,
            summary: self.summary,
            description: self.description,
            packager: self.packager,
            url: self.url,
            checksum: RpmChecksum {
                checksum_type: self.checksum_type,
                pkgid: self.checksum_pkgid,
                value: self.checksum_value,
            },
            size: self.size,
            time: self.time,
            format: self.format,
        };

        let primary_metadata = serde_json::to_value(&meta).ok()?;

        Some(CurationPackageEntry {
            format: "rpm".to_string(),
            package_name: meta.name.clone(),
            version: meta.version.clone(),
            release: Some(meta.release.clone()),
            architecture: Some(meta.arch.clone()),
            checksum_sha256: Some(meta.checksum.value.clone()),
            // The upstream location is kept on the existing `upstream_path`
            // column for the fetch step, but NEVER inside the trusted structured
            // metadata (so it can never be re-emitted into the signed primary).
            upstream_path: self.location_href,
            metadata: serde_json::json!({
                "name": meta.name,
                "version": meta.version,
                "release": meta.release,
                "arch": meta.arch,
                "description": meta.description,
            }),
            primary_metadata: Some(primary_metadata),
        })
    }
}

/// Parse RPM primary.xml content into package entries (#2358 A-hardened).
///
/// Uses a `quick_xml` event reader with entity expansion OFF (its default — DTD
/// / custom-entity resolution is never enabled) so a hostile upstream cannot
/// smuggle markup through entities. Each `<package type="rpm">` is captured into
/// a typed [`RpmPackageMetadata`]; any package whose XML does not parse cleanly,
/// whose required fields are missing, or that exceeds [`MAX_PACKAGE_BYTES`] is
/// DROPPED (fail-closed) and never stored. The upstream `<location href>` is
/// captured only for the `upstream_path` fetch column, never into the metadata.
pub fn parse_rpm_primary_xml(xml: &str) -> Vec<CurationPackageEntry> {
    // Default config: entity expansion is OFF (no DTD / custom-entity
    // resolution) and `check_end_names` is ON, so a mismatched/raw end tag in a
    // text node is a hard parse error that fails the package closed.
    let mut reader = Reader::from_str(xml);

    let mut entries = Vec::new();

    // Per-package parse state. `pkg` is Some only while inside a `<package>`.
    let mut pkg: Option<PkgBuilder> = None;
    let mut pkg_start: u64 = 0;
    let mut dropped = false; // this package hit an over-limit / bad condition
    let mut in_format = false;
    let mut cur_list: Option<ListKind> = None;
    let mut text_target: Option<TextTarget> = None;

    loop {
        let pos = reader.buffer_position();
        match reader.read_event() {
            // A malformed document/package fails closed: stop ingesting here so
            // nothing past the corruption is trusted.
            Err(_) => break,
            Ok(Event::Eof) => break,

            Ok(Event::Start(e)) | Ok(Event::Empty(e)) => {
                let local_name = e.local_name();
                let local = local_name.as_ref();

                match local {
                    b"package" => {
                        // Only capture rpm packages; a non-rpm `type` is ignored.
                        let is_rpm = attr_value(&e, b"type").map(|t| t == "rpm").unwrap_or(true);
                        if is_rpm {
                            pkg = Some(PkgBuilder::default());
                            pkg_start = pos;
                            dropped = false;
                            in_format = false;
                            cur_list = None;
                            text_target = None;
                        }
                    }
                    _ if pkg.is_none() => {}
                    b"name" if !in_format => text_target = Some(TextTarget::Name),
                    b"arch" => text_target = Some(TextTarget::Arch),
                    b"summary" => text_target = Some(TextTarget::Summary),
                    b"description" => text_target = Some(TextTarget::Description),
                    b"packager" => text_target = Some(TextTarget::Packager),
                    b"url" => text_target = Some(TextTarget::Url),
                    b"version" if !in_format => {
                        if let Some(p) = pkg.as_mut() {
                            if let Some(v) = attr_value(&e, b"epoch") {
                                p.epoch = v;
                            }
                            if let Some(v) = attr_value(&e, b"ver") {
                                p.version = v;
                            }
                            if let Some(v) = attr_value(&e, b"rel") {
                                p.release = v;
                            }
                        }
                    }
                    b"checksum" => {
                        if let Some(p) = pkg.as_mut() {
                            if let Some(v) = attr_value(&e, b"type") {
                                p.checksum_type = v;
                            }
                            p.checksum_pkgid = attr_value(&e, b"pkgid")
                                .map(|v| v.eq_ignore_ascii_case("yes") || v == "1")
                                .unwrap_or(false);
                            p.checksum_value.clear();
                        }
                        text_target = Some(TextTarget::Checksum);
                    }
                    b"size" => {
                        if let Some(p) = pkg.as_mut() {
                            p.size = RpmSize {
                                package: attr_u64(&e, b"package"),
                                installed: attr_u64(&e, b"installed"),
                                archive: attr_u64(&e, b"archive"),
                            };
                        }
                    }
                    b"time" => {
                        if let Some(p) = pkg.as_mut() {
                            p.time = RpmTime {
                                file: attr_i64(&e, b"file"),
                                build: attr_i64(&e, b"build"),
                            };
                        }
                    }
                    // The upstream `<location href>` is captured ONLY for the
                    // `upstream_path` fetch column, never into the trusted
                    // metadata: the published location is rebuilt from NEVRA.
                    b"location" => {
                        if let Some(p) = pkg.as_mut() {
                            if let Some(href) = attr_value(&e, b"href") {
                                p.location_href = href;
                            }
                        }
                    }
                    b"format" => in_format = true,
                    b"license" if in_format => text_target = Some(TextTarget::License),
                    b"vendor" if in_format => text_target = Some(TextTarget::Vendor),
                    b"group" if in_format => text_target = Some(TextTarget::Group),
                    b"buildhost" if in_format => text_target = Some(TextTarget::BuildHost),
                    b"sourcerpm" if in_format => text_target = Some(TextTarget::SourceRpm),
                    b"header-range" if in_format => {
                        if let Some(p) = pkg.as_mut() {
                            p.format.header_range =
                                Some((attr_u64(&e, b"start"), attr_u64(&e, b"end")));
                        }
                    }
                    b"file" if in_format => {
                        let kind = attr_value(&e, b"type");
                        if let Some(p) = pkg.as_mut() {
                            if p.format.files.len() >= MAX_LIST_ENTRIES {
                                dropped = true;
                            } else {
                                p.format.files.push(RpmFileEntry {
                                    path: String::new(),
                                    kind,
                                });
                            }
                        }
                        text_target = Some(TextTarget::File);
                    }
                    b"entry" if in_format => {
                        if let Some(list) = cur_list {
                            if let Some(p) = pkg.as_mut() {
                                let entry = RpmEntry {
                                    name: attr_value(&e, b"name").unwrap_or_default(),
                                    flags: attr_value(&e, b"flags"),
                                    epoch: attr_value(&e, b"epoch"),
                                    ver: attr_value(&e, b"ver"),
                                    rel: attr_value(&e, b"rel"),
                                    pre: attr_value(&e, b"pre"),
                                };
                                push_entry(&mut p.format, list, entry, &mut dropped);
                            }
                        }
                    }
                    other if in_format => {
                        if let Some(list) = ListKind::from_local(other) {
                            cur_list = Some(list);
                        }
                    }
                    _ => {}
                }
            }

            // Raw text between markup. quick-xml surfaces entity references
            // SEPARATELY (see `GeneralRef` below), so this is literal content.
            Ok(Event::Text(t)) => {
                if let (Some(target), Some(p)) = (text_target, pkg.as_mut()) {
                    match t.xml10_content() {
                        Ok(txt) => apply_text(p, target, &txt),
                        Err(_) => dropped = true,
                    }
                }
            }

            // CDATA is literal text; it is escaped again on the way out, so it
            // cannot inject markup into the published document.
            Ok(Event::CData(c)) => {
                if let (Some(target), Some(p)) = (text_target, pkg.as_mut()) {
                    match c.decode() {
                        Ok(txt) => apply_text(p, target, &txt),
                        Err(_) => dropped = true,
                    }
                }
            }

            // An entity reference. Entity EXPANSION IS OFF: we resolve ONLY the
            // five predefined XML entities and numeric character references
            // ourselves. Any other (custom/DTD-defined) entity fails the package
            // CLOSED rather than being expanded — a hostile upstream cannot
            // smuggle markup or exfiltrate a file through a custom entity.
            Ok(Event::GeneralRef(r)) => {
                if pkg.is_some() {
                    match resolve_builtin_ref(&r) {
                        Some(txt) => {
                            if let (Some(target), Some(p)) = (text_target, pkg.as_mut()) {
                                apply_text(p, target, &txt);
                            }
                        }
                        None => dropped = true,
                    }
                }
            }

            Ok(Event::End(e)) => {
                let local_name = e.local_name();
                let local = local_name.as_ref();
                match local {
                    b"package" => {
                        let over = pos.saturating_sub(pkg_start) > MAX_PACKAGE_BYTES;
                        if let Some(builder) = pkg.take() {
                            if !dropped && !over {
                                if let Some(entry) = builder.finish() {
                                    entries.push(entry);
                                }
                            }
                        }
                        in_format = false;
                        cur_list = None;
                    }
                    b"format" => {
                        in_format = false;
                        cur_list = None;
                    }
                    b"provides" | b"requires" | b"conflicts" | b"obsoletes" | b"recommends"
                    | b"suggests" | b"supplements" | b"enhances" => {
                        cur_list = None;
                    }
                    _ => {}
                }
                // Any closing tag ends the current simple-text collection.
                text_target = None;
            }
            _ => {}
        }
    }

    entries
}

fn push_entry(fmt: &mut RpmFormat, list: ListKind, entry: RpmEntry, dropped: &mut bool) {
    let v = match list {
        ListKind::Provides => &mut fmt.provides,
        ListKind::Requires => &mut fmt.requires,
        ListKind::Conflicts => &mut fmt.conflicts,
        ListKind::Obsoletes => &mut fmt.obsoletes,
        ListKind::Recommends => &mut fmt.recommends,
        ListKind::Suggests => &mut fmt.suggests,
        ListKind::Supplements => &mut fmt.supplements,
        ListKind::Enhances => &mut fmt.enhances,
    };
    if v.len() >= MAX_LIST_ENTRIES {
        *dropped = true;
    } else {
        v.push(entry);
    }
}

fn apply_text(p: &mut PkgBuilder, target: TextTarget, txt: &str) {
    match target {
        TextTarget::Name => p.name.push_str(txt),
        TextTarget::Arch => p.arch.push_str(txt),
        TextTarget::Summary => p.summary.push_str(txt),
        TextTarget::Description => p.description.push_str(txt),
        TextTarget::Packager => p.packager.get_or_insert_with(String::new).push_str(txt),
        TextTarget::Url => p.url.get_or_insert_with(String::new).push_str(txt),
        TextTarget::Checksum => p.checksum_value.push_str(txt),
        TextTarget::License => p
            .format
            .license
            .get_or_insert_with(String::new)
            .push_str(txt),
        TextTarget::Vendor => p
            .format
            .vendor
            .get_or_insert_with(String::new)
            .push_str(txt),
        TextTarget::Group => p.format.group.get_or_insert_with(String::new).push_str(txt),
        TextTarget::BuildHost => p
            .format
            .buildhost
            .get_or_insert_with(String::new)
            .push_str(txt),
        TextTarget::SourceRpm => p
            .format
            .sourcerpm
            .get_or_insert_with(String::new)
            .push_str(txt),
        TextTarget::File => {
            if let Some(last) = p.format.files.last_mut() {
                last.path.push_str(txt);
            }
        }
    }
}

/// Resolve an entity reference to its literal text, allowing ONLY the five
/// predefined XML entities and numeric character references. Returns `None` for
/// any custom/DTD-defined entity so the caller fails the package closed —
/// this is the "entity expansion OFF" guarantee.
fn resolve_builtin_ref(r: &quick_xml::events::BytesRef<'_>) -> Option<String> {
    // Numeric character reference (`&#60;` / `&#x3C;`).
    match r.resolve_char_ref() {
        Ok(Some(c)) => return Some(c.to_string()),
        Err(_) => return None,
        Ok(None) => {}
    }
    // Named reference: only the five XML predefined entities are honoured.
    let name = r.decode().ok()?;
    match name.as_ref() {
        "lt" => Some("<".to_string()),
        "gt" => Some(">".to_string()),
        "amp" => Some("&".to_string()),
        "quot" => Some("\"".to_string()),
        "apos" => Some("'".to_string()),
        _ => None,
    }
}

/// Decode a named attribute's value. `normalized_value` resolves ONLY the
/// predefined XML entities (no custom/DTD entities), and any unresolvable
/// reference yields `None` so the caller fails closed.
fn attr_value(e: &quick_xml::events::BytesStart<'_>, key: &[u8]) -> Option<String> {
    for attr in e.attributes().flatten() {
        if attr.key.as_ref() == key {
            return attr
                .normalized_value(XmlVersion::Explicit1_0)
                .ok()
                .map(|c| c.into_owned());
        }
    }
    None
}

fn attr_u64(e: &quick_xml::events::BytesStart<'_>, key: &[u8]) -> u64 {
    attr_value(e, key)
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0)
}

fn attr_i64(e: &quick_xml::events::BytesStart<'_>, key: &[u8]) -> i64 {
    attr_value(e, key)
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0)
}

/// Parse Debian Packages index content into package entries.
/// Each package is a block of key-value lines separated by blank lines.
pub fn parse_deb_packages_index(content: &str, component: &str) -> Vec<CurationPackageEntry> {
    let mut entries = Vec::new();

    for block in content.split("\n\n") {
        let block = block.trim();
        if block.is_empty() {
            continue;
        }

        let mut name = String::new();
        let mut version = String::new();
        let mut arch = String::new();
        let mut sha256 = String::new();
        let mut filename = String::new();
        let mut description = String::new();

        for line in block.lines() {
            if let Some(v) = line.strip_prefix("Package: ") {
                name = v.trim().to_string();
            } else if let Some(v) = line.strip_prefix("Version: ") {
                version = v.trim().to_string();
            } else if let Some(v) = line.strip_prefix("Architecture: ") {
                arch = v.trim().to_string();
            } else if let Some(v) = line.strip_prefix("SHA256: ") {
                sha256 = v.trim().to_string();
            } else if let Some(v) = line.strip_prefix("Filename: ") {
                filename = v.trim().to_string();
            } else if let Some(v) = line.strip_prefix("Description: ") {
                description = v.trim().to_string();
            }
        }

        if name.is_empty() || version.is_empty() {
            continue;
        }

        entries.push(CurationPackageEntry {
            format: "debian".to_string(),
            package_name: name.clone(),
            version: version.clone(),
            release: None,
            architecture: if arch.is_empty() {
                None
            } else {
                Some(arch.clone())
            },
            checksum_sha256: if sha256.is_empty() {
                None
            } else {
                Some(sha256)
            },
            upstream_path: filename,
            metadata: serde_json::json!({
                "name": name,
                "version": version,
                "arch": arch,
                "component": component,
                "description": description,
            }),
            // Debian entries carry no reusable RPM metadata.
            primary_metadata: None,
        });
    }

    entries
}

// ---------------------------------------------------------------------------
// repomd.xml helpers (minimal, string-scanning; the SIGNED repomd is small and
// its shape is fixed, unlike the attacker-influenced primary.xml above)
// ---------------------------------------------------------------------------

/// The `primary` data reference parsed from an RPM `repomd.xml`.
///
/// In the yum/RPM trust model the signature over `repomd.xml` PINS
/// `primary.xml.gz` through repomd's `<checksum>` (over the compressed file)
/// and `<open-checksum>` (over the decompressed file). Verifying the repomd
/// signature is therefore only half the chain — the fetched `primary.xml.gz`
/// must then be digested and compared to these pinned values before it is
/// parsed/ingested, or an attacker who can tamper the mirrored primary (MITM,
/// CDN/cache poisoning, or replaying a valid signed repomd while serving a
/// malicious primary at the href) defeats the signature (#2357).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RepomdPrimaryRef {
    pub href: String,
    /// `<checksum type="...">` over the compressed `primary.xml.gz`.
    pub checksum_type: Option<String>,
    pub checksum: Option<String>,
    /// `<open-checksum type="...">` over the decompressed `primary.xml`.
    pub open_checksum_type: Option<String>,
    pub open_checksum: Option<String>,
}

/// Read the attribute value of the first `<tag ... attr="value" ...>` inside
/// `block`. Used to pull `type="sha256"` off a checksum element.
fn tag_attr(block: &str, tag_open: &str, attr: &str) -> Option<String> {
    let start = block.find(tag_open)?;
    let after = &block[start + tag_open.len()..];
    // Bound the attribute search to this tag (up to its closing '>').
    let tag_end = after.find('>')?;
    let tag_text = &after[..tag_end];
    let pat = format!("{}=\"", attr);
    let attr_start = tag_text.find(&pat)? + pat.len();
    let rest = &tag_text[attr_start..];
    let attr_end = rest.find('"')?;
    Some(rest[..attr_end].to_string())
}

/// Read the text content of the first `<tag ...>content</tag>` inside `block`.
fn tag_text_content(block: &str, tag_open: &str, tag_close: &str) -> Option<String> {
    let start = block.find(tag_open)?;
    let after = &block[start..];
    let content_start = after.find('>')? + 1;
    let content = &after[content_start..];
    let end = content.find(tag_close)?;
    Some(content[..end].trim().to_string())
}

/// Extract the full `primary` data reference (href + pinned checksums) from an
/// RPM `repomd.xml`. Returns `None` when no primary `<data>` block is present.
///
/// Kept next to [`parse_rpm_primary_xml`] as a pure, table-testable helper so
/// the sync path single-sources the parse logic (#2357 WI-1).
pub fn extract_primary_data(repomd: &str) -> Option<RepomdPrimaryRef> {
    // Tolerate multiple `<data type="primary">` blocks: return the first that
    // carries a `<location href>` (a block without one has nothing to fetch).
    repomd
        .split("<data type=\"primary\">")
        .skip(1)
        .filter_map(|data_block| {
            let block = data_block.split("</data>").next()?;
            // `href` is required — without a location there is nothing to fetch.
            let loc_start = block.find("<location href=\"")?;
            let href_rest = &block[loc_start + "<location href=\"".len()..];
            let href_end = href_rest.find('"')?;
            let href = href_rest[..href_end].to_string();

            // `<checksum type="...">value</checksum>` over the compressed file.
            // NOTE: search for `<checksum` (not a prefix of `<open-checksum`),
            // so the open-checksum element is not accidentally matched here.
            let (checksum_type, checksum) = if block.contains("<checksum") {
                (
                    tag_attr(block, "<checksum", "type"),
                    tag_text_content(block, "<checksum", "</checksum>"),
                )
            } else {
                (None, None)
            };
            let (open_checksum_type, open_checksum) = if block.contains("<open-checksum") {
                (
                    tag_attr(block, "<open-checksum", "type"),
                    tag_text_content(block, "<open-checksum", "</open-checksum>"),
                )
            } else {
                (None, None)
            };

            Some(RepomdPrimaryRef {
                href,
                checksum_type,
                checksum,
                open_checksum_type,
                open_checksum,
            })
        })
        .next()
}

/// Extract the `primary` data file href from an RPM `repomd.xml`. Thin wrapper
/// over [`extract_primary_data`] for callers that only need the location.
pub fn extract_primary_href(repomd: &str) -> Option<String> {
    extract_primary_data(repomd).map(|d| d.href)
}

/// Compute the lowercase hex digest of `bytes` using the named repodata
/// checksum algorithm (`sha256`, `sha`/`sha1`, `sha512`). Returns `None` for an
/// unsupported/unknown algorithm so the caller can fail closed. `sha` and
/// `sha1` are treated as SHA-1 (repodata historically labels SHA-1 as `sha`).
pub fn repodata_hex_digest(algo: &str, bytes: &[u8]) -> Option<String> {
    use sha2::Digest;
    match algo.trim().to_ascii_lowercase().as_str() {
        "sha256" => Some(hex::encode(sha2::Sha256::digest(bytes))),
        "sha512" => Some(hex::encode(sha2::Sha512::digest(bytes))),
        "sha1" | "sha" => Some(hex::encode(sha1::Sha1::digest(bytes))),
        _ => None,
    }
}

/// Fail-closed check that `bytes` matches the declared `(algo, expected)`
/// checksum from a signed repomd. Returns `false` when the algorithm is
/// unsupported, the expected value is empty, or the digests differ (constant
/// factors aside, a straightforward case-insensitive hex compare).
pub fn repodata_checksum_matches(algo: &str, expected_hex: &str, bytes: &[u8]) -> bool {
    let expected = expected_hex.trim();
    if expected.is_empty() {
        return false;
    }
    match repodata_hex_digest(algo, bytes) {
        Some(actual) => actual.eq_ignore_ascii_case(expected),
        None => false,
    }
}

/// Fail-closed decision for the RPM chain-of-trust (#2357): is the fetched
/// compressed `primary.xml.gz` bound to the (signed) repomd via its primary
/// `<checksum>`? Returns `false` when there is no primary ref, no usable
/// checksum, an unsupported algorithm, or the digests differ — so a
/// signature-verified sync ingests nothing unless `primary.xml.gz` matches the
/// checksum the signed repomd pins. Only consulted on the verified path; the
/// unverified (no-key) path stays backward-compatible.
pub fn primary_gz_pinned_by_repomd(
    primary_ref: Option<&RepomdPrimaryRef>,
    gz_bytes: &[u8],
) -> bool {
    match primary_ref {
        Some(d) => match (d.checksum_type.as_deref(), d.checksum.as_deref()) {
            (Some(ct), Some(cv)) => repodata_checksum_matches(ct, cv, gz_bytes),
            _ => false,
        },
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_primary_href_present() {
        let repomd = r#"<?xml version="1.0"?>
<repomd>
  <data type="filelists"><location href="repodata/filelists.xml.gz"/></data>
  <data type="primary"><location href="repodata/1234-primary.xml.gz"/></data>
</repomd>"#;
        assert_eq!(
            extract_primary_href(repomd),
            Some("repodata/1234-primary.xml.gz".to_string())
        );
    }

    #[test]
    fn test_extract_primary_href_absent() {
        let repomd = r#"<repomd>
  <data type="filelists"><location href="repodata/filelists.xml.gz"/></data>
</repomd>"#;
        assert_eq!(extract_primary_href(repomd), None);
        // Empty / malformed input never panics.
        assert_eq!(extract_primary_href(""), None);
        assert_eq!(extract_primary_href("<data type=\"primary\">"), None);
    }

    // A realistic repomd primary block carries the compressed <checksum> that
    // PINS primary.xml.gz plus an <open-checksum> over the decompressed form.
    fn repomd_with_checksums(sha_gz: &str, sha_open: &str) -> String {
        format!(
            r#"<?xml version="1.0"?>
<repomd>
  <data type="filelists"><location href="repodata/filelists.xml.gz"/></data>
  <data type="primary">
    <checksum type="sha256">{sha_gz}</checksum>
    <open-checksum type="sha256">{sha_open}</open-checksum>
    <location href="repodata/abc-primary.xml.gz"/>
    <size>123</size>
  </data>
</repomd>"#
        )
    }

    #[test]
    fn test_extract_primary_data_reads_href_and_checksums() {
        let repomd = repomd_with_checksums("deadbeef", "cafef00d");
        let d = extract_primary_data(&repomd).expect("primary data present");
        assert_eq!(d.href, "repodata/abc-primary.xml.gz");
        assert_eq!(d.checksum_type.as_deref(), Some("sha256"));
        assert_eq!(d.checksum.as_deref(), Some("deadbeef"));
        // The open-checksum must NOT be confused with the compressed checksum.
        assert_eq!(d.open_checksum_type.as_deref(), Some("sha256"));
        assert_eq!(d.open_checksum.as_deref(), Some("cafef00d"));
    }

    #[test]
    fn test_repodata_hex_digest_algorithms() {
        // Known SHA-256 of the empty input pins the algorithm wiring.
        assert_eq!(
            repodata_hex_digest("sha256", b"").unwrap(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert!(repodata_hex_digest("sha1", b"abc").is_some());
        assert!(repodata_hex_digest("sha512", b"abc").is_some());
        // `sha` is the repodata label for SHA-1.
        assert_eq!(
            repodata_hex_digest("sha", b"abc"),
            repodata_hex_digest("sha1", b"abc")
        );
        // Unknown algorithm -> None (caller fails closed).
        assert!(repodata_hex_digest("md5", b"abc").is_none());
    }

    // The HIGH repro at the unit level: the fetched primary.xml.gz is only
    // trusted when it matches the checksum the signed repomd pins.
    #[test]
    fn test_primary_gz_pinned_by_repomd_match_and_mismatch() {
        let primary_gz = b"\x1f\x8b\x08fake-but-fixed-primary-bytes";
        let good = repodata_hex_digest("sha256", primary_gz).unwrap();
        let repomd = repomd_with_checksums(&good, "unused-open");
        let d = extract_primary_data(&repomd);

        // Matching bytes -> pinned (ingest allowed on the verified path).
        assert!(
            primary_gz_pinned_by_repomd(d.as_ref(), primary_gz),
            "primary.xml.gz matching the signed repomd <checksum> must be accepted"
        );

        // TAMPERED bytes (same href, different content) -> REJECTED. This is the
        // finding: a valid repomd signature must not authenticate a mutated
        // primary.
        let tampered = b"\x1f\x8b\x08EVIL-primary-bytes-swapped-by-attacker";
        assert!(
            !primary_gz_pinned_by_repomd(d.as_ref(), tampered),
            "a tampered primary.xml.gz must be rejected (checksum mismatch)"
        );

        // Signed repomd with NO usable primary <checksum> -> fail closed.
        let no_ck =
            r#"<repomd><data type="primary"><location href="repodata/p.xml.gz"/></data></repomd>"#;
        assert!(!primary_gz_pinned_by_repomd(
            extract_primary_data(no_ck).as_ref(),
            primary_gz
        ));

        // Unsupported checksum algorithm in repomd -> fail closed.
        let md5 = r#"<repomd><data type="primary"><checksum type="md5">00</checksum><location href="repodata/p.xml.gz"/></data></repomd>"#;
        assert!(!primary_gz_pinned_by_repomd(
            extract_primary_data(md5).as_ref(),
            primary_gz
        ));

        // No primary ref at all -> fail closed.
        assert!(!primary_gz_pinned_by_repomd(None, primary_gz));
    }

    #[test]
    fn test_parse_rpm_primary_xml() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<metadata xmlns="http://linux.duke.edu/metadata/common" packages="2">
<package type="rpm">
  <name>nginx</name>
  <arch>x86_64</arch>
  <version epoch="0" ver="1.24.0" rel="1.el9"/>
  <checksum type="sha256" pkgid="YES">abc123def456</checksum>
  <location href="Packages/nginx-1.24.0-1.el9.x86_64.rpm"/>
  <description>A high performance web server</description>
</package>
<package type="rpm">
  <name>curl</name>
  <arch>x86_64</arch>
  <version epoch="0" ver="8.5.0" rel="1.el9"/>
  <checksum type="sha256" pkgid="YES">def789ghi012</checksum>
  <location href="Packages/curl-8.5.0-1.el9.x86_64.rpm"/>
  <description>A URL transfer utility</description>
</package>
</metadata>"#;

        let entries = parse_rpm_primary_xml(xml);
        assert_eq!(entries.len(), 2);

        assert_eq!(entries[0].package_name, "nginx");
        assert_eq!(entries[0].version, "1.24.0");
        assert_eq!(entries[0].release.as_deref(), Some("1.el9"));
        assert_eq!(entries[0].architecture.as_deref(), Some("x86_64"));
        assert_eq!(entries[0].checksum_sha256.as_deref(), Some("abc123def456"));
        // The href is kept ONLY on upstream_path (for the fetch step).
        assert_eq!(
            entries[0].upstream_path,
            "Packages/nginx-1.24.0-1.el9.x86_64.rpm"
        );

        assert_eq!(entries[1].package_name, "curl");
        assert_eq!(entries[1].version, "8.5.0");
    }

    // #2358 A-hardened: a full realistic `<package>` round-trips into a typed
    // `RpmPackageMetadata` (provides/requires/size/format/files preserved), and
    // the upstream `<location href>` is NOT part of the trusted metadata.
    #[test]
    fn test_parse_rpm_primary_xml_structured_round_trip() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<metadata xmlns="http://linux.duke.edu/metadata/common" xmlns:rpm="http://linux.duke.edu/metadata/rpm" packages="1">
<package type="rpm">
  <name>nginx</name>
  <arch>x86_64</arch>
  <version epoch="0" ver="1.24.0" rel="1.el9"/>
  <checksum type="sha256" pkgid="YES">abc123def456</checksum>
  <summary>High performance web server</summary>
  <description>nginx is a web server</description>
  <packager>Fedora Project</packager>
  <url>https://nginx.org</url>
  <time file="1700000000" build="1699999999"/>
  <size package="573440" installed="1048576" archive="1050624"/>
  <location href="Packages/nginx-1.24.0-1.el9.x86_64.rpm"/>
  <format>
    <rpm:license>BSD</rpm:license>
    <rpm:vendor>Fedora</rpm:vendor>
    <rpm:group>System</rpm:group>
    <rpm:buildhost>buildhost.example</rpm:buildhost>
    <rpm:sourcerpm>nginx-1.24.0-1.el9.src.rpm</rpm:sourcerpm>
    <rpm:header-range start="4504" end="98765"/>
    <rpm:provides>
      <rpm:entry name="nginx" flags="EQ" epoch="0" ver="1.24.0" rel="1.el9"/>
      <rpm:entry name="webserver"/>
    </rpm:provides>
    <rpm:requires>
      <rpm:entry name="libc.so.6()(64bit)"/>
      <rpm:entry name="openssl-libs" flags="GE" epoch="0" ver="3.0"/>
    </rpm:requires>
    <file>/usr/sbin/nginx</file>
    <file type="dir">/etc/nginx</file>
  </format>
</package>
</metadata>"#;

        let entries = parse_rpm_primary_xml(xml);
        assert_eq!(entries.len(), 1);
        let meta: RpmPackageMetadata =
            serde_json::from_value(entries[0].primary_metadata.clone().unwrap()).unwrap();

        assert_eq!(meta.name, "nginx");
        assert_eq!(meta.arch, "x86_64");
        assert_eq!(meta.epoch, "0");
        assert_eq!(meta.version, "1.24.0");
        assert_eq!(meta.release, "1.el9");
        assert_eq!(meta.summary, "High performance web server");
        assert_eq!(meta.description, "nginx is a web server");
        assert_eq!(meta.packager.as_deref(), Some("Fedora Project"));
        assert_eq!(meta.url.as_deref(), Some("https://nginx.org"));
        assert_eq!(meta.checksum.checksum_type, "sha256");
        assert!(meta.checksum.pkgid);
        assert_eq!(meta.checksum.value, "abc123def456");
        assert_eq!(meta.size.package, 573440);
        assert_eq!(meta.size.installed, 1048576);
        assert_eq!(meta.size.archive, 1050624);
        assert_eq!(meta.time.file, 1700000000);
        assert_eq!(meta.time.build, 1699999999);
        assert_eq!(meta.format.license.as_deref(), Some("BSD"));
        assert_eq!(meta.format.vendor.as_deref(), Some("Fedora"));
        assert_eq!(
            meta.format.sourcerpm.as_deref(),
            Some("nginx-1.24.0-1.el9.src.rpm")
        );
        assert_eq!(meta.format.header_range, Some((4504, 98765)));
        assert_eq!(meta.format.provides.len(), 2);
        assert_eq!(meta.format.provides[0].name, "nginx");
        assert_eq!(meta.format.provides[0].flags.as_deref(), Some("EQ"));
        assert_eq!(meta.format.provides[0].ver.as_deref(), Some("1.24.0"));
        assert_eq!(meta.format.provides[1].name, "webserver");
        assert_eq!(meta.format.requires.len(), 2);
        assert_eq!(meta.format.requires[1].name, "openssl-libs");
        assert_eq!(meta.format.requires[1].flags.as_deref(), Some("GE"));
        assert_eq!(meta.format.files.len(), 2);
        assert_eq!(meta.format.files[0].path, "/usr/sbin/nginx");
        assert_eq!(meta.format.files[1].path, "/etc/nginx");
        assert_eq!(meta.format.files[1].kind.as_deref(), Some("dir"));

        // The structured metadata carries NO upstream location.
        let raw = entries[0].primary_metadata.as_ref().unwrap().to_string();
        assert!(
            !raw.contains("Packages/nginx"),
            "no upstream href in metadata"
        );
    }

    // Fail-closed: an unclosed tag drops the package (never stored).
    #[test]
    fn test_parse_rpm_fail_closed_unclosed_tag() {
        let xml = r#"<metadata>
<package type="rpm">
  <name>evil</name>
  <arch>x86_64</arch>
  <version epoch="0" ver="1.0" rel="1"/>
  <checksum type="sha256" pkgid="YES">deadbeef
</package>
</metadata>"#;
        let entries = parse_rpm_primary_xml(xml);
        assert_eq!(
            entries.len(),
            0,
            "a package with an unclosed tag is dropped"
        );
    }

    // A RAW `</metadata>` inside a text node is a structural error -> the
    // injected package never reaches the store (fail-closed).
    #[test]
    fn test_parse_rpm_fail_closed_raw_breakout_in_text() {
        let xml = r#"<metadata>
<package type="rpm">
  <name>evil</name>
  <arch>x86_64</arch>
  <version epoch="0" ver="1.0" rel="1"/>
  <checksum type="sha256" pkgid="YES">deadbeef</checksum>
  <summary>pwn</metadata><package type="rpm"><name>backdoor</name></summary>
</package>
</metadata>"#;
        let entries = parse_rpm_primary_xml(xml);
        assert!(
            !entries.iter().any(|e| e.package_name == "backdoor"),
            "a raw </metadata> breakout must never inject a package"
        );
    }

    // A `</metadata>` that arrives ESCAPED survives as inert literal text (and
    // is re-escaped by the canonical publish serializer).
    #[test]
    fn test_parse_rpm_escaped_breakout_survives_as_text() {
        let xml = r#"<metadata>
<package type="rpm">
  <name>pkg</name>
  <arch>x86_64</arch>
  <version epoch="0" ver="1.0" rel="1"/>
  <checksum type="sha256" pkgid="YES">deadbeef</checksum>
  <summary>hi &lt;/metadata&gt;&lt;package type="rpm"&gt; injected</summary>
</package>
</metadata>"#;
        let entries = parse_rpm_primary_xml(xml);
        assert_eq!(entries.len(), 1);
        let meta: RpmPackageMetadata =
            serde_json::from_value(entries[0].primary_metadata.clone().unwrap()).unwrap();
        // The escaped breakout is stored as inert literal text.
        assert!(meta.summary.contains("</metadata>"));
        assert_eq!(meta.name, "pkg");
    }

    // Fail-closed: a `<package>` whose raw bytes exceed MAX_PACKAGE_BYTES is
    // dropped before it is trusted; well-formed neighbours still sync.
    #[test]
    fn test_parse_rpm_fail_closed_oversize() {
        let filler = "x".repeat((MAX_PACKAGE_BYTES as usize) + 1024);
        let xml = format!(
            r#"<metadata>
<package type="rpm">
  <name>huge</name>
  <arch>x86_64</arch>
  <version epoch="0" ver="1.0" rel="1"/>
  <checksum type="sha256" pkgid="YES">deadbeef</checksum>
  <description>{filler}</description>
</package>
<package type="rpm">
  <name>small</name>
  <arch>x86_64</arch>
  <version epoch="0" ver="2.0" rel="1"/>
  <checksum type="sha256" pkgid="YES">cafef00d</checksum>
</package>
</metadata>"#
        );
        let entries = parse_rpm_primary_xml(&xml);
        // Only the small package survives; the oversize one is dropped.
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].package_name, "small");
    }

    // A package missing required fields is dropped fail-closed.
    #[test]
    fn test_parse_rpm_skips_incomplete_entries() {
        let xml = r#"<metadata>
<package type="rpm">
  <arch>x86_64</arch>
</package>
</metadata>"#;

        let entries = parse_rpm_primary_xml(xml);
        assert_eq!(entries.len(), 0);
    }

    // The Debian parser carries no reusable RPM metadata.
    #[test]
    fn test_parse_deb_packages_index_has_no_metadata() {
        let content = "Package: nginx\nVersion: 1.24.0-1\nArchitecture: amd64\nFilename: pool/main/n/nginx/nginx_1.24.0-1_amd64.deb\n";
        let entries = parse_deb_packages_index(content, "main");
        assert_eq!(entries.len(), 1);
        assert!(entries[0].primary_metadata.is_none());
    }

    #[test]
    fn test_parse_deb_packages_index() {
        let content = r#"Package: nginx
Version: 1.24.0-1
Architecture: amd64
SHA256: abc123def456
Filename: pool/main/n/nginx/nginx_1.24.0-1_amd64.deb
Description: High performance web server

Package: curl
Version: 8.5.0-2ubuntu1
Architecture: amd64
SHA256: def789ghi012
Filename: pool/main/c/curl/curl_8.5.0-2ubuntu1_amd64.deb
Description: Command line URL transfer tool
"#;

        let entries = parse_deb_packages_index(content, "main");
        assert_eq!(entries.len(), 2);

        assert_eq!(entries[0].package_name, "nginx");
        assert_eq!(entries[0].version, "1.24.0-1");
        assert_eq!(entries[0].architecture.as_deref(), Some("amd64"));
        assert_eq!(
            entries[0].upstream_path,
            "pool/main/n/nginx/nginx_1.24.0-1_amd64.deb"
        );

        assert_eq!(entries[1].package_name, "curl");
        assert_eq!(entries[1].version, "8.5.0-2ubuntu1");
    }

    #[test]
    fn test_parse_deb_skips_incomplete_entries() {
        let content = "Package: incomplete\n\n";
        let entries = parse_deb_packages_index(content, "main");
        assert_eq!(entries.len(), 0);
    }
}
