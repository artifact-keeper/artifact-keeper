//! Locate the embedded root filesystem image of an ISO9660 live medium
//! (#1966).
//!
//! This is deliberately not a general ISO9660 reader. The scan needs one
//! answer: "does this image hold one of a fixed list of files at depth 2,
//! and which byte range of the image is it?" Everything here is a pure
//! function of the artifact bytes with no I/O, no allocation proportional to
//! the input beyond the bounded name buffers, no recursion and no tree walk,
//! so directory loops, relocated directories and deep nesting are never
//! reached, and the whole input surface fits one fuzz target
//! (`backend/fuzz/fuzz_targets/iso_locate.rs` compiles this file on its own).
//!
//! The only names ever matched are the fixed probe names below. Nothing read
//! from the image is used as a path, so neither an ISO9660 name nor a Rock
//! Ridge `NM` entry can make the caller write anywhere: the caller copies the
//! located byte range to a file name of its own choosing.
//!
//! Layout facts relied on (ECMA-119, IEEE P1281 SUSP, P1282 RRIP):
//! - the volume descriptor set starts at byte 32768 (sector 16 of 2048-byte
//!   sectors) whatever the logical block size, each descriptor is 2048 bytes
//!   and carries `CD001` at offset 1;
//! - the primary volume descriptor (type 1) holds the logical block size at
//!   offset 128 and the root directory record at offset 156;
//! - a directory record never crosses a 2048-byte sector, and a zero length
//!   byte pads to the next sector;
//! - Rock Ridge is announced by an `SP` entry in the system use area of the
//!   root's first record, whose last byte is the number of bytes to skip at
//!   the start of every later system use area.
//!
//! The module has no `use crate::` imports, so the fuzz crate can include it
//! by path.

/// Byte offset of the first volume descriptor.
const VOLUME_DESCRIPTOR_START: usize = 16 * SECTOR;

/// ISO9660 sector size. Volume descriptors and directory record padding use
/// it regardless of the logical block size.
const SECTOR: usize = 2048;

/// Most volume descriptors read before giving up on finding the terminator.
/// Real media carry three to five (primary, boot record, Joliet, terminator).
const MAX_VOLUME_DESCRIPTORS: usize = 32;

/// Largest directory extent read for a probe. A real root or `live/`
/// directory is a few KiB; 1 MiB is far above any of them and bounds the
/// work a crafted directory can cause.
pub const MAX_DIRECTORY_EXTENT: u64 = 1024 * 1024;

/// Most system use bytes (the record's own area plus every continuation
/// area) parsed for one directory record.
const MAX_SYSTEM_USE_BYTES: usize = 64 * 1024;

/// Most continuation areas (`CE`) followed for one directory record. Real
/// records need at most one, for a very long `NM`.
const MAX_CONTINUATION_AREAS: usize = 4;

/// Most system use bytes parsed over one whole [`locate_rootfs`] call. Each
/// record is already capped by [`MAX_SYSTEM_USE_BYTES`], but a 1 MiB
/// directory holds about 30,000 records, each of which could point a `CE` at
/// the same large area; this bounds the total work. A real live medium's
/// probes parse a few KiB.
const MAX_TOTAL_SYSTEM_USE_BYTES: usize = 8 * 1024 * 1024;

/// Longest assembled name (Rock Ridge `NM` or ISO9660 identifier) kept for
/// matching. The probe names are short; a longer name can never match and is
/// not accumulated further.
const MAX_NAME_BYTES: usize = 255;

/// The `hsqs` magic every squashfs superblock starts with (little-endian
/// `0x73717368`).
pub const SQUASHFS_MAGIC: &[u8; 4] = b"hsqs";

/// Rootfs locations probed, in order, as `(directory, file)` at depth 2 from
/// the ISO root. Matching is ASCII case-insensitive.
///
/// - Debian live (live-build): `live/filesystem.squashfs`
/// - Ubuntu before 22.10, Mint, other casper media: `casper/filesystem.squashfs`
/// - Fedora and RHEL-family live media: `LiveOS/squashfs.img`
/// - Fedora, RHEL, Rocky and Alma installer media (boot, netinst, DVD): the
///   Anaconda stage-2 image `images/install.img`
pub const ROOTFS_PROBES: &[(&str, &str)] = &[
    ("live", "filesystem.squashfs"),
    ("casper", "filesystem.squashfs"),
    ("LiveOS", "squashfs.img"),
    ("images", "install.img"),
];

/// Markers of the layered casper media Ubuntu ships since 22.10, where the
/// installed system is a stack of squashfs layers rather than one image.
/// Not supported yet: reported as such instead of as "no rootfs".
pub const LAYERED_MARKERS: &[(&str, &str)] = &[
    ("casper", "minimal.squashfs"),
    ("casper", "minimal.standard.squashfs"),
];

/// Where the embedded rootfs image sits inside the ISO.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocatedRootfs {
    /// The probe that matched, `dir/file` as spelled in [`ROOTFS_PROBES`].
    pub probe: String,
    /// Byte offset of the file's data in the ISO.
    pub offset: u64,
    /// Length of the file's data in bytes.
    pub len: u64,
}

/// Why no rootfs image could be located.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocateError {
    /// No ISO9660 volume descriptor at byte 32769.
    NotIso9660,
    /// The image claims to be ISO9660 but a structure the locator needs is
    /// out of bounds or inconsistent.
    Malformed(String),
    /// A well-formed image holding none of the [`ROOTFS_PROBES`].
    NoRootfs,
    /// A rootfs candidate was found in a form the scan does not read
    /// (multi-extent, zisofs-compressed, interleaved, symlinked, ambiguous,
    /// or layered media).
    Unsupported(String),
}

impl core::fmt::Display for LocateError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            LocateError::NotIso9660 => write!(f, "not an ISO9660 image"),
            LocateError::Malformed(why) => write!(f, "malformed ISO9660 image: {}", why),
            LocateError::NoRootfs => {
                write!(f, "no embedded root filesystem image found (probed ")?;
                for (i, (dir, file)) in ROOTFS_PROBES.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}/{}", dir, file)?;
                }
                write!(f, ")")
            }
            LocateError::Unsupported(why) => write!(f, "unsupported ISO9660 rootfs: {}", why),
        }
    }
}

/// True when `data` carries an ISO9660 volume descriptor at sector 16. This
/// is the detection used by the scan: the file name (`.iso`) is never
/// trusted, and a hybrid image (MBR or GPT at offset 0, as every modern live
/// medium is) is still detected.
pub fn is_iso9660(data: &[u8]) -> bool {
    data.get(VOLUME_DESCRIPTOR_START + 1..VOLUME_DESCRIPTOR_START + 6) == Some(b"CD001")
}

/// Locate the embedded rootfs image of an ISO9660 live or installer medium.
pub fn locate_rootfs(data: &[u8]) -> Result<LocatedRootfs, LocateError> {
    if !is_iso9660(data) {
        return Err(LocateError::NotIso9660);
    }
    let volume = Volume::open(data)?;
    let root = volume.root_directory()?;

    for (dir, file) in ROOTFS_PROBES {
        if let Some(found) = volume.probe(root, dir, file)? {
            return Ok(found);
        }
    }
    for (dir, file) in LAYERED_MARKERS {
        if volume.probe(root, dir, file)?.is_some() {
            return Err(LocateError::Unsupported(format!(
                "layered casper media ({}/{}) is not scanned yet",
                dir, file
            )));
        }
    }
    Err(LocateError::NoRootfs)
}

fn malformed(why: &str) -> LocateError {
    LocateError::Malformed(why.to_string())
}

fn le_u16(b: &[u8], at: usize) -> Option<u16> {
    let s = b.get(at..at.checked_add(2)?)?;
    Some(u16::from_le_bytes([s[0], s[1]]))
}

fn le_u32(b: &[u8], at: usize) -> Option<u32> {
    let s = b.get(at..at.checked_add(4)?)?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

/// The primary volume descriptor's view of the image.
struct Volume<'a> {
    data: &'a [u8],
    /// System use bytes this call may still parse
    /// ([`MAX_TOTAL_SYSTEM_USE_BYTES`]).
    su_budget: core::cell::Cell<usize>,
    block_size: u64,
    /// The Rock Ridge skip length from the root's `SP` entry, when the
    /// volume announces Rock Ridge.
    rock_ridge_skip: Option<usize>,
    root_record: Record<'a>,
}

/// One directory's extent as a byte range of the image.
#[derive(Clone, Copy)]
struct Extent {
    start: usize,
    len: usize,
}

impl<'a> Volume<'a> {
    fn open(data: &'a [u8]) -> Result<Self, LocateError> {
        let mut primary: Option<&'a [u8]> = None;
        for i in 0..MAX_VOLUME_DESCRIPTORS {
            let at = VOLUME_DESCRIPTOR_START + i * SECTOR;
            let Some(vd) = data.get(at..at + SECTOR) else {
                return Err(malformed(
                    "volume descriptor set runs past the end of the image",
                ));
            };
            if &vd[1..6] != b"CD001" {
                return Err(malformed("volume descriptor without the CD001 identifier"));
            }
            match vd[0] {
                1 if primary.is_none() => primary = Some(vd),
                255 => break,
                _ => {}
            }
        }
        let pvd = primary.ok_or_else(|| malformed("no primary volume descriptor"))?;

        let block_size = u64::from(le_u16(pvd, 128).unwrap_or(0));
        if !matches!(block_size, 512 | 1024 | 2048) {
            return Err(LocateError::Malformed(format!(
                "logical block size {} is not 512, 1024 or 2048",
                block_size
            )));
        }
        let root_record = Record::parse(&pvd[156..190])
            .ok_or_else(|| malformed("unreadable root directory record"))?;
        if !root_record.is_dir() {
            return Err(malformed("root directory record is not a directory"));
        }

        let mut volume = Volume {
            data,
            su_budget: core::cell::Cell::new(MAX_TOTAL_SYSTEM_USE_BYTES),
            block_size,
            rock_ridge_skip: None,
            root_record,
        };
        // Rock Ridge is announced by `SP` in the system use area of the
        // root directory's first record ("."), read from its own extent.
        let root = volume.directory_extent(&root_record)?;
        volume.rock_ridge_skip = volume.first_record(root).and_then(|dot| dot.sp_skip());
        Ok(volume)
    }

    fn root_directory(&self) -> Result<Extent, LocateError> {
        self.directory_extent(&self.root_record)
    }

    /// Bounds-checked byte range of a record's extent, for a directory.
    fn directory_extent(&self, record: &Record<'_>) -> Result<Extent, LocateError> {
        if u64::from(record.data_len) > MAX_DIRECTORY_EXTENT {
            return Err(LocateError::Malformed(format!(
                "directory extent of {} bytes exceeds the {} byte limit",
                record.data_len, MAX_DIRECTORY_EXTENT
            )));
        }
        let (start, len) = self
            .extent_range(record)
            .ok_or_else(|| malformed("directory extent runs past the end of the image"))?;
        Ok(Extent {
            start: usize::try_from(start).map_err(|_| malformed("directory extent offset"))?,
            len: usize::try_from(len).map_err(|_| malformed("directory extent length"))?,
        })
    }

    /// The `(offset, len)` byte range of a record's data, when it lies fully
    /// inside the image.
    fn extent_range(&self, record: &Record<'_>) -> Option<(u64, u64)> {
        let start = u64::from(record.extent_lba).checked_mul(self.block_size)?;
        let len = u64::from(record.data_len);
        let end = start.checked_add(len)?;
        (end <= self.data.len() as u64).then_some((start, len))
    }

    fn first_record(&self, dir: Extent) -> Option<Record<'a>> {
        let bytes = self.data.get(dir.start..dir.start + dir.len)?;
        let len = usize::from(*bytes.first()?);
        Record::parse(bytes.get(..len)?)
    }

    /// Every record of a directory extent except `.` and `..`, in order.
    fn records(&self, dir: Extent) -> Result<Vec<Record<'a>>, LocateError> {
        let bytes = self
            .data
            .get(dir.start..dir.start + dir.len)
            .ok_or_else(|| malformed("directory extent runs past the end of the image"))?;
        let mut out = Vec::new();
        let mut pos = 0usize;
        while pos < bytes.len() {
            let len = usize::from(bytes[pos]);
            if len == 0 {
                // Padding to the end of this sector; records never cross one.
                pos = (pos / SECTOR + 1) * SECTOR;
                continue;
            }
            let end = pos + len;
            if end > bytes.len() || (pos / SECTOR) != ((end - 1) / SECTOR) {
                return Err(malformed("directory record crosses its sector or extent"));
            }
            let record = Record::parse(&bytes[pos..end])
                .ok_or_else(|| malformed("short directory record"))?;
            if !record.is_self_or_parent() {
                out.push(record);
            }
            pos = end;
        }
        Ok(out)
    }

    /// Find `dir/file` from the root. `Ok(None)` when either is absent.
    fn probe(
        &self,
        root: Extent,
        dir: &str,
        file: &str,
    ) -> Result<Option<LocatedRootfs>, LocateError> {
        let Some(dir_record) = self.find(root, dir)? else {
            return Ok(None);
        };
        if !dir_record.is_dir() {
            return Ok(None);
        }
        let dir_extent = self.directory_extent(&dir_record)?;
        let Some(file_record) = self.find(dir_extent, file)? else {
            return Ok(None);
        };
        let probe = format!("{}/{}", dir, file);
        if file_record.is_dir() {
            return Err(LocateError::Unsupported(format!(
                "{} is a directory",
                probe
            )));
        }
        if file_record.ext_attr_len != 0 || file_record.unit_size != 0 || file_record.gap != 0 {
            return Err(LocateError::Unsupported(format!(
                "{} uses an extended attribute record or interleaving",
                probe
            )));
        }
        let rr = self.rock_ridge(&file_record)?;
        if rr.zisofs {
            return Err(LocateError::Unsupported(format!(
                "{} is zisofs-compressed",
                probe
            )));
        }
        if rr.symlink {
            return Err(LocateError::Unsupported(format!(
                "{} is a symbolic link",
                probe
            )));
        }
        let (offset, len) = self.extent_range(&file_record).ok_or_else(|| {
            LocateError::Malformed(format!("{} extent runs past the end of the image", probe))
        })?;
        Ok(Some(LocatedRootfs { probe, offset, len }))
    }

    /// The single record of `dir` named `name` (ASCII case-insensitive),
    /// `Ok(None)` when there is none. Two records with that name are refused:
    /// it is either a multi-extent file (bit 7 set on every record but the
    /// last) or a crafted image whose readers could disagree on which one is
    /// meant.
    fn find(&self, dir: Extent, name: &str) -> Result<Option<Record<'a>>, LocateError> {
        let mut found: Option<Record<'a>> = None;
        for record in self.records(dir)? {
            let rr = self.rock_ridge(&record)?;
            if rr.relocated {
                // A relocated directory's placeholder; never followed.
                continue;
            }
            let matches = match rr.name.as_deref() {
                Some(nm) => nm.eq_ignore_ascii_case(name.as_bytes()),
                None => iso_name_matches(record.name, name),
            };
            if !matches {
                continue;
            }
            if record.flags & FLAG_MULTI_EXTENT != 0 {
                return Err(LocateError::Unsupported(format!(
                    "{} is a multi-extent file (over 4 GiB)",
                    name
                )));
            }
            if found.is_some() {
                return Err(LocateError::Unsupported(format!(
                    "more than one directory record is named {}",
                    name
                )));
            }
            found = Some(record);
        }
        Ok(found)
    }

    /// The Rock Ridge facts the locator needs from one record.
    fn rock_ridge(&self, record: &Record<'_>) -> Result<RockRidge, LocateError> {
        let mut rr = RockRidge::default();
        let Some(skip) = self.rock_ridge_skip else {
            return Ok(rr);
        };
        let mut name: Vec<u8> = Vec::new();
        let mut saw_name = false;
        let mut area: &[u8] = record.system_use.get(skip..).unwrap_or(&[]);
        let mut budget = MAX_SYSTEM_USE_BYTES;
        let mut continuations = 0usize;

        'areas: loop {
            let mut next: Option<&[u8]> = None;
            let mut pos = 0usize;
            while pos + 4 <= area.len() {
                let sig = [area[pos], area[pos + 1]];
                let len = usize::from(area[pos + 2]);
                if len < 4 || pos + len > area.len() || len > budget {
                    break 'areas;
                }
                budget -= len;
                let total = self.su_budget.get();
                if len > total {
                    return Err(malformed("too much Rock Ridge system use data"));
                }
                self.su_budget.set(total - len);
                let entry = &area[pos..pos + len];
                match &sig {
                    b"NM" if len >= 5 => {
                        let flags = entry[4];
                        // CURRENT (2) and PARENT (4) name "." and "..".
                        if flags & 0x06 == 0 {
                            saw_name = true;
                            let room = MAX_NAME_BYTES.saturating_sub(name.len());
                            let content = &entry[5..];
                            name.extend_from_slice(&content[..content.len().min(room)]);
                        }
                    }
                    b"CE" if len >= 28 => {
                        next = self.continuation_area(entry);
                    }
                    b"ZF" => rr.zisofs = true,
                    b"SL" => rr.symlink = true,
                    b"RE" => rr.relocated = true,
                    b"ST" => break,
                    _ => {}
                }
                pos += len;
            }
            match next {
                Some(more) if continuations < MAX_CONTINUATION_AREAS => {
                    continuations += 1;
                    area = more;
                }
                _ => break,
            }
        }
        if saw_name {
            rr.name = Some(name);
        }
        Ok(rr)
    }

    /// The bytes a `CE` entry points at, when they lie inside the image.
    fn continuation_area(&self, entry: &[u8]) -> Option<&'a [u8]> {
        let block = u64::from(le_u32(entry, 4)?);
        let offset = u64::from(le_u32(entry, 12)?);
        let len = u64::from(le_u32(entry, 20)?);
        if len > MAX_SYSTEM_USE_BYTES as u64 {
            return None;
        }
        let start = block.checked_mul(self.block_size)?.checked_add(offset)?;
        let end = start.checked_add(len)?;
        let start = usize::try_from(start).ok()?;
        let end = usize::try_from(end).ok()?;
        self.data.get(start..end)
    }
}

const FLAG_DIRECTORY: u8 = 0x02;
const FLAG_MULTI_EXTENT: u8 = 0x80;

#[derive(Default)]
struct RockRidge {
    /// The assembled `NM` name, when the record carries one.
    name: Option<Vec<u8>>,
    zisofs: bool,
    symlink: bool,
    relocated: bool,
}

/// One ISO9660 directory record, borrowed from the image.
#[derive(Clone, Copy)]
struct Record<'a> {
    ext_attr_len: u8,
    extent_lba: u32,
    data_len: u32,
    flags: u8,
    unit_size: u8,
    gap: u8,
    name: &'a [u8],
    system_use: &'a [u8],
}

impl<'a> Record<'a> {
    /// Parse a record from exactly its own bytes (`buf.len()` is the record
    /// length or, for the PVD's root record, 34).
    fn parse(buf: &'a [u8]) -> Option<Self> {
        if buf.len() < 34 {
            return None;
        }
        let name_len = usize::from(buf[32]);
        let name_end = 33usize.checked_add(name_len)?;
        let name = buf.get(33..name_end)?;
        // A padding byte follows an even-length identifier.
        let su_start = name_end + usize::from(name_len.is_multiple_of(2));
        let system_use = buf.get(su_start..).unwrap_or(&[]);
        Some(Record {
            ext_attr_len: buf[1],
            extent_lba: le_u32(buf, 2)?,
            data_len: le_u32(buf, 10)?,
            flags: buf[25],
            unit_size: buf[26],
            gap: buf[27],
            name,
            system_use,
        })
    }

    fn is_dir(&self) -> bool {
        self.flags & FLAG_DIRECTORY != 0
    }

    fn is_self_or_parent(&self) -> bool {
        self.name.len() == 1 && (self.name[0] == 0 || self.name[0] == 1)
    }

    /// The Rock Ridge skip length, when this record's system use area starts
    /// with a valid `SP` entry.
    fn sp_skip(&self) -> Option<usize> {
        let su = self.system_use;
        (su.len() >= 7 && &su[0..2] == b"SP" && su[2] == 7 && su[4] == 0xBE && su[5] == 0xEF)
            .then(|| usize::from(su[6]))
    }
}

/// Match a plain ISO9660 identifier (`FILESYST.SQU;1`, `LIVE`) against a
/// probe name, ignoring the `;version` suffix, a trailing `.` and ASCII case.
/// A level 1 image truncates names to 8.3, so `filesystem.squashfs` cannot
/// match there; such media carries Rock Ridge, whose `NM` is used instead.
fn iso_name_matches(identifier: &[u8], probe: &str) -> bool {
    let mut id = identifier;
    if let Some(semi) = id.iter().position(|&b| b == b';') {
        id = &id[..semi];
    }
    if let Some((&b'.', rest)) = id.split_last() {
        id = rest;
    }
    id.eq_ignore_ascii_case(probe.as_bytes())
}
