//! A tiny ISO9660 writer for tests (#1966): just enough of ECMA-119 and Rock
//! Ridge to lay out a root, one level of directories and their files, with
//! the knobs the locator's tests need to build hostile images (no Rock
//! Ridge, `NM` spread over a continuation area, extra system use entries,
//! raw flags). Generating the bytes here keeps the unit tests independent of
//! `xorriso`, which the CI runners do not install; the tests that do run
//! `xorriso` cross-check this writer against real media layouts.
//!
//! Layout: sectors 0 to 15 are the system area (an MBR signature when
//! `hybrid` is set), 16 the primary volume descriptor, 17 the terminator, 18
//! the root directory, then one sector per directory, then the continuation
//! areas, then every file's data from a fresh sector.

pub(crate) const BLOCK: usize = 2048;

#[derive(Clone, Default)]
pub(crate) struct IsoFile {
    /// The ISO9660 identifier, `;1` included when wanted.
    pub iso_name: String,
    /// The Rock Ridge `NM` name, when the image carries Rock Ridge.
    pub rr_name: Option<String>,
    pub data: Vec<u8>,
    /// Extra flag bits OR-ed into the record (0x80 multi-extent, 0x02 dir).
    pub flags: u8,
    /// Extra system use entries appended after `NM` (`ZF`, `SL`, ...).
    pub extra_su: Vec<u8>,
    /// Put the `NM` name in a continuation area (`CE`), split over two `NM`
    /// entries joined by the CONTINUE flag.
    pub nm_in_continuation: bool,
}

#[derive(Clone, Default)]
pub(crate) struct IsoDir {
    pub iso_name: String,
    pub rr_name: Option<String>,
    pub files: Vec<IsoFile>,
}

#[derive(Clone, Default)]
pub(crate) struct IsoSpec {
    pub rock_ridge: bool,
    pub hybrid: bool,
    pub dirs: Vec<IsoDir>,
}

impl IsoSpec {
    /// A Rock Ridge image holding `dir/file` with `data`, named the way a
    /// default (`-iso-level 1`) `xorriso -as mkisofs -R` writes it: an 8.3
    /// ISO9660 identifier and the real name in `NM`.
    pub(crate) fn live(dir: &str, file: &str, data: Vec<u8>) -> Self {
        IsoSpec {
            rock_ridge: true,
            hybrid: true,
            dirs: vec![IsoDir {
                iso_name: level1_name(dir, false),
                rr_name: Some(dir.to_string()),
                files: vec![IsoFile {
                    iso_name: level1_name(file, true),
                    rr_name: Some(file.to_string()),
                    data,
                    ..Default::default()
                }],
            }],
        }
    }
}

/// An ECMA-119 level 1 identifier for `name`: upper case, 8.3, `;1` on files.
pub(crate) fn level1_name(name: &str, file: bool) -> String {
    let upper = name.to_ascii_uppercase();
    let (stem, ext) = match upper.split_once('.') {
        Some((s, e)) => (s.to_string(), e.to_string()),
        None => (upper.clone(), String::new()),
    };
    let stem: String = stem.chars().take(8).collect();
    let ext: String = ext.chars().take(3).collect();
    if !file {
        return stem;
    }
    format!("{}.{};1", stem, ext)
}

pub(crate) fn sp_entry() -> Vec<u8> {
    vec![b'S', b'P', 7, 1, 0xBE, 0xEF, 0]
}

pub(crate) fn nm_entry(flags: u8, name: &[u8]) -> Vec<u8> {
    let mut e = vec![b'N', b'M', (5 + name.len()) as u8, 1, flags];
    e.extend_from_slice(name);
    e
}

fn both_u32(out: &mut [u8], v: u32) {
    out[0..4].copy_from_slice(&v.to_le_bytes());
    out[4..8].copy_from_slice(&v.to_be_bytes());
}

fn both_u16(out: &mut [u8], v: u16) {
    out[0..2].copy_from_slice(&v.to_le_bytes());
    out[2..4].copy_from_slice(&v.to_be_bytes());
}

pub(crate) fn ce_entry(block: u32, offset: u32, len: u32) -> Vec<u8> {
    let mut e = vec![0u8; 28];
    e[0] = b'C';
    e[1] = b'E';
    e[2] = 28;
    e[3] = 1;
    both_u32(&mut e[4..12], block);
    both_u32(&mut e[12..20], offset);
    both_u32(&mut e[20..28], len);
    e
}

/// One directory record.
pub(crate) fn record(lba: u32, size: u32, flags: u8, name: &[u8], su: &[u8]) -> Vec<u8> {
    let pad = usize::from(name.len().is_multiple_of(2));
    let len = 33 + name.len() + pad + su.len();
    assert!(len <= 255, "directory record too long for the test writer");
    let mut r = vec![0u8; len];
    r[0] = len as u8;
    both_u32(&mut r[2..10], lba);
    both_u32(&mut r[10..18], size);
    r[25] = flags;
    both_u16(&mut r[28..32], 1);
    r[32] = name.len() as u8;
    r[33..33 + name.len()].copy_from_slice(name);
    r[33 + name.len() + pad..].copy_from_slice(su);
    r
}

fn sectors_for(len: usize) -> usize {
    len.div_ceil(BLOCK).max(1)
}

/// Write the image described by `spec`.
pub(crate) fn build(spec: &IsoSpec) -> Vec<u8> {
    let root_lba = 18usize;
    let first_dir_lba = root_lba + 1;
    let first_ce_lba = first_dir_lba + spec.dirs.len();

    // Continuation areas, one sector each, in file order.
    let mut ce_lbas: Vec<Vec<Option<usize>>> = Vec::new();
    let mut next = first_ce_lba;
    for dir in &spec.dirs {
        let mut per = Vec::new();
        for f in &dir.files {
            if f.nm_in_continuation && spec.rock_ridge && f.rr_name.is_some() {
                per.push(Some(next));
                next += 1;
            } else {
                per.push(None);
            }
        }
        ce_lbas.push(per);
    }

    // File data.
    let mut file_lbas: Vec<Vec<usize>> = Vec::new();
    for dir in &spec.dirs {
        let mut per = Vec::new();
        for f in &dir.files {
            per.push(next);
            next += sectors_for(f.data.len());
        }
        file_lbas.push(per);
    }
    let total_sectors = next;
    let mut img = vec![0u8; total_sectors * BLOCK];

    if spec.hybrid {
        img[0] = 0x33;
        img[0x1FE] = 0x55;
        img[0x1FF] = 0xAA;
    }

    // Primary volume descriptor.
    let pvd = &mut img[16 * BLOCK..17 * BLOCK];
    pvd[0] = 1;
    pvd[1..6].copy_from_slice(b"CD001");
    pvd[6] = 1;
    both_u32(&mut pvd[80..88], total_sectors as u32);
    both_u16(&mut pvd[120..124], 1);
    both_u16(&mut pvd[124..128], 1);
    both_u16(&mut pvd[128..132], BLOCK as u16);
    let root_rec = record(root_lba as u32, BLOCK as u32, 0x02, &[0], &[]);
    pvd[156..156 + 34].copy_from_slice(&root_rec);
    pvd[881] = 1;

    // Terminator.
    let term = &mut img[17 * BLOCK..18 * BLOCK];
    term[0] = 255;
    term[1..6].copy_from_slice(b"CD001");
    term[6] = 1;

    let rr_su = |name: &Option<String>| -> Vec<u8> {
        match (spec.rock_ridge, name) {
            (true, Some(n)) => nm_entry(0, n.as_bytes()),
            _ => Vec::new(),
        }
    };

    // Root directory.
    let mut root = Vec::new();
    let dot_su = if spec.rock_ridge {
        sp_entry()
    } else {
        Vec::new()
    };
    root.extend(record(root_lba as u32, BLOCK as u32, 0x02, &[0], &dot_su));
    root.extend(record(root_lba as u32, BLOCK as u32, 0x02, &[1], &[]));
    for (i, dir) in spec.dirs.iter().enumerate() {
        root.extend(record(
            (first_dir_lba + i) as u32,
            BLOCK as u32,
            0x02,
            dir.iso_name.as_bytes(),
            &rr_su(&dir.rr_name),
        ));
    }
    assert!(
        root.len() <= BLOCK,
        "root directory too large for the test writer"
    );
    img[root_lba * BLOCK..root_lba * BLOCK + root.len()].copy_from_slice(&root);

    // Each directory and its files.
    for (i, dir) in spec.dirs.iter().enumerate() {
        let lba = first_dir_lba + i;
        let mut ext = Vec::new();
        ext.extend(record(lba as u32, BLOCK as u32, 0x02, &[0], &[]));
        ext.extend(record(root_lba as u32, BLOCK as u32, 0x02, &[1], &[]));
        for (j, f) in dir.files.iter().enumerate() {
            let mut su = Vec::new();
            match (ce_lbas[i][j], &f.rr_name) {
                (Some(ce_lba), Some(name)) => {
                    let bytes = name.as_bytes();
                    let half = bytes.len() / 2;
                    let mut area = nm_entry(1, &bytes[..half]);
                    area.extend(nm_entry(0, &bytes[half..]));
                    img[ce_lba * BLOCK..ce_lba * BLOCK + area.len()].copy_from_slice(&area);
                    su.extend(ce_entry(ce_lba as u32, 0, area.len() as u32));
                }
                _ => su.extend(rr_su(&f.rr_name)),
            }
            su.extend_from_slice(&f.extra_su);
            ext.extend(record(
                file_lbas[i][j] as u32,
                f.data.len() as u32,
                f.flags,
                f.iso_name.as_bytes(),
                &su,
            ));
            let at = file_lbas[i][j] * BLOCK;
            img[at..at + f.data.len()].copy_from_slice(&f.data);
        }
        assert!(
            ext.len() <= BLOCK,
            "directory too large for the test writer"
        );
        img[lba * BLOCK..lba * BLOCK + ext.len()].copy_from_slice(&ext);
    }
    img
}

/// The offset of the first occurrence of `needle` in `hay`, for tests that
/// patch a built image.
pub(crate) fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}
