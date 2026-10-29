//! Tests for the ISO9660 rootfs locator and stager (#1966).
//!
//! The locator tests build their images with [`super::test_iso`], so they
//! run everywhere. The stager tests need `mksquashfs` / `unsquashfs` (the
//! services-1 CI leg installs squashfs-tools and sets
//! `AK_TESTS_REQUIRE_SQUASHFS`, turning a skip into a failure); the
//! `xorriso` cross-checks run where `xorriso` is installed, and fail instead
//! of skipping under `AK_TESTS_REQUIRE_XORRISO`.

use super::locator::{locate_rootfs, LocateError, LAYERED_MARKERS, ROOTFS_PROBES};
use super::test_iso::{self, IsoDir, IsoFile, IsoSpec, BLOCK};
use super::*;
use std::time::Instant;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn located_bytes<'a>(iso: &'a [u8], found: &locator::LocatedRootfs) -> &'a [u8] {
    &iso[found.offset as usize..(found.offset + found.len) as usize]
}

fn one_file(rock_ridge: bool, dir: (&str, Option<&str>), file: IsoFile) -> Vec<u8> {
    test_iso::build(&IsoSpec {
        rock_ridge,
        hybrid: false,
        dirs: vec![IsoDir {
            iso_name: dir.0.to_string(),
            rr_name: dir.1.map(str::to_string),
            files: vec![file],
        }],
    })
}

fn squashfs_payload() -> Vec<u8> {
    let mut v = SQUASHFS_STUB.to_vec();
    v.extend_from_slice(&[0x5a; 3000]);
    v
}

/// Not a real squashfs, only its magic: enough for the locator tests.
const SQUASHFS_STUB: &[u8] = b"hsqs";

/// A tiny xorshift generator, so the mutation runs are reproducible from the
/// seed printed on failure.
struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

fn env_count(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(default)
}

/// Mutate `seed` in one of the ways a crafted or damaged image differs from
/// a real one: flipped bytes, overwritten 32-bit fields with extreme values,
/// a truncation, or a duplicated sector.
fn mutate(seed: &[u8], rng: &mut XorShift) -> Vec<u8> {
    let mut v = seed.to_vec();
    let rounds = 1 + rng.below(8);
    for _ in 0..rounds {
        if v.is_empty() {
            break;
        }
        match rng.below(5) {
            0 => {
                let at = rng.below(v.len());
                v[at] ^= 1 << rng.below(8);
            }
            1 => {
                let at = rng.below(v.len());
                v[at] = rng.next() as u8;
            }
            2 => {
                let at = rng.below(v.len().saturating_sub(4));
                let val: u32 = match rng.below(4) {
                    0 => 0,
                    1 => u32::MAX,
                    2 => 0x8000_0000,
                    _ => rng.next() as u32,
                };
                if at + 4 <= v.len() {
                    v[at..at + 4].copy_from_slice(&val.to_le_bytes());
                }
            }
            3 => {
                let cut = rng.below(v.len());
                v.truncate(cut);
            }
            _ => {
                let sectors = v.len() / BLOCK;
                if sectors >= 2 {
                    let from = rng.below(sectors) * BLOCK;
                    let to = rng.below(sectors) * BLOCK;
                    let copy = v[from..from + BLOCK].to_vec();
                    v[to..to + BLOCK].copy_from_slice(&copy);
                }
            }
        }
    }
    v
}

/// Run the locator over `iters` mutants of every seed and check that it
/// never panics and only ever returns a range inside the input.
fn fuzz_locator(seeds: &[Vec<u8>], iters: usize, seed: u64) -> (usize, usize) {
    let mut rng = XorShift(seed);
    let mut ok = 0usize;
    for i in 0..iters {
        let base = &seeds[i % seeds.len()];
        let input = mutate(base, &mut rng);
        if let Ok(found) = locate_rootfs(&input) {
            let end = found.offset.checked_add(found.len);
            assert!(
                end.is_some_and(|e| e <= input.len() as u64),
                "iteration {i} (seed {seed}) located a range outside the input: {found:?}"
            );
            ok += 1;
        }
    }
    (iters, ok)
}

fn locator_seeds() -> Vec<Vec<u8>> {
    let mut seeds = vec![
        test_iso::build(&IsoSpec::live(
            "live",
            "filesystem.squashfs",
            squashfs_payload(),
        )),
        test_iso::build(&IsoSpec::live("LiveOS", "squashfs.img", squashfs_payload())),
    ];
    let mut spec = IsoSpec::live("casper", "filesystem.squashfs", squashfs_payload());
    spec.dirs[0].files[0].nm_in_continuation = true;
    seeds.push(test_iso::build(&spec));
    seeds.push(one_file(
        false,
        ("IMAGES", None),
        IsoFile {
            iso_name: "INSTALL.IMG;1".into(),
            data: squashfs_payload(),
            ..Default::default()
        },
    ));
    seeds
}

// ---------------------------------------------------------------------------
// Locator: detection and layouts
// ---------------------------------------------------------------------------

/// Detection is by the volume descriptor magic, never by the name: a hybrid
/// image (MBR at offset 0, as every modern live medium is) is ISO9660, and a
/// zip, a gzip stream or a short file is not.
#[test]
fn iso9660_is_detected_by_its_volume_descriptor() {
    let iso = test_iso::build(&IsoSpec::live(
        "live",
        "filesystem.squashfs",
        squashfs_payload(),
    ));
    assert!(is_iso9660(&iso));
    assert_eq!(&iso[0x1FE..0x200], &[0x55, 0xAA], "the fixture is hybrid");

    assert!(!is_iso9660(b"PK\x03\x04 not an iso"));
    assert!(!is_iso9660(&[0x1f, 0x8b, 0x08, 0x00]));
    assert!(!is_iso9660(&vec![0u8; 40_000]));
    assert!(
        !is_iso9660(&iso[..32_770]),
        "a truncated descriptor is not ISO9660"
    );
}

/// THE layout of a default `xorriso -as mkisofs -R` image: a level 1 8.3
/// identifier (`LIVE/FILESYST.SQU;1`) and the real name in Rock Ridge `NM`.
/// The locator matches the `NM` name and returns exactly the file's bytes.
#[test]
fn locates_a_level1_image_through_rock_ridge_names() {
    let payload = squashfs_payload();
    let iso = test_iso::build(&IsoSpec::live(
        "live",
        "filesystem.squashfs",
        payload.clone(),
    ));
    assert!(test_iso::find(&iso, b"FILESYST.SQU;1").is_some());

    let found = locate_rootfs(&iso).expect("live/filesystem.squashfs must be found");
    assert_eq!(found.probe, "live/filesystem.squashfs");
    assert_eq!(located_bytes(&iso, &found), payload.as_slice());
}

/// Every probe path is found, Fedora and RHEL-family layouts included.
#[test]
fn locates_every_probe_path() {
    for (dir, file) in ROOTFS_PROBES {
        let payload = squashfs_payload();
        let iso = test_iso::build(&IsoSpec::live(dir, file, payload.clone()));
        let found = locate_rootfs(&iso).unwrap_or_else(|e| panic!("{dir}/{file}: {e}"));
        assert_eq!(found.probe, format!("{dir}/{file}"));
        assert_eq!(located_bytes(&iso, &found), payload.as_slice());
    }
}

/// A level 3 image without Rock Ridge: the plain identifier
/// `FILESYSTEM.SQUASHFS;1` matches case-insensitively with the version
/// stripped. A level 1 image without Rock Ridge cannot name the file, and
/// reports no rootfs rather than guessing at an 8.3 match.
#[test]
fn plain_iso9660_names_match_without_rock_ridge() {
    let payload = squashfs_payload();
    let level3 = one_file(
        false,
        ("LIVE", None),
        IsoFile {
            iso_name: "FILESYSTEM.SQUASHFS;1".into(),
            data: payload.clone(),
            ..Default::default()
        },
    );
    let found = locate_rootfs(&level3).expect("level 3 name must match");
    assert_eq!(located_bytes(&level3, &found), payload.as_slice());

    let level1 = one_file(
        false,
        ("LIVE", None),
        IsoFile {
            iso_name: "FILESYST.SQU;1".into(),
            data: payload,
            ..Default::default()
        },
    );
    assert_eq!(locate_rootfs(&level1), Err(LocateError::NoRootfs));
}

/// A long `NM` split over two entries in a continuation area (`CE`), the
/// CONTINUE flag joining them, is assembled and matched.
#[test]
fn rock_ridge_names_in_a_continuation_area_are_assembled() {
    let mut spec = IsoSpec::live("live", "filesystem.squashfs", squashfs_payload());
    spec.dirs[0].files[0].nm_in_continuation = true;
    let iso = test_iso::build(&spec);
    assert_eq!(
        locate_rootfs(&iso).map(|f| f.probe),
        Ok("live/filesystem.squashfs".to_string())
    );
}

/// Media with none of the probe paths (installer-only, Windows, data discs)
/// report `NoRootfs`, naming what was probed; layered casper media is
/// reported as unsupported rather than as having no rootfs.
#[test]
fn media_without_a_rootfs_and_layered_media_are_reported() {
    let iso = test_iso::build(&IsoSpec::live("boot", "vmlinuz", b"kernel".to_vec()));
    let err = locate_rootfs(&iso).unwrap_err();
    assert_eq!(err, LocateError::NoRootfs);
    let text = err.to_string();
    for (dir, file) in ROOTFS_PROBES {
        assert!(text.contains(&format!("{dir}/{file}")), "{text}");
    }

    let (dir, file) = LAYERED_MARKERS[0];
    let layered = test_iso::build(&IsoSpec::live(dir, file, squashfs_payload()));
    assert!(
        matches!(locate_rootfs(&layered), Err(LocateError::Unsupported(ref m)) if m.contains("layered")),
        "{:?}",
        locate_rootfs(&layered)
    );
}

// ---------------------------------------------------------------------------
// Locator: hostile records
// ---------------------------------------------------------------------------

fn live_with(file: IsoFile) -> Vec<u8> {
    one_file(true, ("LIVE", Some("live")), file)
}

fn squash_file() -> IsoFile {
    IsoFile {
        iso_name: "FILESYST.SQU;1".into(),
        rr_name: Some("filesystem.squashfs".into()),
        data: squashfs_payload(),
        ..Default::default()
    }
}

/// Files the locator does not read are refused explicitly, never copied
/// half-way: a multi-extent file (over 4 GiB), a zisofs-compressed one (its
/// extent is not the squashfs), a Rock Ridge symlink, a directory under the
/// file's name, and two records with the same name (readers could disagree
/// on which is meant).
#[test]
fn unreadable_rootfs_records_are_refused() {
    let unsupported = |iso: Vec<u8>, needle: &str| match locate_rootfs(&iso) {
        Err(LocateError::Unsupported(m)) => assert!(m.contains(needle), "{m}"),
        other => panic!("expected Unsupported({needle}), got {other:?}"),
    };

    unsupported(
        live_with(IsoFile {
            flags: 0x80,
            ..squash_file()
        }),
        "multi-extent",
    );
    unsupported(
        live_with(IsoFile {
            extra_su: vec![b'Z', b'F', 16, 1, b'p', b'z', 4, 15, 0, 0, 0, 0, 0, 0, 0, 0],
            ..squash_file()
        }),
        "zisofs",
    );
    unsupported(
        live_with(IsoFile {
            extra_su: vec![b'S', b'L', 5, 1, 0],
            ..squash_file()
        }),
        "symbolic link",
    );
    unsupported(
        live_with(IsoFile {
            flags: 0x02,
            ..squash_file()
        }),
        "directory",
    );

    let twice = test_iso::build(&IsoSpec {
        rock_ridge: true,
        hybrid: false,
        dirs: vec![IsoDir {
            iso_name: "LIVE".into(),
            rr_name: Some("live".into()),
            files: vec![
                squash_file(),
                IsoFile {
                    iso_name: "OTHER.IMG;1".into(),
                    ..squash_file()
                },
            ],
        }],
    });
    unsupported(twice, "more than one");
}

/// Names from the image are only ever compared with the fixed probe names;
/// a Rock Ridge name spelling a path (`../live`, `/live`,
/// `live/../live`) never matches, so it cannot steer the locator, and the
/// caller never uses a name from the image as a path in the first place.
#[test]
fn rock_ridge_names_that_spell_paths_never_match() {
    for hostile in [
        "../live",
        "/live",
        "live/../live",
        "live/",
        "./live",
        "live\0",
    ] {
        let iso = one_file(true, ("LIVE", Some(hostile)), squash_file());
        assert_eq!(
            locate_rootfs(&iso),
            Err(LocateError::NoRootfs),
            "dir NM {hostile:?} must not match"
        );
    }
    for hostile in [
        "../filesystem.squashfs",
        "/live/filesystem.squashfs",
        "filesystem.squashfs/",
    ] {
        let iso = live_with(IsoFile {
            rr_name: Some(hostile.into()),
            ..squash_file()
        });
        assert_eq!(
            locate_rootfs(&iso),
            Err(LocateError::NoRootfs),
            "file NM {hostile:?} must not match"
        );
    }
}

/// A file extent that runs past the end of the image (a truncated upload, or
/// a crafted logical block number) is malformed, never a short read.
#[test]
fn an_extent_past_the_end_of_the_image_is_malformed() {
    let mut iso = test_iso::build(&IsoSpec::live(
        "live",
        "filesystem.squashfs",
        squashfs_payload(),
    ));
    iso.truncate(iso.len() - BLOCK);
    assert!(
        matches!(locate_rootfs(&iso), Err(LocateError::Malformed(ref m)) if m.contains("past the end")),
        "{:?}",
        locate_rootfs(&iso)
    );
}

/// A root directory claiming more than [`locator::MAX_DIRECTORY_EXTENT`]
/// bytes is refused before it is read, and an image cut inside its volume
/// descriptor set is malformed.
#[test]
fn oversized_directories_and_cut_descriptor_sets_are_malformed() {
    let mut iso = test_iso::build(&IsoSpec::live(
        "live",
        "filesystem.squashfs",
        squashfs_payload(),
    ));
    let root_len_at = 16 * BLOCK + 156 + 10;
    iso[root_len_at..root_len_at + 4].copy_from_slice(&(2u32 * 1024 * 1024).to_le_bytes());
    assert!(
        matches!(locate_rootfs(&iso), Err(LocateError::Malformed(ref m)) if m.contains("exceeds")),
        "{:?}",
        locate_rootfs(&iso)
    );

    let iso = test_iso::build(&IsoSpec::live(
        "live",
        "filesystem.squashfs",
        squashfs_payload(),
    ));
    assert!(matches!(
        locate_rootfs(&iso[..16 * BLOCK + 100]),
        Err(LocateError::Malformed(_))
    ));
}

/// A `CE` that points back at its own area is followed a bounded number of
/// times: the locator answers instead of looping.
#[test]
fn a_continuation_area_pointing_at_itself_terminates() {
    let mut spec = IsoSpec::live("live", "filesystem.squashfs", squashfs_payload());
    spec.dirs[0].files[0].nm_in_continuation = true;
    let mut iso = test_iso::build(&spec);
    // The continuation area holds two NM entries; replace the second with a
    // CE pointing at the area's own sector.
    let area_at = test_iso::find(&iso, b"NM").unwrap();
    let area_lba = (area_at / BLOCK) as u32;
    let first_len = usize::from(iso[area_at + 2]);
    let ce = test_iso::ce_entry(area_lba, 0, 64);
    iso[area_at + first_len..area_at + first_len + ce.len()].copy_from_slice(&ce);

    let started = Instant::now();
    let result = locate_rootfs(&iso);
    assert!(started.elapsed() < Duration::from_secs(1), "{result:?}");
}

/// Bounded mutation run over the locator's seeds, in every CI run: no
/// panic, no out-of-bounds range, and the whole run stays fast because the
/// locator's work is bounded by construction. `AK_ISO_FUZZ_ITERS` raises the
/// count for a local campaign; the cargo-fuzz target
/// (`backend/fuzz/fuzz_targets/iso_locate.rs`) is the coverage-guided one.
#[test]
fn locator_survives_mutated_images() {
    let seeds = locator_seeds();
    for s in &seeds {
        assert!(locate_rootfs(s).is_ok(), "every seed must locate cleanly");
    }
    let iters = env_count("AK_ISO_FUZZ_ITERS", 20_000);
    let started = Instant::now();
    let (runs, ok) = fuzz_locator(&seeds, iters, 0x1966_1966_1966_1966);
    eprintln!(
        "iso locator mutation run: {runs} inputs, {ok} located, {:?}",
        started.elapsed()
    );
}

// ---------------------------------------------------------------------------
// Stager (needs squashfs-tools)
// ---------------------------------------------------------------------------

fn squashfs_tools_available() -> bool {
    let available = ["mksquashfs", "unsquashfs"].iter().all(|bin| {
        std::process::Command::new(bin)
            .arg("-version")
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).contains(&format!("{bin} version")))
            .unwrap_or(false)
    });
    let required = std::env::var("AK_TESTS_REQUIRE_SQUASHFS").is_ok_and(|v| !v.is_empty());
    assert!(
        available || !required,
        "AK_TESTS_REQUIRE_SQUASHFS is set but mksquashfs/unsquashfs are not on PATH"
    );
    available
}

fn xorriso_available() -> bool {
    let available = std::process::Command::new("xorriso")
        .arg("-version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    let required = std::env::var("AK_TESTS_REQUIRE_XORRISO").is_ok_and(|v| !v.is_empty());
    assert!(
        available || !required,
        "AK_TESTS_REQUIRE_XORRISO is set but xorriso is not on PATH"
    );
    available
}

/// What to put in a test rootfs.
enum Node<'a> {
    File(&'a str, &'a [u8]),
    /// A sparse file of the given length.
    Sparse(&'a str, u64),
    Link(&'a str, &'a str),
    Fifo(&'a str),
}

fn build_squashfs(nodes: &[Node<'_>]) -> Vec<u8> {
    let staging = tempfile::tempdir().unwrap();
    let src = staging.path().join("src");
    std::fs::create_dir_all(&src).unwrap();
    for node in nodes {
        let path = match node {
            Node::File(p, _) | Node::Sparse(p, _) | Node::Link(p, _) | Node::Fifo(p) => *p,
        };
        let full = src.join(path);
        std::fs::create_dir_all(full.parent().unwrap()).unwrap();
        match node {
            Node::File(_, data) => std::fs::write(&full, data).unwrap(),
            Node::Sparse(_, len) => std::fs::File::create(&full).unwrap().set_len(*len).unwrap(),
            Node::Link(_, target) => std::os::unix::fs::symlink(target, &full).unwrap(),
            Node::Fifo(_) => assert!(std::process::Command::new("mkfifo")
                .arg(&full)
                .status()
                .expect("mkfifo must run")
                .success()),
        }
    }
    let img = staging.path().join("img.squashfs");
    let out = std::process::Command::new("mksquashfs")
        .arg(&src)
        .arg(&img)
        .args(["-noappend", "-quiet", "-no-progress"])
        .output()
        .expect("mksquashfs must run");
    assert!(
        out.status.success(),
        "mksquashfs failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    std::fs::read(&img).unwrap()
}

const OS_RELEASE: &[u8] = b"PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nID=debian\nVERSION_ID=\"12\"\nVERSION_CODENAME=bookworm\n";
const DPKG_STATUS: &[u8] = b"Package: openssl\nStatus: install ok installed\nPriority: optional\nArchitecture: amd64\nVersion: 3.0.11-1~deb12u2\n\n";

fn debian_rootfs() -> Vec<u8> {
    build_squashfs(&[
        Node::File("usr/lib/os-release", OS_RELEASE),
        Node::Link("etc/os-release", "../usr/lib/os-release"),
        Node::File("var/lib/dpkg/status", DPKG_STATUS),
        Node::File("var/lib/dpkg/info/openssl.list", b"/usr/bin/openssl\n"),
        Node::File("usr/bin/blob", &[0x42; 300_000]),
        Node::File("home/user/notes.txt", b"not inventory"),
    ])
}

fn iso_of(rootfs: Vec<u8>) -> Bytes {
    Bytes::from(test_iso::build(&IsoSpec::live(
        "live",
        "filesystem.squashfs",
        rootfs,
    )))
}

fn small_limits() -> IsoLimits {
    IsoLimits {
        max_bytes: 64 * 1024 * 1024,
        max_entries: 10_000,
        list_timeout: Duration::from_secs(30),
        extract_timeout: Duration::from_secs(60),
    }
}

fn names_under(root: &Path) -> Vec<String> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for e in std::fs::read_dir(&dir).unwrap() {
            let e = e.unwrap();
            let p = e.path();
            out.push(p.strip_prefix(root).unwrap().to_string_lossy().into_owned());
            if e.file_type().unwrap().is_dir() {
                stack.push(p);
            }
        }
    }
    out.sort();
    out
}

fn assert_unscannable(staging: &IsoStaging, needle: &str) {
    match staging {
        IsoStaging::Unscannable(reason) => {
            assert!(
                reason.contains(needle),
                "reason {reason:?} lacks {needle:?}"
            )
        }
        other => panic!("expected Unscannable({needle}), got {other:?}"),
    }
}

/// THE #1966 happy path: the rootfs package database (and the OS release
/// file, through the in-image symlink) comes out at the workspace root where
/// the engines look for it; nothing else of the image is written, and the
/// staged squashfs is gone before the engines run.
#[tokio::test]
async fn stages_only_the_package_database_of_the_rootfs() {
    if !squashfs_tools_available() {
        return;
    }
    let ws = tempfile::tempdir().unwrap();
    let staged = stage_iso_rootfs(ws.path(), &iso_of(debian_rootfs()), small_limits())
        .await
        .unwrap();
    assert_eq!(
        staged,
        IsoStaging::Extracted {
            probe: "live/filesystem.squashfs".into()
        }
    );
    let root = ws.path();
    assert_eq!(
        std::fs::read(root.join("var/lib/dpkg/status")).unwrap(),
        DPKG_STATUS
    );
    assert_eq!(
        std::fs::read(root.join("etc/os-release")).unwrap(),
        OS_RELEASE
    );
    assert!(root.join("var/lib/dpkg/info/openssl.list").is_file());
    assert!(
        !root.join("usr/bin/blob").exists(),
        "binaries are not extracted"
    );
    assert!(!root.join("home").exists(), "nothing outside the DB paths");
    assert!(
        !root.join(STAGED_IMAGE_NAME).exists(),
        "the staged image is removed"
    );
}

/// A squashfs with a valid magic and a corrupt body: the listing fails, the
/// image is unscannable with the tool's reason, and the workspace is empty
/// (no raw image that a fallback scan could read as clean).
#[tokio::test]
async fn a_corrupt_squashfs_is_unscannable_and_leaves_nothing() {
    if !squashfs_tools_available() {
        return;
    }
    let mut rootfs = debian_rootfs();
    for b in rootfs.iter_mut().skip(96) {
        *b = 0xA5;
    }
    let ws = tempfile::tempdir().unwrap();
    let staged = stage_iso_rootfs(ws.path(), &iso_of(rootfs), small_limits())
        .await
        .unwrap();
    assert_unscannable(&staged, "live/filesystem.squashfs");
    assert_eq!(names_under(ws.path()), Vec::<String>::new());
}

/// The embedded file must be a squashfs; a nested ISO9660 image is refused
/// (nesting stops at the squashfs rootfs), and so is anything else. Nothing
/// is written for either.
#[tokio::test]
async fn nested_images_and_non_squashfs_payloads_are_refused() {
    let inner = test_iso::build(&IsoSpec::live(
        "live",
        "filesystem.squashfs",
        squashfs_payload(),
    ));
    let ws = tempfile::tempdir().unwrap();
    let staged = stage_iso_rootfs(ws.path(), &iso_of(inner), small_limits())
        .await
        .unwrap();
    assert_unscannable(&staged, "nested");
    assert_eq!(names_under(ws.path()), Vec::<String>::new());

    let staged = stage_iso_rootfs(ws.path(), &iso_of(b"\x7fELF...".to_vec()), small_limits())
        .await
        .unwrap();
    assert_unscannable(&staged, "not a squashfs image");
    assert_eq!(names_under(ws.path()), Vec::<String>::new());

    let staged = stage_iso_rootfs(
        ws.path(),
        &Bytes::from_static(b"not an iso"),
        small_limits(),
    )
    .await
    .unwrap();
    assert_unscannable(&staged, "not an ISO9660 image");
}

/// A squashfs bomb: a huge sparse `var/lib/dpkg/status` compresses to almost
/// nothing. The listing's declared size trips the byte ceiling and the
/// extraction never runs, so not a byte of it reaches the disk.
#[tokio::test]
async fn a_declared_size_over_the_ceiling_is_refused_before_extraction() {
    if !squashfs_tools_available() {
        return;
    }
    let rootfs = build_squashfs(&[
        Node::File("etc/os-release", OS_RELEASE),
        Node::Sparse("var/lib/dpkg/status", 256 * 1024 * 1024),
    ]);
    assert!(rootfs.len() < 1024 * 1024, "the bomb must be small");
    let ws = tempfile::tempdir().unwrap();
    let limits = IsoLimits {
        max_bytes: 8 * 1024 * 1024,
        ..small_limits()
    };
    let started = Instant::now();
    let staged = stage_iso_rootfs(ws.path(), &iso_of(rootfs), limits)
        .await
        .unwrap();
    assert_unscannable(&staged, "declare more than 8388608 bytes");
    assert_eq!(names_under(ws.path()), Vec::<String>::new());
    assert!(started.elapsed() < Duration::from_secs(20));
}

/// An entry-count bomb under the package-database paths is refused from the
/// listing, before extraction.
#[tokio::test]
async fn an_entry_count_over_the_ceiling_is_refused() {
    if !squashfs_tools_available() {
        return;
    }
    let names: Vec<String> = (0..64)
        .map(|i| format!("var/lib/dpkg/info/p{i}.list"))
        .collect();
    let mut nodes: Vec<Node<'_>> = names.iter().map(|n| Node::File(n, b"x")).collect();
    nodes.push(Node::File("var/lib/dpkg/status", DPKG_STATUS));
    let ws = tempfile::tempdir().unwrap();
    let limits = IsoLimits {
        max_entries: 20,
        ..small_limits()
    };
    let staged = stage_iso_rootfs(ws.path(), &iso_of(build_squashfs(&nodes)), limits)
        .await
        .unwrap();
    assert_unscannable(&staged, "more than 20 entries");
    assert_eq!(names_under(ws.path()), Vec::<String>::new());
}

/// A symlink in the package database that climbs out of the workspace
/// refuses the whole image (the Incus guard), and the extracted tree is
/// removed. An absolute in-image link (`/etc/...`) is re-rooted under the
/// workspace by the guard, as on Incus images, and stays.
#[tokio::test]
async fn an_escaping_symlink_refuses_the_image() {
    if !squashfs_tools_available() {
        return;
    }
    let rootfs = build_squashfs(&[
        Node::File("etc/os-release", OS_RELEASE),
        Node::File("var/lib/dpkg/status", DPKG_STATUS),
        Node::Link("var/lib/dpkg/evil", "../../../../../../../../etc/passwd"),
    ]);
    let ws = tempfile::tempdir().unwrap();
    let staged = stage_iso_rootfs(ws.path(), &iso_of(rootfs), small_limits())
        .await
        .unwrap();
    assert_unscannable(&staged, "escaping the workspace");
    assert_eq!(names_under(ws.path()), Vec::<String>::new());

    let rootfs = build_squashfs(&[
        Node::File("etc/os-release", OS_RELEASE),
        Node::File("var/lib/dpkg/status", DPKG_STATUS),
        Node::Link("var/lib/dpkg/abs", "/etc/os-release"),
    ]);
    let staged = stage_iso_rootfs(ws.path(), &iso_of(rootfs), small_limits())
        .await
        .unwrap();
    assert!(matches!(staged, IsoStaging::Extracted { .. }), "{staged:?}");
}

/// A rootfs with no package database (an ext4 `rootfs.img` inside the
/// squashfs, as older Fedora media ship, or an unknown distribution) is
/// unscannable, not an empty clean tree.
#[tokio::test]
async fn a_rootfs_without_a_package_database_is_unscannable() {
    if !squashfs_tools_available() {
        return;
    }
    let rootfs = build_squashfs(&[
        Node::File("etc/os-release", OS_RELEASE),
        Node::File("LiveOS/rootfs.img", &[0u8; 4096]),
    ]);
    let ws = tempfile::tempdir().unwrap();
    let staged = stage_iso_rootfs(
        ws.path(),
        &Bytes::from(test_iso::build(&IsoSpec::live(
            "LiveOS",
            "squashfs.img",
            rootfs,
        ))),
        small_limits(),
    )
    .await
    .unwrap();
    assert_unscannable(&staged, "no dpkg, rpm or apk package database");
    assert_eq!(names_under(ws.path()), Vec::<String>::new());
}

fn fake_program(dir: &Path, body: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let path = dir.join("fake-unsquashfs");
    std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path
}

fn stub_iso() -> Bytes {
    iso_of(squashfs_payload())
}

/// A FIFO (or device node) in the package database refuses the image at the
/// listing, before anything is written: an engine opening a FIFO named like
/// a package database would block until the scan's budget ran out.
#[tokio::test]
async fn special_files_in_the_package_database_refuse_the_image() {
    if !squashfs_tools_available() {
        return;
    }
    let rootfs = build_squashfs(&[
        Node::File("etc/os-release", OS_RELEASE),
        Node::File("lib/apk/db/installed", b"P:musl\nV:1.2.4-r2\n\n"),
        Node::Fifo("var/lib/dpkg/status"),
    ]);
    let ws = tempfile::tempdir().unwrap();
    let staged = stage_iso_rootfs(ws.path(), &iso_of(rootfs), small_limits())
        .await
        .unwrap();
    assert_unscannable(&staged, "device node, FIFO or socket");
    assert_eq!(names_under(ws.path()), Vec::<String>::new());
}

/// The post-extraction guard refuses a FIFO too, should one get past the
/// listing.
#[tokio::test]
async fn the_guard_refuses_special_files() {
    use crate::services::incus_scanner::{guard_extracted_tree, TreeLimits};
    let ws = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(ws.path().join("var/lib/dpkg")).unwrap();
    assert!(std::process::Command::new("mkfifo")
        .arg(ws.path().join("var/lib/dpkg/status"))
        .status()
        .expect("mkfifo must run")
        .success());
    let err = guard_extracted_tree(
        ws.path(),
        TreeLimits {
            max_bytes: 1 << 20,
            max_entries: 100,
            label: "ISO rootfs image",
            reject_special_files: true,
        },
    )
    .await
    .expect_err("a FIFO must be refused");
    assert!(
        err.to_string().contains("not a file, directory or symlink"),
        "{err}"
    );
}

/// A listing line longer than [`MAX_LISTING_LINE_BYTES`] refuses the image
/// without buffering the rest of it.
#[tokio::test]
async fn an_overlong_listing_line_refuses_the_image() {
    let tools = tempfile::tempdir().unwrap();
    let program = fake_program(
        tools.path(),
        "head -c 200000 /dev/zero | tr '\\0' a; exit 0",
    );
    let ws = tempfile::tempdir().unwrap();
    let staged = stage_with(
        program.to_str().unwrap(),
        ws.path(),
        &stub_iso(),
        small_limits(),
    )
    .await
    .unwrap();
    assert_unscannable(&staged, "listing line is longer than");
    assert_eq!(names_under(ws.path()), Vec::<String>::new());
}

/// An extractor that never finishes is killed at the timeout; the worker is
/// not pinned and the image is unscannable.
#[tokio::test]
async fn a_hung_extractor_is_killed_at_the_timeout() {
    let tools = tempfile::tempdir().unwrap();
    let program = fake_program(tools.path(), "exec sleep 30");
    let ws = tempfile::tempdir().unwrap();
    let limits = IsoLimits {
        list_timeout: Duration::from_millis(500),
        ..small_limits()
    };
    let started = Instant::now();
    let staged = stage_with(program.to_str().unwrap(), ws.path(), &stub_iso(), limits)
        .await
        .unwrap();
    assert_unscannable(&staged, "did not finish within");
    assert!(started.elapsed() < Duration::from_secs(10));
    assert_eq!(names_under(ws.path()), Vec::<String>::new());
}

/// A missing `unsquashfs` (a non-container install) is an unscannable image
/// with the reason, not a host error.
#[tokio::test]
async fn a_missing_extractor_is_unscannable() {
    let ws = tempfile::tempdir().unwrap();
    let staged = stage_with(
        "/nonexistent/unsquashfs",
        ws.path(),
        &stub_iso(),
        small_limits(),
    )
    .await
    .unwrap();
    assert_unscannable(&staged, "cannot run /nonexistent/unsquashfs");
    assert_eq!(names_under(ws.path()), Vec::<String>::new());
}

/// The child runs under the address-space, CPU-time and file-size rlimits
/// (the file-size one is the byte ceiling, so a single sparse file cannot be
/// written past it even if the listing were wrong).
#[cfg(target_os = "linux")]
#[tokio::test]
async fn the_extractor_runs_under_rlimits() {
    let tools = tempfile::tempdir().unwrap();
    let limits_out = tools.path().join("limits.txt");
    let program = fake_program(
        tools.path(),
        &format!("cat /proc/self/limits > '{}'; exit 1", limits_out.display()),
    );
    let ws = tempfile::tempdir().unwrap();
    let limits = IsoLimits {
        max_bytes: 12_345_678,
        ..small_limits()
    };
    let staged = stage_with(program.to_str().unwrap(), ws.path(), &stub_iso(), limits)
        .await
        .unwrap();
    assert_unscannable(&staged, "squashfs listing failed");
    let text = std::fs::read_to_string(&limits_out).unwrap();
    let line = |name: &str| {
        text.lines()
            .find(|l| l.starts_with(name))
            .unwrap_or_else(|| panic!("{name} missing from {text}"))
            .split_whitespace()
            .skip(name.split_whitespace().count())
            .take(2)
            .collect::<Vec<_>>()
            .join(" ")
    };
    assert_eq!(line("Max address space"), "1073741824 1073741824");
    assert_eq!(line("Max cpu time"), "300 300");
    assert_eq!(line("Max file size"), "12345678 12345678");
}

/// The listing parser counts entries and the declared size of regular files
/// only; device lines (`maj, min` in the size column) and stray text add
/// nothing, and an unreadable size on a regular file counts as over any
/// ceiling.
#[test]
fn listing_lines_are_accounted_conservatively() {
    let mut l = Listed::default();
    l.add_line("drwxr-xr-x root/root                59 2026-10-24 16:31 squashfs-root");
    l.add_line(
        "-rw-r--r-- root/root                93 2026-10-24 16:31 squashfs-root/var/lib/dpkg/status",
    );
    l.add_line("lrwxrwxrwx root/root                21 2026-10-24 16:31 squashfs-root/etc/os-release -> ../usr/lib/os-release");
    l.add_line("crw-r--r-- root/root             1,  3 2026-10-24 16:31 squashfs-root/dev/null");
    l.add_line("Extract filename lib/apk/db can't be resolved");
    l.add_line("");
    assert_eq!(
        l,
        Listed {
            entries: 4,
            bytes: 93,
            special: 1,
        }
    );
    l.add_line("-rw-r--r-- root/root  huge 2026-10-24 16:31 squashfs-root/x");
    assert_eq!(l.bytes, u64::MAX);
}

// ---------------------------------------------------------------------------
// Through the scan workspace
// ---------------------------------------------------------------------------

fn iso_artifact(name: &str) -> crate::models::artifact::Artifact {
    crate::services::scanner_service::test_helpers::make_test_artifact(
        name,
        "application/octet-stream",
        &format!("media/{name}"),
    )
}

/// End to end through `ScanWorkspace::prepare_pinned`, the lifecycle Grype
/// and Trivy filesystem scans use: the guard's directory holds the package
/// database, not the raw ISO, whatever the file is called.
#[tokio::test]
async fn prepare_pinned_stages_the_rootfs_package_database() {
    use crate::services::scanner_service::ScanWorkspace;
    if !squashfs_tools_available() {
        return;
    }
    let base = tempfile::tempdir().unwrap();
    let content = iso_of(debian_rootfs());
    for name in ["debian-live-12.iso", "debian-live-12.img", "download"] {
        let artifact = iso_artifact(name);
        let mut guard = ScanWorkspace::prepare_pinned(
            base.path().to_str().unwrap(),
            None,
            &artifact,
            &content,
            None,
        )
        .await
        .unwrap();
        let names = names_under(&guard);
        assert!(
            names.contains(&"var/lib/dpkg/status".to_string()),
            "{name}: {names:?}"
        );
        assert!(
            !names.iter().any(|n| n == name),
            "{name}: the raw image is not staged"
        );
        guard.cleanup().await;
    }
}

/// `xorriso`-built media (the tool Debian live-build and most distribution
/// builders use), default level 1 and level 3, Debian and Fedora layouts,
/// with Joliet: the locator and the stager agree with real images, not only
/// with the test writer.
#[tokio::test]
async fn xorriso_media_are_located_and_staged() {
    if !xorriso_available() || !squashfs_tools_available() {
        return;
    }
    let rootfs = debian_rootfs();
    for (dir, file, level) in [
        ("live", "filesystem.squashfs", "1"),
        ("live", "filesystem.squashfs", "3"),
        ("casper", "filesystem.squashfs", "1"),
        ("LiveOS", "squashfs.img", "1"),
        ("images", "install.img", "3"),
    ] {
        let tree = tempfile::tempdir().unwrap();
        let path = tree.path().join("tree").join(dir).join(file);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, &rootfs).unwrap();
        std::fs::write(tree.path().join("tree/README"), b"live medium").unwrap();
        let out_iso = tree.path().join("out.iso");
        let out = std::process::Command::new("xorriso")
            .args([
                "-as",
                "mkisofs",
                "-quiet",
                "-R",
                "-J",
                "-iso-level",
                level,
                "-V",
                "DTFLIVE",
                "-o",
            ])
            .arg(&out_iso)
            .arg(tree.path().join("tree"))
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let iso = Bytes::from(std::fs::read(&out_iso).unwrap());

        let found =
            locate_rootfs(&iso).unwrap_or_else(|e| panic!("{dir}/{file} level {level}: {e}"));
        assert_eq!(located_bytes(&iso, &found), rootfs.as_slice());

        let ws = tempfile::tempdir().unwrap();
        let staged = stage_iso_rootfs(ws.path(), &iso, small_limits())
            .await
            .unwrap();
        assert_eq!(
            staged,
            IsoStaging::Extracted {
                probe: format!("{dir}/{file}")
            }
        );
    }
}

/// Mutation run over the squashfs path: corrupted rootfs images go through
/// the real listing, extraction and guard. Each one must finish within the
/// timeouts, end either with a package database inside the ceilings or with
/// an empty workspace, and never write outside the workspace (a sentinel
/// directory beside it must be untouched). `AK_ISO_SQUASHFS_FUZZ_ITERS`
/// raises the count for a local campaign.
#[tokio::test]
async fn squashfs_path_survives_mutated_images() {
    if !squashfs_tools_available() {
        return;
    }
    let iters = env_count("AK_ISO_SQUASHFS_FUZZ_ITERS", 24);
    let seeds = [
        debian_rootfs(),
        build_squashfs(&[
            Node::File("etc/os-release", OS_RELEASE),
            Node::File("var/lib/dpkg/status", DPKG_STATUS),
            Node::Link("var/lib/dpkg/abs", "/etc/os-release"),
            Node::File("lib/apk/db/installed", b"P:musl\nV:1.2.4-r2\n\n"),
        ]),
    ];
    let base = tempfile::tempdir().unwrap();
    let sentinel = base.path().join("sentinel");
    std::fs::create_dir_all(&sentinel).unwrap();
    let limits = IsoLimits {
        max_bytes: 16 * 1024 * 1024,
        max_entries: 5_000,
        list_timeout: Duration::from_secs(20),
        extract_timeout: Duration::from_secs(20),
    };
    let mut rng = XorShift(0x5157_4153_4846_5321);
    let (mut extracted, mut refused) = (0usize, 0usize);
    let started = Instant::now();
    for i in 0..iters {
        let seed = &seeds[i % seeds.len()];
        // Keep the magic so the mutant reaches unsquashfs, and mutate the
        // superblock (the first 96 bytes) and the inode, directory,
        // fragment and id tables, which mksquashfs writes at the end.
        let mut rootfs = seed.clone();
        let rounds = 1 + rng.below(6);
        let tail = rootfs.len().saturating_sub(4096).max(96);
        for _ in 0..rounds {
            let at = match rng.below(3) {
                0 => 4 + rng.below(92),
                1 => tail + rng.below(rootfs.len() - tail),
                _ => 4 + rng.below(rootfs.len() - 4),
            };
            rootfs[at] = match rng.below(3) {
                0 => 0xFF,
                1 => 0,
                _ => rng.next() as u8,
            };
        }
        let ws = base.path().join(format!("ws-{i}"));
        std::fs::create_dir_all(&ws).unwrap();
        let one = Instant::now();
        let staged = stage_iso_rootfs(&ws, &iso_of(rootfs), limits)
            .await
            .unwrap();
        assert!(
            one.elapsed() < Duration::from_secs(45),
            "mutant {i} took {:?}",
            one.elapsed()
        );
        match staged {
            IsoStaging::Extracted { .. } => {
                extracted += 1;
                assert!(PACKAGE_DB_MARKERS.iter().any(|m| ws.join(m).is_file()));
            }
            IsoStaging::Unscannable(_) => {
                refused += 1;
                assert_eq!(names_under(&ws), Vec::<String>::new(), "mutant {i}");
            }
        }
        assert_eq!(names_under(&sentinel), Vec::<String>::new());
        let siblings: Vec<String> = std::fs::read_dir(base.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n != "sentinel" && !n.starts_with("ws-"))
            .collect();
        assert!(
            siblings.is_empty(),
            "mutant {i} wrote beside the workspace: {siblings:?}"
        );
        std::fs::remove_dir_all(&ws).ok();
    }
    eprintln!(
        "squashfs mutation run: {iters} images, {extracted} extracted, {refused} refused, {:?}",
        started.elapsed()
    );
}

/// Write the locator's seed images (and, where `xorriso` is installed, real
/// media) into `$AK_ISO_FUZZ_CORPUS` for a cargo-fuzz campaign
/// (`backend/fuzz/README.md`). Ignored: run it on demand.
#[test]
#[ignore = "writes the fuzz seed corpus on demand"]
fn write_fuzz_seed_corpus() {
    let Ok(dir) = std::env::var("AK_ISO_FUZZ_CORPUS") else {
        panic!("set AK_ISO_FUZZ_CORPUS to the corpus directory");
    };
    let dir = PathBuf::from(dir);
    std::fs::create_dir_all(&dir).unwrap();
    let mut seeds = locator_seeds();
    seeds.push(test_iso::build(&IsoSpec::live(
        "boot",
        "vmlinuz",
        b"kernel".to_vec(),
    )));
    let (d, f) = LAYERED_MARKERS[0];
    seeds.push(test_iso::build(&IsoSpec::live(d, f, squashfs_payload())));
    if xorriso_available() {
        for level in ["1", "3"] {
            let tree = tempfile::tempdir().unwrap();
            let path = tree.path().join("tree/live/filesystem.squashfs");
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, squashfs_payload()).unwrap();
            let out_iso = tree.path().join("out.iso");
            let ok = std::process::Command::new("xorriso")
                .args([
                    "-as",
                    "mkisofs",
                    "-quiet",
                    "-R",
                    "-J",
                    "-iso-level",
                    level,
                    "-o",
                ])
                .arg(&out_iso)
                .arg(tree.path().join("tree"))
                .status()
                .unwrap()
                .success();
            assert!(ok);
            seeds.push(std::fs::read(&out_iso).unwrap());
        }
    }
    for (i, seed) in seeds.iter().enumerate() {
        std::fs::write(dir.join(format!("seed-{i:02}.iso")), seed).unwrap();
    }
}
