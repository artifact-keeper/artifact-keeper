# ISO image scanning

An uploaded ISO9660 image (a live or installer medium) is scanned for the
operating-system packages of the root filesystem it carries, in any
repository format. Before 1.12.0 the image was staged as one opaque file:
the scanners cataloged nothing inside it, and the scan read as a clean
grade A (#1966).

## What is scanned

An upload is treated as an ISO when its bytes carry the ISO9660 volume
descriptor (`CD001` at byte 32769). The `.iso` extension is neither required
nor trusted, and hybrid images (an MBR or GPT at offset 0, which every modern
live medium has) are detected. A file whose name is a known archive type
(`.tar.gz`, `.jar`, `.whl`, ...) or a Debian or RPM package (`.deb`, `.udeb`,
`.ddeb`, `.rpm`) keeps its own path even if its bytes are also ISO9660, and
so does a pinned scan. So does a file whose bytes start with the magic of an
executable (ELF, PE, Mach-O) or of another package or compressed format
(zip, gzip, xz, zstd, bzip2, `ar`, RPM), whatever its name: no ISO medium
starts that way.

The scanner looks for the embedded root filesystem image at these paths:

| Media | Path |
|---|---|
| Debian live (live-build) | `live/filesystem.squashfs` |
| Ubuntu before 22.10, Mint, other casper media | `casper/filesystem.squashfs` |
| Fedora and RHEL-family live media | `LiveOS/squashfs.img` |
| Fedora, RHEL, Rocky and Alma installer media | `images/install.img` |

Names are read from Rock Ridge (`NM`) when the image has it, which is how a
default `xorriso -as mkisofs -R` image names `filesystem.squashfs` (the plain
ISO9660 name is the 8.3 `FILESYST.SQU`), and from the ISO9660 identifier
otherwise. Joliet is not read.

From that squashfs image, only the package databases are extracted, with
`unsquashfs` (the same binary the Incus scanner uses):

- `etc/os-release`, `usr/lib/os-release` and the other release files the
  scanners use to identify the distribution;
- `var/lib/dpkg/` (Debian, Ubuntu), `var/lib/rpm/` and
  `usr/lib/sysimage/rpm/` (Fedora, RHEL family, SUSE), `lib/apk/db/`
  (Alpine).

The scanners (Grype, and Trivy where configured) then catalog those package
databases exactly as they do for a container image, and the packages are
stored as the scan's inventory (`scan_packages`), with their findings.
Language packages and binaries inside the image are not inventoried.

## When the image cannot be inventoried

If no package database comes out of the image, the scan is recorded
`not_cataloged`, with a reason, `inventory_status = 'partial'`, and the
repository reports `has_uncataloged_scan`. It is never a complete, clean
scan. The reason the image could not be read is in the backend log
(`ISO9660 image ... has no scannable root filesystem: ...`). This happens
when:

- none of the paths above exists (data discs, Windows media);
- the media is Ubuntu's layered casper layout (22.10 and later:
  `casper/minimal.squashfs` and the layers on top of it), which is not read
  yet;
- the embedded file is not a squashfs image, is itself an ISO image, or is a
  multi-extent (over 4 GiB), zisofs-compressed or symlinked file;
- the squashfs image is corrupt, or `unsquashfs` is not installed;
- the extraction would exceed the limits below;
- a symlink in the package database points outside the extracted tree, or
  the package database holds a device node, FIFO or socket;
- the root filesystem holds no dpkg, rpm or apk database (for example older
  Fedora media, whose `squashfs.img` carries an ext4 `rootfs.img`, which is
  not mounted or read).

An ISO is not package-shaped, so a `not_cataloged` ISO does not floor the
legacy grade letter, like a plain generic `.zip` (#4154). Its scan reads
`unrated` with the reason, and it counts as uncataloged in the repository's
coverage: the repository's grade status is `incomplete` when other artifacts
were assessed, and `unrated` when the ISO is the only one (see
[Grade status](security/grade-status.md)).

## Limits

The extraction draws on the same ceilings as every other scan-workspace
extraction:

| Limit | Default | Setting |
|---|---|---|
| Bytes the package-database paths may hold | 2 GiB | `MAX_SCAN_EXTRACTED_BYTES` |
| Entries the package-database paths may hold | 200,000 | fixed |
| Concurrent extracting scans | 4 | `MAX_CONCURRENT_SCAN_EXTRACTIONS` |

These are checked twice: against the sizes the squashfs image declares
(`unsquashfs -lls`), before anything is written, and again over the tree
actually written. The declared size is what `unsquashfs` writes, so a
squashfs bomb or a huge sparse file is refused before it reaches the disk.

Each `unsquashfs` run is also bounded:

- single-threaded, with 32 MiB data and fragment queues;
- killed after 120 seconds for the listing and 300 seconds for the
  extraction, and when the scan itself is cancelled;
- an address-space limit of 1 GiB, a CPU-time limit of 300 seconds, and a
  file-size limit equal to the byte ceiling (Linux).

The ISO itself is never unpacked: the scanner reads the volume descriptor and
at most two directories per probed path, and copies the squashfs image's
byte range into the scan workspace. Nothing nested deeper than that squashfs
image is unpacked. The ingestion limits (`MAX_INGEST_DECOMPRESSED_BYTES`,
`MAX_INGEST_ARCHIVE_ENTRIES`) do not apply: nothing in an ISO is decoded at
upload time.

## Requirements

`unsquashfs` must be on the backend's `PATH`. The published images ship it
(see [Incus image scanning](incus-image-scanning.md) for the compression
codecs each image supports: the UBI image reads gzip, xz and zstd squashfs
images, which covers current Debian, Ubuntu and Fedora media).

The design is described in
[the ISO rootfs design note](plans/2026-10-23-scanner-iso-rootfs-design.md).
