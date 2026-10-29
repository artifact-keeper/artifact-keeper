# Scanner workspace: ISO9660 live media and the shared squashfs path (design note)

**Date**: 2026-10-23
**Status**: Implemented for 1.12.0 (#1966) along the recommendations below,
with the differences listed under "Implementation notes" at the end. The
open questions stay open for the maintainer; the implementation can switch
either choice without changing its interface.
**Issues**: #1966 (ISO rootfs inventory), #1429 (incus on the shared workspace lifecycle)
**Depends on**: the `ScanWorkspace::prepare_with` extractor hook (#1429, PR #4925)

The maintainer deferred #1966 out of 1.11.0 because an ISO9660 parser in the
scan path is new supply-chain and memory-exhaustion surface. This note settles
the open choices before code is written: which reader parses the ISO, what
extracts the embedded squashfs, which budgets bound each layer, how deep
nesting may go, and what the scan reports when it cannot get a rootfs.

The maintainer's plan on #1966 named `backhand` for squashfs and an ISO crate
under the shared mid-stream extraction budget. This note recommends the
opposite on both counts (the shipped `unsquashfs` with selective extraction,
and an in-tree locator rather than an ISO crate). Those are recommendations
for review, not decisions, and are listed as open questions at the end.

## Where the code stands after #1429

- `ScanWorkspace::prepare_with(base, prefix, artifact, content, extractor)`
  owns the job directory (`<base>/<prefix>-<artifact>-<job>`, #4668), the
  `WorkspaceGuard` (removal on every exit including the wall-clock budget,
  #3565), cleanup when extraction fails, and a check that the scan root the
  extractor returns lies inside the workspace.
- Two extractors ride it: `StagedArtifactExtractor` (the archive formats,
  in-process `tar`/`zip`/`zstd`/`bzip2` under `ExtractionBudget`, 2 GiB and
  200,000 entries by default) and `IncusRootfsExtractor` (`tar` or
  `unsquashfs` child processes, then a post-extraction walk that rejects
  escaping symlinks and enforces 64 GiB / 2,000,000 entries, compressed input
  capped at 16 GiB).
- `unsquashfs` 4.7.5 ships in the UBI runtime image, built from the pinned
  upstream tarball with hardening flags (#4469, Dockerfile.backend stage 5a),
  and the non-root exit-2 handling is in place (#4470).

An ISO extractor is a third `WorkspaceExtractor`. Nothing in the lifecycle
changes for it.

## What a live ISO looks like

Measured with `xorriso -as mkisofs` 1.5.8 (the tool Debian live-build and most
distribution media builders use) on a tree holding `live/filesystem.squashfs`:

| Build flags | ISO9660 name | Rock Ridge `NM` |
|---|---|---|
| default (`-iso-level 1`), `-R -J` | `LIVE/FILESYST.SQU;1` | `live/filesystem.squashfs` |
| `-iso-level 3 -R -J` | `LIVE/FILESYSTEM.SQUASHFS;1` | `live/filesystem.squashfs` |

So the plain ISO9660 name is only reliable on level 3 media (the layout the
#1966 reporter shows). Any reader we use must read Rock Ridge `NM` entries, or
the locator silently misses level 1 media. Joliet is not needed: the Linux
live media builders that write Joliet also write Rock Ridge, and media with
Joliet only (Windows) carries no Linux rootfs to find.

Known rootfs locations to probe, all at depth 2 from the ISO root:

| Media | Path | Notes |
|---|---|---|
| Debian live | `live/filesystem.squashfs` | single squashfs |
| Ubuntu before 22.10, Mint | `casper/filesystem.squashfs` | single squashfs |
| Ubuntu 22.10 and later | `casper/minimal.squashfs`, `casper/minimal.standard.squashfs`, `casper/minimal.standard.live.squashfs` | layered: each layer is a diff over the previous one |
| Fedora, RHEL family | `LiveOS/squashfs.img` | older media nest an ext4 `LiveOS/rootfs.img` inside the squashfs |

## Choice 1: the ISO reader

Options considered:

| Option | Surface | Notes |
|---|---|---|
| `hadris-iso` 2.5.0 (MIT) | ~9 workspace crates (`hadris-*`), `bytemuck`, `spin` | actively released (2.5.0 on 2026-10-15, 3.0 in rc), reads Rock Ridge and Joliet, MSRV 1.88 |
| `cdfs` 0.2.3 (MIT OR Apache-2.0) | `nom`, plus `clap`, `fuser`, `simple_logger` as normal dependencies | last release 2023-10; the FUSE binary's deps come along with the library |
| `iso9660_simple`, `iso9660-rs` | small | low adoption, little history |
| `xorriso` or `bsdtar` child process | a second large C parser of untrusted input | not in the runtime image; would be a self-built binary that the image scanners and dependabot cannot see, like `unsquashfs` today |
| in-tree locator | none | see below |

**Recommendation: an in-tree locator, not a crate.** The scan never needs a
general ISO reader. It needs to answer one question: "does this image hold
one of a fixed list of files at depth 2, and where is its extent?" That is:

1. Check `CD001` at offset 32769 (volume descriptor at sector 16). This is
   also the detection magic; the `.iso` extension alone is not trusted.
2. Read the primary volume descriptor's root directory record.
3. Read at most two directory extents per probe path (root, then `live/`,
   `casper/` or `LiveOS/`), matching names case-insensitively on the Rock
   Ridge `NM` entry when present and on the ISO9660 name with `;1` stripped
   otherwise. `NM` continuation (`CONTINUE` flag, `CE` areas) is read with a
   cap on total system-use bytes per record.
4. Return the file's extent: logical block, length, and the multi-extent
   chain for files over 4 GiB (flag bit 7), or refuse multi-extent files
   explicitly in the first version.
5. Copy that byte range of the artifact into the workspace.

Every read is bounds-checked against the artifact length; a directory extent
is capped (1 MiB is far above any real directory at these paths); there is no
recursion and no tree walk, so directory loops, relocated directories (`RE`,
`CL`, `PL`) and deep nesting cannot be reached. That is roughly 300 lines plus
tests, with zero new dependencies, and its whole input surface fits in a
fuzz target. A crate would bring a full tree walker, path tables, El Torito
and Joliet decoders that the scan does not use but would still parse.

If the maintainer prefers a crate anyway, `hadris-iso` is the one to take:
it is the only maintained candidate with Rock Ridge support, and its
allocation-free reader suits the memory constraints below. `cdfs` should not
be taken while its library and FUSE binary share one dependency list.

## Choice 2: the squashfs extractor

`backhand` 0.25.5 (MIT OR Apache-2.0, ~300k downloads, MSRV 1.90, below our
1.98 pin) versus the shipped `unsquashfs`.

| | `unsquashfs` (shipped) | `backhand` (in-process) |
|---|---|---|
| Supply chain | self-built C binary, invisible to Trivy, grype and dependabot; CVE watch is manual | Rust crate, visible to `cargo audit` and dependabot; pulls `deku`, `xxhash-rust`, and a second `zstd` major (0.13, we are on 0.14) |
| Memory | data and fragment queues bounded by `-da` / `-fr` (256 MiB default each) | `FilesystemReader` builds the whole node tree in memory, proportional to the entry count; needs a superblock `inode_count` cap before parsing |
| Byte budget | enforced after extraction by the post-walk guard; a bomb fills the volume up to the cap before it is caught | enforceable mid-stream: we write each file ourselves through `copy_entry_bounded` and `ExtractionBudget` |
| Cancellation | child killed on drop (`kill_on_drop`) | blocking task checks the guard's cancel flag per entry, as the archive extractors do |
| Non-root quirks | device nodes and xattrs handled (#4470) | we choose what to materialise; device nodes and xattrs are simply not written |
| Code reuse | the incus path today | new code; incus would move to it later or keep `unsquashfs` |

**Recommendation: keep `unsquashfs` for #1966 and close its one real gap,
the after-the-fact byte budget, with selective extraction.** Package inventory
does not need the whole rootfs. Trivy and grype build the OS inventory from a
small, known set of paths:

- `etc/os-release`, `usr/lib/os-release` (on Debian the first is a symlink to
  the second)
- `var/lib/dpkg/` (`status`, `status.d/`, and the `info/*.list` and
  `*.md5sums` files)
- `var/lib/rpm/`, `usr/lib/sysimage/rpm/`
- `lib/apk/db/installed`

`unsquashfs -d <dest> -follow-symlinks <image> <paths...>`, with the flags the
incus path already passes (`-no-xattrs -quiet -no-progress`), extracts only
those (following the os-release symlink inside the image, not on the host), so
the extracted tree is the package DB alone (tens of MiB for a full desktop
image, most of it `var/lib/dpkg/info/`), whatever the image claims. A 2 GiB squashfs bomb never gets the chance to write more than the
package DB paths it names. Checked locally with `unsquashfs` 4.6.1 against an
image holding a 5 MB blob, an `etc/os-release -> ../usr/lib/os-release`
symlink and a dpkg `status`: the output was the symlink, its target and the
status file (8 KiB), and a requested path the image lacks
(`lib/apk/db/installed`) was a warning with exit 0 (with `-no-xattrs`; without
it a non-root run on an image carrying `security.selinux` xattrs exits 2), so
one path list serves every distribution. `-follow-symlinks` implies
`-no-wildcards` (a glob such as `var/lib/dpkg/info/*.list` is then reported as
"can't be resolved" and skipped), so the path list names directories, not
globs: a directory extract path brings its whole subtree, which for
`var/lib/dpkg/` includes `info/`. The listing below bounds what that subtree
may hold.

A crafted image can still make one named path enormous (a 50 GiB
`var/lib/dpkg/status` of zeros compresses to almost nothing). So the
extraction is preceded by a listing of the same paths (`unsquashfs -lls
-follow-symlinks <image> <paths...>`), which reads only the directory and
inode tables and reports each file's declared size; the scan refuses before
extracting if the declared total exceeds a small cap (256 MiB is far above any
real package DB set). The declared size is what `unsquashfs` writes, so the
listing is an exact pre-check, not an estimate. The existing post-extraction
guard still runs over the result. This is the change that makes the "shared
mid-stream extraction budget" moot for squashfs: there is no stream large
enough to need it.

The cost is coverage: language packages and binaries inside the image (Go
build info, Python site-packages, JARs) are not inventoried. For #1966's use
case (OS package inventory of live media for Dependency-Track) that is the
point; a full-rootfs mode can be a follow-up behind a per-repository setting.

`backhand` becomes the better choice if a full-rootfs mode is ever wanted
under a hard mid-stream budget. That is a separate decision, and it should
move incus at the same time so the two image paths keep sharing one squashfs
extractor (the reason #1429 and #1966 were paired).

## Choice 3: budgets and memory ceilings

- **Input**: the ISO is already in memory as the artifact's `Bytes` when the
  scanner runs (every scanner receives the full artifact). The locator works
  on that slice directly and writes only the squashfs extent to disk, so the
  ISO layer adds no second copy. The extent is capped by the incus
  compressed-input ceiling (`MAX_INCUS_SCAN_COMPRESSED_BYTES`, 16 GiB), since
  it is the same kind of input.
- **Extracted tree**: the incus caps (`MAX_INCUS_SCAN_EXTRACTED_BYTES`,
  64 GiB, and 2,000,000 entries) apply, not the 2 GiB archive caps. An ISO
  rootfs is an OS image, not a package. With selective extraction the real
  tree is tiny, so these are a backstop. No new environment variables.
- **Concurrency**: unchanged. The scan holds the per-tenant and global
  extraction permits (#2555) for the whole scan, as every scanner does.
- **Locator reads**: bounded by construction (fixed path list, two directory
  extents per path, 1 MiB per extent, capped system-use bytes per record).

## Choice 4: nesting depth

Two container layers, fixed: the ISO, then one squashfs (or, for layered
Ubuntu media, an ordered list of squashfs layers extracted into the same
tree, each through the same selective path list and the same caps). Nothing
found inside the rootfs is unpacked further by us; the engines handle what
they understand. An ext4 `rootfs.img` inside a Fedora `squashfs.img` is not
mounted or parsed: the scan reports it (below) rather than adding an ext4
reader.

Open question for the maintainer (repeated at the end): support layered
Ubuntu media in the first PR (extract `minimal`, then `minimal.standard`, then
`minimal.standard.live`, later layers overwriting earlier files; overlay
whiteouts are character devices that the non-root extractor skips, which is
harmless for the package DB because each layer's `dpkg/status` is a whole
file), or ship single-squashfs media first and report layered media as
unsupported.

## Choice 5: failure reporting

The bug class #1966 is about is a scan that returns zero packages and reads
as clean. Every way the ISO path can fail to produce a rootfs must therefore
surface:

| Situation | Outcome |
|---|---|
| Not ISO9660 (no `CD001`) | not this extractor; existing behaviour |
| ISO with none of the probe paths (installer-only media, Windows media) | scan completes with `scan_completeness = not_cataloged` and a reason naming the paths probed |
| Probe path found but squashfs corrupt, or `unsquashfs` exit 1 | scan fails (`failed`), message from the extractor, never a clean empty result |
| Squashfs extracted but no package DB present (ext4-in-squashfs, unusual distro) | `not_cataloged` with a reason naming what was found |
| Cap breach (input, bytes, entries) | scan fails, the same messages incus uses today |

`scan_packages` persistence is the existing path (`ScanOutput::packages` from
`from_trivy_report`); the extractor only has to hand the engines a rootfs.
`inventory_status` keeps its current meaning (`complete`, `partial`,
`failed` persistence of what was cataloged).

## Open questions for the maintainer

1. **Squashfs extractor.** The plan on #1966 named `backhand`. This note
   recommends keeping `unsquashfs` with selective extraction and a listing
   pre-check (Choice 2), and keeping `backhand` for a possible full-rootfs
   mode. Which one #1966 uses is the maintainer's call.
2. **ISO reader.** The plan on #1966 named an ISO crate under the shared
   mid-stream extraction budget. This note recommends an in-tree locator with
   `hadris-iso` as the crate if one is preferred (Choice 1). Also the
   maintainer's call.
3. **Layered Ubuntu media.** Support the `minimal`, `minimal.standard`,
   `minimal.standard.live` layer stack in the first PR, or report layered
   media as unsupported until a follow-up (Choice 4). Left open.

## Testing and fuzzing

- Unit tests build ISOs at test time with `xorriso` and squashfs images with
  `mksquashfs` (the services-1 CI leg installs squashfs-tools already; xorriso
  would be added there), covering level 1 and level 3 names, missing Rock
  Ridge, each probe path, layered media if in scope, and truncated or
  out-of-bounds extents.
- A fuzz target for the locator. The repository has no fuzz harness today
  (`util/bounded_archive.rs` has unit tests, not a fuzzer), so this adds `backend/fuzz` with `cargo-fuzz` and one
  target over `locate_rootfs(&[u8])`. It is cheap because the locator is a
  pure function of a byte slice.
- DTF tier `scan-iso-rootfs-inventory`: an ISO built at run
  time with a squashfs holding a dpkg `status` that lists a known-vulnerable
  package; assert `scan_packages > 0` and the finding; a second fixture with a
  corrupt squashfs asserts the scan fails rather than grading clean.

## Out of scope

- Full-rootfs extraction and language-package inventory of ISOs.
- ext4, UDF, and VM disk images (QCOW2 stays refused, as in incus).
- Moving incus to `backhand` or to selective extraction. Incus keeps its full
  extraction; the two paths share the lifecycle and the `unsquashfs`
  invocation, not the path list.

## Implementation notes (1.12.0)

What #1966 shipped, against the choices above. Operator-facing behaviour is
in `docs/iso-image-scanning.md`.

- **Reader and extractor**: the in-tree locator
  (`services/iso_rootfs/locator.rs`) and the shipped `unsquashfs` with
  selective extraction and the `-lls` pre-check, as recommended. The
  extractor is reached through the `ScanWorkspace` staging step that Grype
  and Trivy filesystem scans already use (`StagedArtifactExtractor`), so
  every engine sees the package database at the workspace root, where its
  distribution detection looks.
- **Probe paths**: `images/install.img` (Fedora, RHEL, Rocky and Alma
  installer media) is probed after the three live layouts.
- **Budgets**: the declared-size pre-check and the post-extraction guard use
  the scan-workspace ceilings (`MAX_SCAN_EXTRACTED_BYTES`, default 2 GiB, and
  200,000 entries), not the Incus caps and not a separate 256 MiB cap: the
  tree is the package database alone, and one setting operators already tune
  is simpler than a new one. Each `unsquashfs` child also runs
  single-threaded with 32 MiB queues, under wall-clock timeouts (120 s list,
  300 s extract) and address-space (1 GiB), CPU-time (300 s) and file-size
  (the byte ceiling) rlimits.
- **Nesting**: the embedded file must start with the squashfs magic; a
  nested ISO9660 image is refused, so the depth is fixed at two.
- **Failure reporting**: every failure to produce a package database (no
  probe path, layered media, corrupt squashfs, ceiling breach, escaping
  symlink, no dpkg/rpm/apk database) leaves the workspace empty and is
  recorded `not_cataloged` with `inventory_status = 'partial'`, rather than
  some of them failing the scan. An ISO upload expects a catalog in any
  repository format (`upload_expects_catalog`), so an empty catalog is never
  a clean grade. #4336 can map that state to its `incomplete` grade status.
- **Layered Ubuntu media** (open question 3): reported unsupported for now.
- **Fuzzing**: `backend/fuzz` holds a cargo-fuzz target over
  `locate_rootfs`, and bounded mutation runs over the locator and the
  squashfs path run in every CI build of the services-1 shard.
