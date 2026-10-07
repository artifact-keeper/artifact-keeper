# Incus image scanning

The Incus scanner (`INCUS_SCANNER_ENABLED`, on by default) scans uploaded
Incus/LXC images for OS-package vulnerabilities. It extracts the image's
root filesystem into the scan workspace and runs Trivy over it, either the
local CLI or the scanner-adapter. VM disk images (QCOW2/IMG) and
metadata-only tarballs are skipped.

| image shape | extracted with |
|---|---|
| unified tarball (`.tar.xz`, `.tar.gz`, `.tar.zst`) | `tar`, with `xz` / `zstd` |
| SquashFS rootfs (`rootfs.squashfs`) | `unsquashfs` (#4469) |

The compressed input and the extracted tree are bounded by
`MAX_INCUS_SCAN_COMPRESSED_BYTES` and `MAX_INCUS_SCAN_EXTRACTED_BYTES`.

## SquashFS compression support differs between the images

- **UBI image (`Dockerfile.backend`, the published default):** `unsquashfs`
  is built from the pinned squashfs-tools release, because the UBI 9
  repositories do not carry the package. It supports **gzip, xz and zstd**
  only. A SquashFS image compressed with LZO or LZ4 fails extraction there.
- **Alpine image (`Dockerfile.backend.alpine`):** `unsquashfs` comes from
  Alpine's `squashfs-tools` package and supports all five codecs (gzip, xz,
  zstd, LZO, LZ4).

## Known limitation: non-root extraction

The backend runs as a non-root user. Run that way, `unsquashfs` exits
non-zero on an image whose files carry `security.*` extended attributes or
that contains device nodes, which is most real rootfs images, and the scan
fails. Tracked in #4470.
