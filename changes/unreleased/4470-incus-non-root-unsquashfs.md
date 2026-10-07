---
section: Fixed
issues: [#4470]
---
- **Incus SquashFS scans no longer fail on images with extended attributes or device nodes** (#4470). The backend runs as a non-root user, and `unsquashfs` exits 2 on such an image because it cannot write `security.*` xattrs or create device nodes, which most real rootfs images carry; the scanner treated that as a failed extraction. `unsquashfs` now runs with `-no-xattrs`, and exit 2 is a logged warning as long as a non-empty tree came out. Fatal errors (exit 1, such as an unsupported compressor) still fail the scan. Unified tarballs get the same treatment: a `Cannot mknod` from `tar` on a device node is a warning, and any other `tar` error still fails.
