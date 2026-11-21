---
section: Security
issues: [#6394]
---
- **The backend image's bundled `buildctl` now links containerd v2.3.7** (#6394). It fixes CVE-2026-95839 (containerd daemon crash via a malformed digest in a subject-annotated descriptor), which the Docker Publish scan reported against containerd v2.3.6 in `buildctl`. BuildKit stays at v0.33.1. No v0.33.x release carries the fix, so the build overrides containerd to v2.3.7, the patch release on the same line. `buildctl` is a client and does not run the containerd daemon the advisory describes.
