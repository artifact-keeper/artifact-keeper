---
section: Fixed
issues: [#5692]
---
- **Native conda uploads now store the package's conda identity before triggering scan-on-upload** (#5692). The trigger used to run while the artifact metadata was still unwritten, so the dependency scan either missed the purl and PyPI aliases entirely or found them only when its worker happened to start late; the same bytes could be graded `unrated`/`not_cataloged` on one upload and `incomplete` on another. The metadata upsert and package analysis now run first, and the scan trigger follows them, so every scan sees the stored identity. The Helm native upload path was reordered the same way because its scan reads the chart metadata for declared dependencies.
