---
section: Changed
issues: [#5002]
---
- **A chunked upload into a format without a native finalize now dispatches its format handler, and every format metadata document is written in the artifact transaction** (#5002). Completion previously ran a format parser only for Maven, Gradle, npm, PyPI, RPM, Incus and Debian; other formats stayed generic even though their handler derives metadata from the upload path. The completion now calls the handler's `parse_metadata` with an empty body and records its document, while paths a native route declines and the generic handler keep the old behaviour. The document is written in the same transaction as the `artifacts` row, so a crash cannot leave an indexed artifact without its metadata; catalog rows, RPM scriptlet analysis, cache invalidation and the Debian/RPM auxiliary tables remain after the commit. See `docs/chunked-uploads.md`.
