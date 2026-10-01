---
section: Fixed
issues: [#3925]
---
- **Migrated RPM repositories are indexed natively** (#3925). The importer now records each `.rpm` header's metadata exactly as an upload does, so the repodata served for a migrated RPM/YUM repository carries summaries and dependencies, and RPM is no longer reported as a file-copy-only format. A package whose header exceeds the repodata indexing limits is still migrated and listed from its filename. Conan, Conda and Debian repositories still migrate as file copies with the empty-index warning shown in the assessment and report.
