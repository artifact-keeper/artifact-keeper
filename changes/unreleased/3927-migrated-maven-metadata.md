---
section: Fixed
issues: [#3927]
---
- **Migrated Maven repositories now serve `maven-metadata.xml`** (#3927). The importer stored Maven files without the coordinate metadata that `maven-metadata.xml` generation reads, so `LATEST`/`RELEASE` resolution fell through to another repository. Each migrated Maven file now records its groupId/artifactId/version, and re-running the migration job repairs repositories migrated before this fix without re-transferring anything.
