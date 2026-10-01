---
section: Fixed
issues: [#4197]
---
- **Maven `maven-metadata.xml` and checksum/signature sidecar uploads no longer register bogus package catalog rows** (#4197). The generic finalize path (replication, migration, generic push) applied no metadata skip: `parse_coordinates` read the artifactId directory as a version and registered `groupId:artifactId` at a nonsense version. Publish time now applies the same skip predicate as the catalog backfill, so the two paths can never disagree.
