---
section: Fixed
issues: [#4916]
---
- **Protobuf label replication no longer loses moves, leaves superseded documents behind, or fails on pre-#4889 rows, and Maven plugin-prefix metadata now reaches peers** (#4916). Each `_labels` write reclaims the previous content-addressed document once no live row names it and carries a monotonic revision that a receiving peer compares before overwriting (equal revisions are broken deterministically by checksum). The sync worker rebuilds an empty legacy label row from its inline label map before transferring it. A group-level plugin-prefix `maven-metadata.xml` (`<plugins>`) gets an artifact row and travels through the Maven upload route like a normal artifact, while artifact-level version indexes remain row-less and peer-regenerated.
