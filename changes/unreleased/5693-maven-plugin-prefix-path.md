---
section: Fixed
issues: [#5693]
---
- **An artifact-level `maven-metadata.xml` that mentions `<plugins>` is no longer published as a plugin-prefix mapping** ([#5693]). Plugin-prefix detection looked only for `<plugins` in the body, so a deployed artifact-level (`g/a/maven-metadata.xml`) or version-level (`g/a/1.0-SNAPSHOT/maven-metadata.xml`) document carrying such a block got an artifact row, was queued to push peers and left the row-less metadata lifecycle (storage-GC and repository-delete guards). Only a document at a group-level path with no `<versioning>` block, the only shape Maven writes for prefix mappings, now takes the plugin-prefix path.
