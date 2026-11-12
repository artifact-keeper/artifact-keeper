---
section: Changed
issues: [#5689]
---
- **A crate download issues fewer database and upstream requests** (#5689). The `repositories` row was read twice on every download from a remote or virtual Cargo repository, once by the curation gate and once by the age gate. One read now serves both, and hosted repositories skip it. The digest gate also reads the crate's cached sparse index entry before fetching it upstream again, falling through to the upstream fetch when the cached entry lacks the version. A failed row read on a remote or virtual download is now an error instead of serving the crate with curation unenforced, as the age gate already did.
