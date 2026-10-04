---
section: Added
issues: [#2359]
---
- **Curated RPM repositories can now prune old snapshot versions automatically** (#2359). Every curated RPM snapshot (`@N`) kept its database rows, signed repodata and cached packages forever, so a nightly mirror grew by one full snapshot per night. Setting `RPM_VERSION_RETENTION_KEEP=N` (default unset: keep everything) starts an hourly pass, run by one replica at a time under a scheduler lease, that keeps each repository's N newest versions plus its active publication, deletes the older versions, and deletes the objects stored under their `@N` prefix. A pruned `@N` URL stops resolving; the active publication and the newest version are never removed, so version numbers are never reissued.
