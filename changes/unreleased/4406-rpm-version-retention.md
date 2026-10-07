---
section: Added
issues: [#4406, #2359]
---
- **Curated RPM repositories can now prune old snapshot versions automatically** (#4406, #2359). Every curated RPM snapshot (`@N`) kept its database rows, signed repodata and cached packages forever, so a nightly mirror grew by one full snapshot per night. Setting `RPM_VERSION_RETENTION_KEEP=N` (default unset: keep everything) starts an hourly pass on each replica, run by one replica at a time under a scheduler lease, that keeps each repository's N newest published versions, every unpublished version newer than the newest published one, and its active publication, deletes the other versions, and deletes the objects stored under their `@N` prefix (including objects a crashed publish or pass left behind). A pruned `@N` URL stops resolving; the active publication and the newest version are never removed, so version numbers are never reissued, and unpublished drafts never push a published snapshot out of the window.
