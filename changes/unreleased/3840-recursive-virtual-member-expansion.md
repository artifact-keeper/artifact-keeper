---
section: Fixed
issues: [#3840]
---
- **Virtual repositories whose members are themselves virtual repositories now list and resolve the nested members' content** (#3840). Member expansion was a single-level join, so a nested virtual contributed nothing: the flat listing, the Maven grouped view, the Docker tag view and every download-resolution path saw zero content through it. Expansion is now recursive — leaves are inlined at the nested virtual's slot in depth-first priority order, so listing and download resolution pick the same member for a duplicate coordinate — with an explicit cycle guard (cycle-closing edges are skipped and logged) and the same 32-level depth cap the write-time cycle check enforces. npm packument and cargo index cache invalidation now also reach every ancestor virtual, not just direct parents, so writes to a leaf no longer leave a nested virtual's cached document stale.
