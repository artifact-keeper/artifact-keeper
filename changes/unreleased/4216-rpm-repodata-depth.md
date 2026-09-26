---
section: Added
issues: [#4216]
---
- **Hosted RPM repositories can serve independent YUM/DNF metadata at a configured directory depth** (#4216). Set `repodata_depth` on an empty local RPM repository to preserve nested upload paths and isolate each build's packages, metadata, and signatures without creating child repositories. Depth zero preserves existing behavior; unsupported repository modes and unsafe layout changes are rejected explicitly.
