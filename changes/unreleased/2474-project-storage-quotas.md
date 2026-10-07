---
section: Added
issues: [#2474, #2475]
---
- **Project storage quotas are now enforced across every repository in the project** (#2474, #2475). `projects.quota_bytes` was stored but ignored, so a project cap could be evaded by spreading uploads across its repositories. Upload admission now also checks the project's aggregate usage, summed from the per-repository usage ledger (hosted artifacts, proxy-cache entries and OCI blobs) over every repository assigned to the project, in addition to the repository's own `quota_bytes`. The authoritative check locks the project row, so concurrent uploads into sibling repositories cannot both pass against the same total. A rejected upload returns `507 QUOTA_EXCEEDED` with `Project storage quota exceeded`. An unset or non-positive project quota means unlimited, as it does for repositories.

  `npm publish` now runs the same repository and project quota admission. Before this it skipped quota checks entirely. A publish addressed to a virtual repository (#968) is charged to the hosted member it resolves to, so the member's project quota applies and the virtual's does not.
