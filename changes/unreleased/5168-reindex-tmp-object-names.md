---
section: Fixed
issues: [#5168, #4323]
---
- **Storage reindex on the filesystem backend now finds objects whose names contain `.tmp.`** (#5168, #4323). The listing skipped every such file, so a Maven file like `x.tmp.jar` was never listed or recovered, and a live row for one was reported as a missing object. It now skips only the backend's own atomic-write staging names, `.tmp.<uuid>` and `<name>.tmp.<uuid>`. RPM version retention uses the same listing, so it now also collects such a file under a version number it is removing.
