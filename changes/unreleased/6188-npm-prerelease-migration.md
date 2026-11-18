---
section: Fixed
issues: [#6188]
---
- **A migrated npm prerelease tarball keeps its package name** (#6188). The importer split `@scope/core/-/core-1.1.6-4.tgz` at the last hyphen and stored it as package `@scope/core-1.1.6` version `4`, so the version was missing from the packument and its tarball URL answered 404. The name now comes from the `<name>/-/` folder of the source path and the version is the rest of the filename, so `1.0.0-4`, `0.5.0-preview-1` and `1.0.0+build` stay whole. Helm charts get the same treatment: the split is at the first hyphen followed by a full SemVer version, so `chart-1.2.3-4.tgz` is chart `chart` version `1.2.3-4`.
