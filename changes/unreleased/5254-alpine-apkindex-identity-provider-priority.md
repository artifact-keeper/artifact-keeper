---
section: Fixed
issues: [#5254]
---
- **Alpine `APKINDEX` now lists every package under its own name and version and carries its `k:` (provider priority) and `i:` (install_if) fields** (#5254). The index generator ignored `provider_priority` and `install_if` in a package's `.PKGINFO`, so `apk add postgresql` stopped with "please select one of the 'provided by' packages explicitly" and `-doc`/`-openrc` style subpackages were never auto-installed. A package uploaded through the generic repository endpoint was also listed under the first two path segments (`P:v3.24` / `V:main`), because the metadata derived at index time never recorded `pkgname`/`pkgver`. The index now takes `P:`/`V:` from the package's own `.PKGINFO` whenever it has been parsed and emits `k:` and `i:` in the order `apk index` writes them.

  Packages stored by an earlier release are repaired automatically: the next `APKINDEX.tar.gz` request re-reads each one once (at most 32 per request, packages missing from the index first) to record the new fields, and corrects the artifact's stored name and version, which listings and search read, to the package's own identity. A package whose bytes cannot be re-read keeps its existing index entry and is not retried.
