---
section: Added
issues: [#2525]
---
- **R/CRAN repositories can be migrated from Artifactory and Nexus** (#2525). Nexus `r` and Artifactory `cran` repositories migrate into native CRAN repositories: source packages land at the native path and are listed in `src/contrib/PACKAGES`, and the source's own `PACKAGES*` index files are skipped. Binary packages are copied at their source path but are not yet listed in a binary `PACKAGES` index.
