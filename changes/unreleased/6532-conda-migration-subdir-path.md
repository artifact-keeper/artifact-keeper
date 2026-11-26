---
section: Fixed
issues: [#6532]
---
- **A conda package migrated from Artifactory is listed in the destination channel's `repodata.json`** (#6532). The migration stored it under `<name>/<version>/<file>`, the layout it uses for formats without their own rule, so `noarch/tzdata-2024a-h0c530f3_0.conda` became `tzdata/2024a/...` and was indexed under a subdir called `tzdata` that no client asks for. Conda packages now keep their source path, `<subdir>/<file>`. Packages migrated before this stay at the old path, a re-run imports them again at the right one. The `index.json` metadata of a migrated package is still not recorded (#5266), so its repodata record carries no dependencies yet
