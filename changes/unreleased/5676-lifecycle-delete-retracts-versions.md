---
section: Fixed
issues: [#5676]
---
- **Lifecycle (retention) deletes now drop the npm dist-tags and move the catalog Latest of the versions they remove** ([#5676]). The policy sweeps soft-delete in bulk SQL and never reached the cleanup every per-artifact delete runs since [#5604]/[#5632], so a policy that removed an npm package's tagged version left `latest` (or a custom tag) naming it, and `npm install` failed with `ETARGET`, while the Packages page kept the removed version as Latest. After each sweep of a repository the same cleanup now runs once per affected package. The catalog-Latest step also finds a Maven package by its `groupId:artifactId` catalog name (and an SBT package by `org/module`), so a trash restore of a Maven version moves its Latest back up, which it did not since [#5632].
