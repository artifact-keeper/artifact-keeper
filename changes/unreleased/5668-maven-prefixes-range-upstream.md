---
section: Fixed
issues: [#5668]
---
- **An empty Maven repository no longer publishes a prefix file that blocks SNAPSHOT metadata** ([#5668]). A hosted repository with no artifacts yet (and a virtual whose members publish no groupIds) served a header-only `.meta/prefixes.txt`, which Maven Resolver reads as "deny every path" and keeps for a day: `mvn deploy` then could not read the SNAPSHOT `maven-metadata.xml` it had just written ("the prefixes file appears stale") and the timestamped build number stayed at 1. That file (and its checksum) is now `404` with `Cache-Control: no-store` until the repository has a groupId, and the first publish makes the next request serve the real file.
