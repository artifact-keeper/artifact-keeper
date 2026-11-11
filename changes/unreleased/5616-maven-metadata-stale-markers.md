---
section: Fixed
issues: [#5616]
---
- **A Remote `maven-metadata.xml` served stale now says so** ([#5616]). When the upstream failed and the cached copy was served under the `stale-if-error` grace, `maven-metadata.xml` and its `.sha1`/`.md5`/`.sha256` answered `200` without `Warning: 110` and `X-AK-Stale-Since`. They now carry both, as the other stale serves do. A Virtual Maven merge built from such a member copy carries them too, and is not kept in the virtual metadata cache.
