---
section: Fixed
issues: [#6285]
---
- **Composer `search.json` on a Virtual now searches its members, and a Remote answers 501 instead of an empty result** (#6285). The search only looked at artifacts stored in the requested repository, so a Virtual always answered `{"results":[],"total":0}` while `packages.json` and `p2/` resolved the same packages through its members. A Virtual now searches the Local and Staging members the caller may read (#3323) in one query, so `total`, pagination and the `type` filter cover all of them, and result URLs point at the Virtual. A Remote caches dist files under their archive path, not under the package name, and nothing forwards the search upstream, so it now answers `501 Not Implemented` like hosted npm audit (#5631).
