---
section: Fixed
issues: [#5616]
---
- **A generic virtual download served from a stale member is marked stale** ([#5616]). When a remote member answered under the stale-if-error grace, the generic virtual download served its body with `200` but without the `Warning: 110` and `X-AK-Stale-Since` headers that a direct remote serve carries, as `docs/proxy-cache-freshness.md` documents. The virtual serve now carries both.
