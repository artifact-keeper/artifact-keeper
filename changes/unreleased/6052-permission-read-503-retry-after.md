---
section: Fixed
issues: [#6052]
---
- **A format-route read that cannot check repository permissions during a database outage now answers `503` with `Retry-After: 1`** (#6052). When the repository's permission-rules entry had left its 30 second cache, a read such as a Git LFS batch or an npm metadata GET answered a bare `503` with no `Retry-After` header, while writes and every other outage path already sent `Retry-After: 1`. Reads now send the same retryable answer, so clients back off and retry.
