---
section: Fixed
issues: [#5079]
---
- **The repository `test-upstream` probe now reaches the upstream the way proxy fetches do** (#5079). `POST /api/v1/repositories/{key}/test-upstream` now applies the upstream URL validation before it sends anything (a URL that validation refuses answers `400`) and goes out on the repository's egress route (`direct` or `explicit` proxy), so its result reflects the path real fetches take. Its `502` message, and the curation sync failure messages built from HTTP client errors, no longer include the request URL.
