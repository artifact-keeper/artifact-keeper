---
section: Fixed
issues: [#5615]
---
- **A download through a generic virtual repository now carries the serving member's `ETag`, so `If-Range` answers `206`** ([#5615]). The virtual arm of `GET /api/v1/repositories/{key}/download/*path` (and `/general/{key}/*path`, and `GET .../artifacts/*path` on a virtual) built its response without an `ETag`, so a ranged request with `If-Range` never matched and always got the whole object back. The response now carries the validator of the member that served it, a hosted member's quoted SHA-256 or a remote member's upstream `ETag`, and `If-Range` naming it is honoured.
