---
section: Changed
issues: [#5620]
---
- **A virtual repository answers `503` with `Retry-After` for an npm packument, a PyPI simple page or a Cargo sparse index entry when no member has it and a member could not answer** (#5620). The #5504 rule (a member's upstream `5xx`, transport failure, timeout or open circuit is not a miss) covered artifact downloads only: these metadata walks still answered `404` ("Package not found in any member repository"), which `npm`, `pip` and `cargo` report as "not found" and some cache, and a `404` also evicted the npm virtual's cached packument. A miss or a permanent `4xx` from every member is still `404`, and a member that answers still serves the merge as before. Helm chart archives, OCI manifests, blobs and tag lists, PyPI file pages and the Go module routes are not changed here.

  **Default change:** clients that saw `404` for these routes during a member outage now see `503` with `Retry-After: 1`.
