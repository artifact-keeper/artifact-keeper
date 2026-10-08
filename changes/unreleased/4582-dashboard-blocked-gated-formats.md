---
section: Fixed
issues: [#4582]
---
- **The dashboard's `policy_violations_blocked` counts only what the proxy scan gate refuses** (#4582). Since #4380 it counted proxied content with a blocking verdict under the repository's scan policy without checking that the format runs the gate, so a format that stores `scan_on_proxy` but serves its proxied bytes unscanned (rpm, Go, generic and the others reported as `accepted` by `GET /api/v1/formats`) showed a package as blocked while serving it. The count now uses the same format predicate as the handlers, so it changes automatically as formats adopt the gate. Conda is gated as of #4585.
