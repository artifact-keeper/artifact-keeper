---
section: Fixed
issues: [#5356]
---
- **The age-gate `451` is no longer cacheable** (#5356). An age-gate block now carries `Cache-Control: no-store`, so a CDN, client cache or proxy cannot keep refusing a version after a review approves it or it ages past the gate (RFC 7725 makes a `451` cacheable by default). Backport of the fix in #5257.
