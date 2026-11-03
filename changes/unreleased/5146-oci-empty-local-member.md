---
section: Fixed
issues: [#5146]
---
- **An unrelated empty hosted member no longer blocks below-threshold remote image blobs through a Docker virtual repository** (#5146). Hosted block-on-any applies only when that member references the requested blob; proxy policies, hosted referrers, and fail-closed reference lookup errors remain enforced.
