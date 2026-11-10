---
section: Fixed
issues: [#5669]
---
- **Maven metadata (`maven-metadata.xml` and its checksums) through a Virtual where no member serves and at least one is unavailable (5xx, 408/425/429, DNS/connect/TLS failure or connect timeout) now answers 503 with Retry-After and is not cached, instead of a cacheable 404; a member that misses the 20 s deadline still gets the 502** ([#5669]). This is the maven-metadata subset of #5621.
