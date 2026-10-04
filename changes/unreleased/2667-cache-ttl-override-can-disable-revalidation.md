---
section: Changed
issues: [#2667]
---
- **A remote repository's cache TTL can now be set high enough to stop revalidation** (#2667). `PUT /api/v1/repositories/{key}/cache-ttl` capped `cache_ttl_seconds` at 30 days. The maximum is now 315360000 seconds (about ten years), the lifetime immutable artifacts are cached for, so setting it means the remote's mutable paths (indexes, tag manifests) are never revalidated. Overrides read from the database are also clamped to that range, so a hand-edited value can no longer overflow the expiry computation. The web UI's TTL input needs the same maximum (artifact-keeper-web).
