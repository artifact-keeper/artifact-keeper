---
section: Fixed
issues: [#4421]
---
- **Two concurrent publishes of the same RPM curation version no longer interleave their repodata writes** (#4421). Both requests passed the "already published" check and wrote the same immutable `@N` repodata keys, so `repomd.xml` and `repomd.xml.asc` could come from different writers and fail verification. A publish now holds a per-version lock for its whole run and re-checks immutability under it; the second request gets 409 Conflict before it writes anything. Marking the version published also requires `published_at IS NULL`, and a lost race at that point returns 409 without deleting the winner's repodata.
