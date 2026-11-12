---
section: Fixed
issues: [#5894]
---
- **An OCI pull of a stored blob or manifest answers `503` while object storage is down, not `404`** (#5894). With the storage backend unreachable, a blob `GET` and a manifest `GET` or `HEAD` for content the repository holds answered `404 BLOB_UNKNOWN` / `MANIFEST_UNKNOWN`, which docker and containerd read as "this image does not exist" and do not retry. They now answer `503 UNAVAILABLE` with `Retry-After` and the fixed storage-unavailable message, like every other route since #5649; a virtual repository's local member does the same on blob `GET` and `HEAD`. A blob or manifest whose object is really missing still answers `404`, and a remote repository still refetches it from upstream.
