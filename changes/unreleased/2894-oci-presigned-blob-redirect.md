---
section: Added
issues: [#2894]
---
- **OCI/Docker blob pulls can be served by a presigned-URL redirect** (#2894). With `PRESIGNED_DOWNLOADS_ENABLED=true` and a storage backend that signs URLs (S3 with redirect downloads, GCS, Azure, CloudFront), `GET /v2/<name>/blobs/<digest>` now answers `307 Temporary Redirect` to the object store instead of streaming the layer through the backend, so a layer is no longer transferred twice (object store to backend, then backend to client). This covers hosted repositories, local members of a virtual repository, and remote repositories whose proxy cache already holds the layer. Range requests are redirected too (object stores honour `Range` on a presigned GET). `HEAD` is never redirected, and every authorization and vulnerable-image re-block check still runs before the redirect is issued. Proxy-cache entries stored with an upstream `Content-Encoding` or inside a Package Age Policy hold keep streaming.
