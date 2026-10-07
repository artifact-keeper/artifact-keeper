---
section: Added
issues: [#4417]
---
- **`S3_PUBLIC_ENDPOINT` and `AZURE_STORAGE_PUBLIC_ENDPOINT` set the address presigned download redirects point at** (#4417). Presigned redirects (including the OCI blob `307`) used the backend's own storage endpoint, so with an in-cluster `S3_ENDPOINT` such as `http://storage-minio:9000` every redirected download from outside the cluster failed. When the new variable is set, S3 presigned URLs are signed for and point at that origin (SigV4 covers the host, so the URL is signed for it rather than rewritten), and Azure SAS redirect URLs use that base; the backend's own storage calls keep the internal endpoint. Malformed values (no `http`/`https` scheme, userinfo, query, or a path for S3) stop the backend at startup when it is the primary storage backend; a secondary (per-repository) backend is skipped with a warning. CloudFront, when configured, still signs S3 redirects and the public endpoint is ignored. Unset, nothing changes.

  Operator note: do not enable `PRESIGNED_DOWNLOADS_ENABLED` while the storage endpoint is unreachable from clients and no public endpoint is set. For S3 the proxy in front of the public endpoint must keep the `Host` header and path unchanged; for Azure it must rewrite `Host` to the storage account host (or use the account's custom domain). See `docs/operations/presigned-downloads.md`.
