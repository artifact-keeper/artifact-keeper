---
section: Security
issues: [#4588]
---
- **Slow or stalled uploads can no longer hold every global request slot, and health and readiness probes are never shed** (#4588, GHSA-9f9r-c4w8-rjv9). Upload and download routes (Git LFS, OCI blobs, the repository artifact routes, `/api/v1/uploads`, Incus/LXC) are exempt from the `GLOBAL_REQUEST_TIMEOUT_SECS` wall-clock timeout (#3263). Nothing else limited how long a client could take to send a body. A user with write access to one Git LFS repository could open 512 uploads, send the headers and one byte on each, and hold all of `GLOBAL_MAX_CONCURRENCY`'s request slots for as long as the sockets stayed open. Every other request, including `/health` and `/ready`, was then refused with 503, so an orchestrator would also restart or drain the replica. Git LFS also buffered each object (up to 2 GB) in memory before the handler ran. Four changes:
  - An upload body that delivers fewer than `UPLOAD_MIN_PROGRESS_BYTES` (default 16384) during an `UPLOAD_PROGRESS_WINDOW_SECS` window (default 60) spent waiting for data is aborted with `408 Request Timeout`. This is a progress floor, not an idle timeout, so trickling one byte at a time does not keep a request open. Time the server spends on its own work does not count.
  - A principal (an authenticated user, or a client address when anonymous) may have at most `UPLOAD_MAX_IN_FLIGHT_PER_PRINCIPAL` uploads (default 64) in flight on the native-format routes, the repository artifact routes and `/api/v1/uploads`. Further uploads get `429` with `Retry-After`.
  - `/health`, `/healthz`, `/ready`, `/readyz` and `/livez` bypass the global concurrency limit.
  - Git LFS object uploads stream to the upload scratch disk (`AK_UPLOAD_STAGING_DIR`, or `$STORAGE_PATH/.incoming`) while being hashed, then stream into storage, instead of being buffered in memory. The 2 GB per-object limit is unchanged.

  Each setting accepts `0` to turn its limit off. The scratch-disk sizing guide (`docs/operations/upload-scratch-disk.md`) now lists Git LFS uploads and documents these limits. OCI `/v2` uploads get the progress deadline but not the per-principal cap.
