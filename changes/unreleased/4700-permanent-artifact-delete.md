---
section: Added
issues: [#4700]
---
- **Admins can permanently delete an artifact, so a release can be re-uploaded without waiting for storage GC** (#4700). A deleted release stayed in the trash as a tombstone, and every upload path refused different bytes at that path until GC hard-deleted it, which with `GC_TRASH_RETENTION_DAYS` set meant the whole retention window. `DELETE /api/v1/admin/trash/{id}` now purges one trashed artifact, and `DELETE /api/v1/repositories/{key}/artifacts/{path}?permanent=true` deletes and purges in one call. Both are admin only and record `ARTIFACT_PURGED`.

  The stored object, and a Maven artifact's checksum sidecars, are deleted only when no other artifact or revision in the same storage scope still references the key; otherwise GC reclaims them later. OCI manifests and blobs are refused (409), as restore refuses them, because their tags and shared layers belong to storage GC and blob GC. Proxy-cache objects are never deleted.
