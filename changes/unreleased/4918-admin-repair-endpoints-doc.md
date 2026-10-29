---
section: Changed
issues: [#4918]
---
- **The admin repair endpoints have an operator page** (#4918). `docs/operations/admin-repair-endpoints.md` covers `POST /api/v1/admin/repositories/{key}/reindex-storage` (Maven and Gradle ghost objects) and `POST /api/v1/admin/repositories/{key}/backfill-debian` (hosted Debian packages migrated without a control document): when to run each, what they read and write, the admin-only access, per-repository lock and audit actions (`STORAGE_REINDEX_RUN`, `DEBIAN_BACKFILL_RUN`), the `limit` cap and the backfill's `after` / `next_after` continuation with curl loops, every report field, including the rows the backfill reports but does not move, and the cost on a very large repository. Documentation only; no behaviour change.
