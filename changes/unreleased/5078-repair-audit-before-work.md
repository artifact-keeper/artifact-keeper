---
section: Fixed
issues: [#5078]
---
- **The admin repair endpoints now audit a run before it starts** (#5078). `POST /api/v1/admin/repositories/{key}/reindex-storage` and `.../backfill-debian` wrote their audit row only when the call returned, so a call cut off by the request timeout or a client disconnect left no record of the rows it had already registered or moved, and an unknown repository key was not audited at all. Each call now writes a `started` row before any work, then `completed` (with the report counts) or `failed`, or `cancelled` when the call is dropped mid-run, tied together by a `run_id`, like the storage scrub. Existing fields (`repository`, `dry_run`, the counts, `error`) keep their names.
