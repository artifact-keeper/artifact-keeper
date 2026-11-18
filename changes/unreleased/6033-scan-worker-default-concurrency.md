---
section: Fixed
issues: [#6033]
---
- **With `SCAN_WORKER_CONCURRENCY` unset, the scan worker now runs as many jobs at once as `MAX_CONCURRENT_SCAN_EXTRACTIONS` allows, as documented** (#6033). The worker fell back to a fixed 4 whatever `MAX_CONCURRENT_SCAN_EXTRACTIONS` was set to, so a pod with `MAX_CONCURRENT_SCAN_EXTRACTIONS=1` claimed four jobs, three of which held their claim and lease while they waited on the one extraction permit, and the `running` count in `GET /api/v1/admin/security/scan-queue` and the `ak_scan_worker_slots_*` metrics overstated the work in progress. Unset now means the same value the extraction limit resolves to (default 4); a set `SCAN_WORKER_CONCURRENCY` is used as before. A worker whose extraction limit is 1 now runs one job at a time, and while a rescan holds it (rescans take at most half the slots, one on a single-slot worker) other jobs wait; set `SCAN_WORKER_CONCURRENCY` to 2 or more to keep a slot free.
