---
section: Fixed
issues: [#4544]
---
- **Two writers can no longer deadlock on precomputed RPM repodata bookkeeping** (#4544). Marking a hosted RPM root dirty used to lock that root's row in `rpm_repodata_roots` until the writer committed, so two transactions that changed two roots in opposite order (for example two metadata updates, which take no other per-repository lock) could deadlock, and Postgres aborted one of them. Writers now only append to `rpm_repodata_dirty` (migration 309), which never waits; the background builder moves those marks onto the roots.
