---
section: Fixed
issues: [#6207]
---
- **Replication run now and the scheduled mirror pass no longer queue deleted artifacts** (#6207). Both queued a push task for every artifact row of the repository, soft-deleted ones included. The sync worker never claims a push for a deleted artifact, so those tasks stayed `pending` for good, counted in the run now answer and in the pending sync task count. The pass now queues live artifacts only
