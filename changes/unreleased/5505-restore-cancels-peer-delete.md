---
section: Fixed
issues: [#5505, #5497]
---
- **Restoring a trashed artifact now cancels its queued peer deletes and pushes it again** (#5505, #5497). A delete task queued for a peer that was offline when the artifact was deleted stayed pending after an admin restored the artifact from trash, so the peer deleted the restored artifact when it came back and nothing re-pushed it. `TrashService::restore` now cancels the artifact's pending and failed delete tasks and queues a push for every eligible push or mirror peer, forcing a finished push back to `pending` because the peer may have applied the delete before the restore. A delete a worker already claimed is left to finish and the push follows it. The cancellation and the push are written in the restore's own transaction, so a crash cannot leave a live artifact with a pending delete.

  A peer that stays offline longer than the trash retention still keeps the artifact: the trash purge and storage GC hard-delete the row, and `sync_tasks.artifact_id` cascades, so the queued delete is dropped with it.
