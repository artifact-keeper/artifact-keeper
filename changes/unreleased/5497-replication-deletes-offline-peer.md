---
section: Fixed
issues: [#5497]
---
- **A delete made while a peer was offline is now replicated once the peer returns** (#5497). The delete fan-out filtered on `pi.status IN ('online','syncing')`, but the sync worker already skips offline peers when it claims a task, so the second gate only meant the task was never queued at all. The peer kept the artifact forever, and a backfill could not repair it because backfill only pushes. The push fan-out never had this filter, so a peer that went offline replicated later uploads but none of the deletes in between.
