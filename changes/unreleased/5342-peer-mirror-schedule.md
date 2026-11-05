---
section: Fixed
issues: [#5342]
---
- **A `mirror` peer subscription's `replication_schedule` now runs** (#5342). The cron schedule was stored and shown, but nothing acted on it, so `mirror` behaved exactly like `push` and existing content moved only when someone called `POST /api/v1/peers/{id}/repositories/{repo_id}/sync`. The sync worker now checks enabled `mirror` subscriptions about once a minute and, when a schedule is due, queues every artifact the peer has no task for (the same work as the `sync` route), setting `last_replicated_at` in the same transaction so it advances only when the pass completes. A subscription that has never completed a pass runs one on the first check, and missed occurrences add up to one pass. Scheduled passes honour the upstream-jobs switch (#5288): none runs while it is on. An invalid cron expression is now refused with 400 instead of being stored and never firing.
