---
section: Fixed
issues: [#5671]
---
- **The sync claim recovery tests no longer race each other or the trash restore test** (#5671). `recover_expired_sync_task_claims` resets every lapsed `in_progress` sync task in the database. #5818 made its two tests assert only on their own task, but two sweeps at once still interfered: one sweep could reset the other test's legacy row between the two statements that seeded it (the peer counter then stayed at `1`), or hold the row's lock while the other test claimed it, so `SKIP LOCKED` handed back nothing. Run 16 at a time, they failed 5 and 3 times in 320 runs each. They now take a shared test lock for their whole body, which `restore_cancels_queued_deletes_and_rearms_pushes` (whose unclaimed `in_progress` row a sweep would reset) takes too, and the legacy test seeds its row and its peer's counter in one transaction. Test-only change; no runtime behaviour changes.
