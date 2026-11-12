---
section: Fixed
issues: [#5818]
---
- **The sync claim recovery tests no longer flake on a shared test database** ([#5818]). `expired_sync_task_claims_recover_and_fence_stale_owner` and `legacy_in_progress_sync_task_without_claim_metadata_recovers` asserted the count returned by the instance-wide `recover_expired_sync_task_claims`, which includes expired claims other tests leave behind. They now assert only the state of their own task and peer. Test-only change; no runtime behaviour changes.
