---
section: Fixed
issues: [#5880]
---
- **The trash restore and purge tests no longer flake while a storage GC test runs** ([#5880]). `restore_after_purge_leaves_the_peer_with_the_restored_bytes_5699` and the `trash_service` tests need a soft-deleted row to survive until their own `restore` or `purge` call. A concurrent GC test's instance-wide `run_gc` pass hard-deleted any such row, so the restore answered `NotFound` and the test failed with `X2 push: RowNotFound`. They now run in the `db-serial` nextest group with the GC tests. Test-only change; no runtime behaviour changes.
