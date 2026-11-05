---
section: Fixed
issues: [#5084]
---
- **Writes to two repositories in opposite order no longer deadlock on `repository_usage_ledger`** (#5084). The usage triggers used to take each repository's ledger row lock at the artifact INSERT, so two multi-repository transactions that touched the same pair in opposite order could deadlock (`40P01`). Deltas are now queued per transaction and applied once at commit in repository-id order, so every transaction takes the ledger rows in the same global order; single-repository writes still take exactly one row, and rollback still discards the charge with the write.
