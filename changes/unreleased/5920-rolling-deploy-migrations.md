---
section: Added
issues: [#5920]
---
- **Rolling deploys: migrations from 418 on must be backward compatible or marked as contracts, and `MIGRATIONS_IGNORE_MISSING=true` lets a pod of the previous release restart mid-rollout** (#5920). In a rolling update the previous release serves on the schema the new release has just migrated. Nothing checked that a migration kept the previous release working. A pod of the previous release that restarted during the rollout failed with `VersionMissing` and crash-looped until the rollout finished, or for good if it was paused or rolled back.
  - **Expand/contract check.** A new CI check fails a migration that drops, renames, retypes or tightens an existing table, column, type or constraint, in any form, long or short, unless the file is named `NNN_contract_of_MMM_<what>.sql` after its expand migration MMM.
  - **Old pods restart.** With `MIGRATIONS_IGNORE_MISSING=true` (default off), a binary starts on a database migrated by a newer release when every newer migration is an expand, or a contract of an expand the binary already has. It refuses to start on any other newer contract, so rolling back across a contract to a release older than its expand still fails.

  `docs/operations/online-migrations.md` says which upgrades can roll and which need a stop-the-world deploy.
