---
section: Changed
issues: [#6090]
---
- **Uploads in formats other than conda no longer run the conda shard triggers** (#6090). The triggers that mark conda shards dirty fired on every insert and update of `artifacts` and every change of `artifact_metadata`, in every format, and looked up the repository to find out it was not conda. They now fire only for package rows (`.conda` and `.tar.bz2`), the only rows a conda client receives. Migration 399 replaces the triggers with `CREATE OR REPLACE TRIGGER`, which blocks writes to `artifacts` for a moment but never reads or downloads, under a 5-second lock timeout with retries. The backed-out attempt in 1.12.2 (#6234) dropped the triggers and blocked reads.

  To keep every conda document consistent with what is marked, a file in a hosted conda channel that is not a package no longer counts for the virtual dependency-confusion guard, no longer hides an older package of the same name from `current_repodata.json`, and no longer sets a package's version in `channeldata.json`. A conda subdir's revision no longer moves when only such a file changes.
