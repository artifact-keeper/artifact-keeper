---
section: Fixed
issues: [#5884]
---
- **A repository-scoped or incremental backup no longer archives every repository and download-statistics row** (#5884). The `repositories` and `download_statistics` tables were exported whole whatever the backup's repository filter or `since` cutoff. A restore of such an archive brought back repositories deleted after the backup (empty), failed on the statistics of artifacts the archive did not carry, and, when any RPM repository outside the scope had a repodata depth, ran as a depth-bearing restore that failed as a whole on that row and locked the out-of-scope repository's layout. The archive now holds the repositories in scope and the download statistics of the artifacts it archives, and an exclude-only filter is read in the backup's own snapshot. Unscoped backups are unchanged.
