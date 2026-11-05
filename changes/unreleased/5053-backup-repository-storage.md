---
section: Fixed
issues: [#5053]
---
- **Full backups now read artifact bytes from each repository's own storage path instead of the deployment-global storage root** (#5053). Filesystem repositories store objects under `<STORAGE_PATH>/<repo_key>`, so the backup's single global storage handle missed every artifact and the run failed with `backup is missing artifact content`. Backups now resolve each artifact through its repository's configured storage backend and location, and capture an object shared by several repositories once. Restores write the bytes back to every repository that references them, at the location of the repository as it exists on the restoring server. A repository location taken from the archive is used only when that repository does not exist, and only if it lies below the configured storage root. Legacy archives without repository rows still use the global handle.
