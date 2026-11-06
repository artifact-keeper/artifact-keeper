---
section: Fixed
issues: [#5387]
---
- **One MCP publisher can no longer starve the introspection queue** (#5387). Introspection jobs were handed out oldest first across every repository, so a publisher that pushed many versions with several stdio packages filled the queue with `sandbox_run` jobs, and each one that timed out held a worker for up to three 120 s attempts while every other repository's probes waited. A claim now picks the repository with the fewest jobs claimed at that moment, then its oldest due job, in the same single `FOR UPDATE SKIP LOCKED` statement; and a `sandbox_run` that times out is retried once instead of twice, so its second timeout is final.
