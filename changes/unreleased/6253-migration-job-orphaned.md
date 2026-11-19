---
section: Fixed
issues: [#6253]
---
- **A migration job no longer stays `running` forever when the backend pod running it restarts** (#6253). The worker ran in a task on one replica with no link to the process shutdown and no record of who ran it, so after a roll, eviction or OOM kill the job never moved again and `/resume` refused it. A clean shutdown now pauses the job, the worker holds a claim on its row that it renews while it runs (migration 400), and a janitor on every replica pauses `running` jobs whose claim lapsed with the error summary `worker lost`. `/resume` then continues them, skipping the items already done. Jobs left `running` before the upgrade are paused the same way on the first pass.
