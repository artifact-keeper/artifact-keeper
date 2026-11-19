---
section: Fixed
issues: [#6305]
---
- **A migration worker that loses its claim on the job now stops at once and leaves the job's status alone** (#6305). When a worker could not renew its claim (for example, the database was unreachable for longer than the 300-second claim lifetime) and the janitor paused the job or another worker resumed it, the old worker kept migrating until its next status check, and could then stamp the job `cancelled` or `failed` over the run that had taken it over. The worker now cancels itself as soon as a renewal finds the claim gone, and a worker that no longer holds the claim writes no status.
