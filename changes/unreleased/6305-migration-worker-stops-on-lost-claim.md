---
section: Fixed
issues: [#6305]
---
- **A migration worker that loses its claim on the job now stops at once and leaves the job's status alone** (#6305). When a worker could not renew its claim (for example, the database was unreachable for longer than the 300-second claim lifetime) and the janitor paused the job or another worker resumed it, the old worker kept migrating until its next status check, and could then stamp the job `cancelled` or `failed` over the run that had taken it over. The worker now cancels itself as soon as a renewal finds the claim gone, and its job-row writes (progress counters, totals, the no-op warning and the final status) apply only while the row still carries its claim, so a worker that was taken over writes nothing onto the new owner's job even before its renewal notices.
