---
section: Fixed
issues: [#3928]
---
- **The pre-migration assessment reports real artifact counts** (#3928). It read a one-row listing page's `range.total` as the repository size, which neither Artifactory nor Nexus provides, so every repository counted as at most one artifact and the job's denominator was seeded from that. Repositories are now counted by a bounded listing walk; the assessment flags counts that are only a lower bound (`artifact_count_exact` / `total_artifacts_exact`), and the job's total is seeded only from an exact count.
