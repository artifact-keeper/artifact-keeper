---
section: Fixed
issues: [#5244]
---
- **A lifecycle policy run that deletes scanned artifacts now refreshes the repository's security score** (#5244). The bulk soft delete published no `artifact.deleted` event, so the repository's grade and finding counts kept the deleted artifacts' findings until its next scan. Each repository the run deleted from is now recalculated at the end of the run, if it already has a score
