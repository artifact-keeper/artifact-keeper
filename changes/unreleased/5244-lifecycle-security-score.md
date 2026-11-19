---
section: Fixed
issues: [#5244]
---
- **Deleted artifacts no longer leave their scan results behind** (#5244). A lifecycle policy run soft deletes in bulk and published no `artifact.deleted` event, so the repository's grade and finding counts kept the deleted artifacts' findings until its next scan. Each repository the run deleted from is now recalculated at the end of the run, if it already has a score. The scan listings (`GET /api/v1/security/scans`, a repository's and an artifact's scans) also leave out the scans of a soft-deleted artifact, a restore from the trash brings them back
