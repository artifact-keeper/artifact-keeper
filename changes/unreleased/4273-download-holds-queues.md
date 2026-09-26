---
section: Added
issues: [#4273]
---
- **Admin queues for quarantined artifacts and packages blocked by scan policy** (#4273). `GET /api/v1/admin/holds/*` lists timed quarantine holds and `policy_blocked` packages separately, so a scan-policy hold is no longer reported as a quarantine 409.
