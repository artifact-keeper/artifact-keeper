---
section: Added
issues: [#4281]
---
- **Admin queues for hosted and proxy-cache quarantine holds** (#4281). `GET /api/v1/admin/holds/summary` and `GET /api/v1/admin/holds/quarantine` list currently-blocking `artifacts` rows and proxy-cache `quarantine_until` holds without introducing a separate `policy_blocked` status.
