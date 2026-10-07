---
section: Added
issues: [#4516, #4281]
---
- **Admin queues for hosted and proxy-cache quarantine holds** (#4516, #4281). `GET /api/v1/admin/holds/summary` and `GET /api/v1/admin/holds/quarantine` list currently-blocking `artifacts` rows and proxy-cache `quarantine_until` holds, filterable by repository and by `kind` (`active`, `expired`, `rejected`). Scan-policy blocks are stored as quarantine today, so they appear here as active hosted holds. Repository-scoped tokens are refused.
