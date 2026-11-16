---
section: Added
issues: [#5971]
---
- **The API pods can run without grype when the scan queue is on** (#5971). A backend without `grype` on its `PATH` never starts it: a scan that needs it fails with that reason (never clean), the version and vulnerability-database probes report nothing, and stored proxy verdicts are compared against the CVE scanner version the scan workers report on every sweep (`system_settings` key `scan.cve_scanner_version`). With `SCAN_QUEUE_ENABLED`, a repository rescan (`POST /api/v1/security/scan` with `repository_id`) and `POST /api/v1/admin/rescan-for-inventory` queue one `hosted_artifact` job per artifact instead of scanning in the API process. At startup the backend logs an error when grype is missing and the queue is off or the instance is a scan worker. Proxy scans the queue cannot carry yet (OCI images, catalog rescans, OS package pins, `fail_closed` fills that are not cached) still run in process and fail closed without grype.
