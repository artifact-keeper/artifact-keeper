---
section: Added
issues: [#5177]
---
- **Each scanner's vulnerability database age is reported, with a warning when it goes stale** (#5177). `GET /api/v1/admin/security/vuln-db` lists, per engine (Trivy, Grype), the installed database's version, build time and age, where that came from, and whether it is older than `SCAN_VULN_DB_MAX_AGE_HOURS`. Trivy's age comes from the scanner adapter's `GET /api/v1/vulndb` (set `TRIVY_ADAPTER_VULNDB_TOKEN` to the adapter's `SCANNER_ADAPTER_TOKEN`), Grype's from the `grype db status` probe the scanner already caches, and either falls back to the newest database recent scans recorded. Age is measured against now, so an air-gapped install whose database never updates goes stale on schedule. The report is reused for 60 seconds and refreshed every five minutes in the background, so polling it never runs a scanner. New gauges `ak_scanner_vuln_db_age_seconds` and `ak_scanner_vuln_db_stale` (label `engine`), `ak_scanner_vuln_db_max_age_seconds`, and the counter `ak_scanner_vuln_db_stale_warnings_total`; a stale engine logs a warning at once and then hourly.

  **Default change:** the limit is 7 days (`SCAN_VULN_DB_MAX_AGE_HOURS=168`). It only reports: scan verdicts, quarantine decisions and grades are unchanged whatever the age. Set `SCAN_VULN_DB_MAX_AGE_HOURS=0` to turn the stale state and its warning off. See `docs/security/vuln-db-age.md`.
