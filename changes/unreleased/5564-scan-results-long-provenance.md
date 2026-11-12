---
section: Fixed
issues: [#5564]
---
- **A scanner version or vulnerability-database identity longer than its old column no longer strands a scan in `running`** ([#5564]). `scan_results.scanner_version` was `VARCHAR(50)` and `vuln_db_version` was `VARCHAR(100)`, both filled from scanner-supplied strings. A longer value made `complete_scan` fail with `value too long for type character varying`; the scan stayed `running` until the stuck-scan janitor failed it, and every scanner after it in the set was skipped. Both columns are now `TEXT`, the provenance is stored whole instead of being silently truncated into a different database identity, and a `complete_scan` write the schema still refuses fails only that scanner, named, so the rest of the set keeps running. External findings ingestion accepts the same long `scanner_version`.
