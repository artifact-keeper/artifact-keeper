---
section: Fixed
issues: [#5992]
---
- **Rescans now start after a Trivy database update, not only a Grype one** (#5992). The rescan pass reads the database builds recent scans recorded, which is how the scanner adapter's Trivy build is learned, with `make_interval(hours => …)` bound to a floating-point value. Postgres has no such function, so the query failed on every worker tick (`could not read recent vulnerability-database builds`), the Trivy build was never recorded, and only Grype database updates could trigger rescans. The window is now bound as an integer.
