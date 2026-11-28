---
section: Added
issues: [#6335]
---
- **Scan results now record how many dependency lookups `ADVISORY_EXCLUDE_PATTERNS` skipped** (#6335). The count is stored on the scan result and exposed as `advisory_excluded` in the scan API, so an operator or auditor can see from the result that packages were deliberately kept out of OSV and GitHub lookups instead of silently missing coverage.
