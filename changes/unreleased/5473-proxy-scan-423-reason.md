---
section: Fixed
issues: [#5473]
---
- **A fail-closed proxy pull withheld with `423` because its scan was inconclusive now logs why** (#5473). No scanner configured, a scan that failed and a scan that ran out of its inline budget all answer the same `423` "retry shortly", but only the budget case resolves on a retry, and nothing recorded which one a client had hit. The gate now writes a `warn` line with the repository, file, digest and the reason (`NoScanner`, `ScanFailed` or `BudgetExceeded`). The response is unchanged.
