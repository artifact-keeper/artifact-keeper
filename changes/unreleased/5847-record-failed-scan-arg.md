---
section: Fixed
issues: [#5847]
---

- The backend builds again after #5684 and #5833 met on main: the scan-result write failure path passes the scanned digest to `record_failed_scan` (#5847).
