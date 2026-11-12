---
section: Fixed
issues: [#5877]
---

- The upstream fetch audit's secret-leak test uses a fixed repository id, so a random UUID containing "abc" no longer fails it (#5877).
