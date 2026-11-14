---
section: Fixed
issues: [#5863]
---
- **A scanned Helm chart says it cannot be graded instead of reporting a clean** (#5863). A chart ships templates and values, not packages, so the CVE engine always finished with zero findings and the upload read as a complete, clean scan. The CVE engine's result for a `.tgz` in a `helm` repository is now recorded `not_applicable` with the reason, the same terminal state any scanner that does not apply records, so the chart counts as scanned without claiming a grade. The images a chart names are graded where they are pulled. Contributed by @nicola-preda.
