---
section: Added
issues: [#4848]
---
- **Helm uploads accept a ChartMuseum-compatible `?force` parameter to overwrite an existing chart version** (#4848). `helm cm-push --force` now re-publishes a chart whose name and version already exist instead of failing with `409 Chart ... already exists`, by tombstoning the previous chart and provenance rows before the upload proceeds. The parameter requires the same `write:artifacts` permission as a normal publish and bypasses no repository or scan checks.
