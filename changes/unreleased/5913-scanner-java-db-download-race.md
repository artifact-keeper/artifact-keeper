---
section: Fixed
issues: [5913]
---
- **Serialized the scanner adapter's on-demand Java DB download so concurrent first JAR scans no longer race on `trivy-java.db`** (#5913). The adapter now downloads the Java DB once, serialized at startup (or on first use), and runs scans with `--skip-java-db-update` after it is present, preventing "no such file or directory" failures and duplicate per-process Java DB staging during concurrent scans.
