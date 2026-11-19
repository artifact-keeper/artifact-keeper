---
section: Security
issues: [#5691]
---
- **`ADVISORY_EXCLUDE_PATTERNS` keeps internal package names out of external advisory lookups** (#5691). The dependency scanner sends every dependency of a scanned artifact, and since #4669 the artifact's own coordinate, to OSV.dev (and to the GitHub Advisory Database when `GITHUB_TOKEN` is set), so scanning a hosted internal library disclosed its name and version to a third party. The new opt-in setting takes comma-separated package-URL globs such as `pkg:maven/com.example.internal/*,pkg:npm/@acme/*,pkg:pypi/acme-*`; a matching package is never named in an OSV or GitHub request, is not counted as an unanswered lookup (the scan stays `complete`), and still appears in the package inventory and SBOM and is still matched by grype and trivy. Public dependencies of the same artifact are looked up as before. Unset, nothing changes.
