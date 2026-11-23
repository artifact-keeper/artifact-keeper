---
section: Fixed
issues: [#6379]
---
- **Trivy conjunctive SPDX license expressions now survive inventory ingestion instead of becoming opaque `LicenseRef-` operands** (#6379). A license element such as `MIT AND PSF-2.0` is kept when the scanner's array is joined with `AND`, so CycloneDX exports and Dependency-Track policy evaluation see its real terms; free-form names and choices containing `OR` are still wrapped as `LicenseRef-`.
