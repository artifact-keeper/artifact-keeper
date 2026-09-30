---
section: Fixed
issues: [#4096]
---
- **The proxy-cache SBOM now marks a partially read inventory** (#4096). `GET /api/v1/repositories/{key}/security/proxy-sbom` always rendered its regenerated SBOM as complete, because the inline proxy scan never recorded whether the scanner could read every target. The completeness is now stored with the verdict (migration 252) and emitted as the CycloneDX `artifact-keeper:scan-completeness` property or the SPDX creation comment, so a client can tell a partial inventory from an authoritative one.
