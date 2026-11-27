---
section: Fixed
issues: [#5264]
---
- **Artifactory Helm OCI repositories (`helmoci`) now migrate into native `helm_oci` repositories instead of being rejected as unsupported** (#5264). The migration did not recognize Artifactory's `helmoci` package type, so both it and AK's own `helm_oci` were classified `Unsupported` and the repository was skipped. `helmoci` now normalizes to `helm_oci`, is classified as fully importable like `docker`, and takes the existing OCI import path, which registers chart manifests and blobs in the OCI index the way a native push does. Classic `helm` chart repositories are unchanged.
