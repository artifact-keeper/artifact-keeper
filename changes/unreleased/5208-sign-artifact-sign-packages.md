---
section: Fixed
issues: [#5208]
---
- **`POST /api/v1/signing/artifacts/{artifact_id}/sign` now signs for a repository configured with `sign_packages: true`** (#5208). The route used the metadata-signing key lookup, which needs `sign_metadata: true`, so a repository set up only for package signing got a 409 claiming it had "no active signing key or signing config". Artifact content signing now accepts `sign_packages` (and, as before, `sign_metadata`); metadata signing still needs `sign_metadata`. When signing is refused, the 409 names what is missing: no signing config, no `signing_key_id`, an inactive key, or `sign_packages: false`.
