---
section: Fixed
issues: [#5594]
---
- **Serve Docker manifests correctly through the generic repository download route** (#5594). Downloading a manifest from a Docker repository via `/api/v1/repositories/{key}/download/v2/.../manifests/...` no longer fails with a 502 integrity error caused by verifying the manifest bytes against the image size recorded on the artifact row.
