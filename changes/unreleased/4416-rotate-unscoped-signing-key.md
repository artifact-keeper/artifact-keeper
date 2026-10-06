---
section: Fixed
issues: [#4416]
---
- **Rotating a signing key created without a `repository_id` now repoints the Debian and RPM repositories bound to it** (#4416). Rotation only updated the signing config of the repository named on the key itself, so a key created unscoped and bound through `POST /api/v1/signing/repositories/{id}/config` left those configs on the retired key, and InRelease, Release.gpg and the public key returned 404 "No signing key configured for this repository" after rotation. Rotation now moves every signing config bound to the old key to its successor, in the same transaction; the old key still co-signs during the rotation overlap window.
