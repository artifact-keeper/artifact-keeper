---
section: Fixed
issues: [#5776]
---
- **A Maven `.sha512` sidecar is checked against the stored artifact** (#5776). The `artifacts` row keeps no SHA-512, so a wrong `.sha512` uploaded before its file locked the release: the deploy's own `.sha512` then got 409 with nothing to prove the stored one wrong, and a wrong `.sha512` after the file was stored unchecked. A `.sha512` upload of a stored artifact now hashes the stored bytes, so the correct digest replaces a wrong stored one and a mismatching one answers 400, like the other algorithms. Artifacts over 512 MiB are not hashed and keep the previous behaviour.
