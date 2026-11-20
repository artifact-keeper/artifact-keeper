---
section: Fixed
issues: [#5766]
---
- **An OCI release, and the `flagged` mark after a failed scan, are bound to the digest they were decided on** (#5766). `POST /api/v1/quarantine/{id}/release` acted on whatever image a tag row named when the request landed, so a release an administrator decided for one image could clear a newer hold placed on the image the tag had since moved to. The endpoint now accepts an optional `expected_digest` (`sha256:<hex>`), as quarantine and reject do since #5646: when the tag has moved, the old image's held row is released, the response names both digests (`held_digest`, `moved_to_digest`), and the newer hold stays. With no `expected_digest` it binds to the digest the row names when read; a request with no body works as before. The scanner's `flagged` write after a failed scan is a no-op once the tag row names other bytes, instead of marking the new image.
