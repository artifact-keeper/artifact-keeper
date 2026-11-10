---
section: Security
issues: [#5618]
---
- **An administrator's quarantine or rejection of an OCI tag is no longer lost when it lands while a push is moving that tag** (#5618). When a push moves a held tag to another image, the hold moves to the old image's digest row (#5457). The push decided whether there was a hold from the tag row as it was when its database statement started. If an administrator quarantined or rejected that row while the push was waiting for it, the administrator got a success response but the push saw no hold and cleared it. The old image was then served again by digest and under its other tags. The push now locks the tag row before it decides, so a hold that commits while the push is waiting moves to the old digest.
