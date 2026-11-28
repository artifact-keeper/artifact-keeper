---
section: Fixed
issues: [#5217]
---
- **Remote OCI blobs served by a presigned redirect now get their corrupt stored copy repaired in the background** (#5217). The redirect could not verify bytes without reading every layer on every pull; a database-backed claim now runs one bounded integrity check per blob per day and refetches from the Remote's upstream when the stored bytes fail their digest, so the client's retry succeeds.
