---
section: Fixed
issues: [#4453]
---
- **An OCI Remote whose upstream token service rejects its credentials now reports an upstream authentication failure instead of "manifest unknown"** (#4453). A 401 or 403 from the upstream's bearer token endpoint was logged as `Storage error` and the client got `404 MANIFEST_UNKNOWN`, so wrong upstream credentials looked like a missing image. The pull now fails with `502` and the OCI error code `DENIED` ("upstream registry authentication failed"), and the backend logs a warning on the `security` target naming the token service (redacted, no credentials) and whether credentials were sent. Other token-endpoint failures are unchanged.
