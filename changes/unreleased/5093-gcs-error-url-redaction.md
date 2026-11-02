---
section: Fixed
issues: [#5093]
---
- **Google Cloud Storage error messages no longer carry the request URL** (#5093). When a GCS request failed in transport (for example a refused connection or an unresolvable `GCS_ENDPOINT`), the storage error, the `/health` storage check message and API error bodies repeated the full request URL, naming the endpoint host, the bucket and the object key. They now name only the operation and the transport error, as #4866 did for Azure. A few S3 error paths that printed the raw object-store error are trimmed the same way, and the health check strips any URL left in a backend's message.
