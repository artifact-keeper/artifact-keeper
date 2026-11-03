---
section: Security
issues: [#5181]
---
- **A refused Azure signature no longer puts the source SAS into error messages and logs** (#5181). When Azure refused the signature on a Put Blob From URL copy, its error body quoted the string it signed, including the source URL and its SAS token, and the backend copied that body into its error. OCI blob uploads and the chunked upload API return that text to the client, and the storage spans and proxy cache log it, so a signed read URL for the source blob could reach authenticated API clients and the logs until it expired. Azure errors now report the HTTP status, the Azure error code, the copy source's code and status, and the request id, and never the response body. This covers every Azure blob operation, not only copy.
