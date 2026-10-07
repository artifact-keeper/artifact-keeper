---
section: Fixed
issues: [#3919]
---
- **A corrupted stored artifact is no longer served as a complete `200` under its original `X-Checksum-Sha256`** (#3919). The generic download route (`GET /api/v1/repositories/{key}/download/{path}`, including `?version=` revisions) now hashes the body incrementally while streaming it, holding back only the final chunk; if the bytes or length no longer match the recorded SHA-256, the response is aborted before that chunk and the corruption is logged with the repository and path, so no client receives a full body that contradicts the digest header. A `Range` request that covers the whole object (`bytes=0-`, a suffix at least as long as the object) is verified the same way. Memory use stays at one chunk. Proper sub-ranges and presigned redirects are not verified.

  A stored object longer than its recorded size is refused the same way instead of being served as a clean prefix. Protobuf module commit bundles are exempt, because their rows record the commit digest rather than the bundle's own SHA-256.

  **Upgrade note:** verification is on by default and costs one SHA-256 pass per full download. Some pre-existing races that used to serve bytes not matching the row now abort the download instead. These include a Maven SNAPSHOT redeployed while it is being downloaded, a promotion that failed with 409 after overwriting the target object, a backup restore over existing objects, and a NuGet or PyPI object being re-materialized during a download. Clients see a failed transfer they can retry instead of silently mismatched bytes. Set `DOWNLOAD_VERIFY_CHECKSUMS=false` to turn verification off and leave integrity checking to clients.
