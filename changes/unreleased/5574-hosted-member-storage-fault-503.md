---
section: Fixed
issues: [#5574, #5504]
---
- **A Virtual repository whose hosted member cannot read a stored artifact now answers a retryable 503 instead of a 404** (#5574, #5504). The checksum walk already treated a Local or Staging member with a storage or database fault as unavailable, but the artifact walk read the same fault as a miss, so through one broken member `lib-1.0.jar.sha1` answered 503 while `lib-1.0.jar` answered 404, which build tools cache. Every resolver reading a hosted member (buffered, streaming and the npm, Maven and NuGet scan-aware walks) now classifies the fault as an unavailable member that still defers to the next member and answers 503 only when nothing else serves. A missing row stays a plain 404 and a policy block stays terminal.
