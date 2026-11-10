---
section: Fixed
issues: [#5678]
---
- **Re-uploading a released Maven artifact's checksum sidecar with the same value now succeeds** ([#5678]). A `PUT` of a `.sha1`/`.md5`/`.sha256`/`.sha512` already stored for a release answered `409` even when the value was identical, so a Maven or Gradle retry after a lost response failed the deploy. An identical value now answers `200` and leaves the stored sidecar untouched, a different value is still `409`, and the artifact's own digest may replace a stored sidecar that does not match it, so a wrong sidecar uploaded before its file no longer locks the release. The `-SNAPSHOT` filename alias also resolves for an artifactId that itself contains `<version>-SNAPSHOT` (for example `x-1.0-SNAPSHOT-y`), which it used to mis-split.
