---
section: Fixed
issues: [#5148]
---
- **npm proxy identity lookup can read late package metadata in large archives** (#5148). Its separate entry budget defaults to 100,000 and is configurable with `MAX_NPM_IDENTITY_ARCHIVE_ENTRIES`; decompressed-byte and metadata-size limits remain enforced. A fail-closed identity refusal now returns `scan_identity_unestablished` instead of claiming a scan is pending, retaining HTTP 423 and withholding the bytes.
