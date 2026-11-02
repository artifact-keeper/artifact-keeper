---
section: Fixed
issues: [#5148, #5149]
---
- **npm proxy identity lookup supports late metadata and DefinitelyTyped archive roots** (#5148, #5149). It prefers `package/package.json` and accepts a root manifest in a single alternatively named directory; ambiguous fallback roots remain withheld. Its separate entry budget defaults to 100,000 and is configurable with `MAX_NPM_IDENTITY_ARCHIVE_ENTRIES`; decompressed-byte and metadata-size limits remain enforced. A fail-closed identity refusal now returns `scan_identity_unestablished` instead of claiming a scan is pending, retaining HTTP 423 and withholding the bytes.
