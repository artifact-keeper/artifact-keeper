---
section: Fixed
issues: [#5543]
---
- **CI and gateway capability reports now apply the worker result's observation and cache metadata bounds and error code** (#5543). A report's `ttlMs` was only checked for being non-negative, with no upper bound, and its `observedAt` and `cacheScope` refusals answered `mcp_invalid_capabilities`, unlike the same metadata on job completion. Reports now share `validate_metadata` with job completion: an `observedAt` more than the 5-minute clock-skew window ahead, a `cacheScope` other than `public` or `private`, or a `ttlMs` outside `0` to `2592000000` (30 days) is refused with `400 mcp_invalid_result_metadata` (previously `400 mcp_invalid_capabilities`) and the offending `field`, and nothing is stored. A malformed report body still answers `mcp_invalid_capabilities`. Gateway operators that parse the error code must accept the new one.
