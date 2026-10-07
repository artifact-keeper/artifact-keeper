---
section: Added
issues: [#2906]
---
- **The OCI blob GC's minimum blob age is configurable through `BLOB_GC_MIN_AGE_SECS`** (#2906). The 24-hour grace that shields an in-flight push from blob garbage collection was a compile-time constant, so a short-lived environment such as the release gate could never observe a pushed blob being reclaimed. The default stays 86400 seconds; the value is clamped to between 60 seconds and 7 days and a value under one hour is logged as a warning at startup. The grace window on objects recorded for GC by a repository delete (#3733) guards the same push-time hazard and now follows the same setting, so the two windows cannot drift apart.
