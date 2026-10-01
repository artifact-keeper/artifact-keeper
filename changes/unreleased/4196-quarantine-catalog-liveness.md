---
section: Fixed
issues: [#4196]
---
- **Held uploads no longer appear on the Packages page, rejection delists a published package, and release from quarantine re-lists it** (#4196). The catalog liveness check filtered on `is_deleted` alone, so the twenty-one format handlers that apply the upload hold and then register the package left a held artifact listed from publish time, a later rejection never delisted it, and an older artifact released from quarantine stayed off the page until the backfill re-ran. The read-side predicate now applies the same quarantine rule the download path and the backfill use — held or rejected artifacts are not live, released or elapsed-hold artifacts are — so all three gaps close with no per-handler change.
