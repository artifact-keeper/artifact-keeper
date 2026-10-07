---
section: Fixed
issues: [#4425]
---
- **Hash-based scan reuse now copies only from a scan that actually ran, never from another reused copy** (#4425). When an artifact's scan was reused from an identical artifact, the reused row was stamped with the time of the copy, so it became the newest match and later uploads of the same bytes copied from the copy. Copies chained onto copies, and each hop restarted the reuse window, so a verdict could stay reusable long after the scan behind it had expired. Reuse now requires an original scan (`source_scan_id IS NULL`), which keeps every reused row one hop from a real scan and bounds reuse by that scan's age. An artifact whose own scan is a reused copy is still treated as already scanned, so a rescan of it does not add a second completed scan.
