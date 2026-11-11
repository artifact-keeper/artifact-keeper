---
section: Fixed
issues: [#5630]
---
- **The "scan_on_proxy is enabled ... cached UNSCANNED" warning no longer fires for objects the scan-on-proxy gate scanned, and fires at most once per object** (#5630). The WARN from #1274 was logged for every newly cached object of a Remote with `scan_on_proxy` enabled, including objects the gate had just scanned (and some it refused with 403 `scan_blocked`), and the message claimed they were cached unscanned. On the reporting instance that was 64 lines in one hour of normal scanning traffic. The warning now fires only when no `proxy_scan_results` verdict exists for the cached content's digest, and each object is warned about once per process, so a cache refill after the TTL lapses does not repeat it.
