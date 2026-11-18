---
section: Fixed
issues: [#6208]
---
- **Scan-on-proxy no longer logs "scanning async" for pulls it will never scan** (#6208). Under `fail_open` and `record_only` a pull whose bytes do not establish the coordinate they are served at is served `pending` with no scan run or queued, but it logged the fail-open line promising an async scan. It now logs `served, will not be scanned: identity not established` with the repository, file and version, and counts in the new `ak_proxy_scan_unscannable_total{repository, format, reason}` counter, so these serves show up on their own instead of inside the fail-open share
