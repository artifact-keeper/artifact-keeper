---
section: Fixed
issues: [#5942]
---
- **A scanner that never returns no longer keeps its scan `running` for half an hour** (#5942). An artifact scan ran each scanner with no time limit, so a hung grype held its `scan_results` row `running` until the stuck-scan janitor failed it after `STUCK_SCAN_THRESHOLD_SECS`, and on the scan worker it used up the 600 s job budget and dropped the other scanners' results with it. Each scanner now runs under `SCANNER_TIMEOUT_SECS` (default 300, clamped to 1 to 540): past it the scanner is stopped (grype's child process is killed on drop) and its row is recorded `failed` with `scanner <name> timed out after <N>s`, while the other scanners' rows complete as usual.
