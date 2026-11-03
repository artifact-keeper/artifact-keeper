---
section: Added
issues: [#5232]
---
- **`record_only` now has a view of what enforcement would refuse** (#5232). `GET /api/v1/security/proxy-blocked`, the dashboard's `proxy_blocked` and `GET /api/v1/admin/holds/policy-blocks` list only what a repository's own settings refuse, so all three are empty under `record_only`. `GET /api/v1/security/proxy-blocked?would_block=true` applies each repository's severity gate to its recorded verdicts whatever its action, through the predicate the gate's other listings use, and the dashboard adds `proxy_would_block`, read from the same query as `proxy_blocked`.

  Files with no usable verdict are not listed. The preview response counts them in `would_block_summary` (`no_verdict`, `stale_verdict`, `clean_graded_nothing`), because `fail_closed` scans them inline on the next pull and answers `423` if the scan is inconclusive. Without `would_block` the list's response is unchanged, and `proxy_blocked` and `policy_violations_blocked` keep their meaning. See `docs/security/scan-on-proxy.md`.
