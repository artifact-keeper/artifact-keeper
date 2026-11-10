---
section: Fixed
issues: [#5273]
---
- **A first `npm install` through a `fail_closed` scanning repository no longer fails on a scan that is still in flight** (#5273). A tarball whose scan was still queued or running when its request stopped waiting was refused `423 scan_pending`. A retry would have joined that scan or found its verdict, but npm, pnpm and Yarn do not retry a `423`, so the install failed. The npm tarball routes, Remote and Virtual, now answer that refusal `503` with `Retry-After: 5` and the same `scan_pending` body, which those clients retry: npm asks three times in all by default. No byte is served without a verdict, as before, and a verdict that blocks is still `403`.

  A refusal that a retry does not resolve stays `423`: no scanner, a failed scan, a file over the 200 MiB cap, an identity that cannot be established. Other formats' routes are unchanged. The `503` counts as a server error in request metrics and traces; `ak_proxy_scan_verdicts_total` still labels it `inconclusive` / `locked`. See "Clients that do not retry a `423`" in `docs/security/scan-on-proxy.md`.
