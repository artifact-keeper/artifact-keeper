---
section: Security
issues: [#3579]
---
- **The scanner adapter's Go toolchain floor guards again, and is raised to go1.27.2; the adapter is published as 1.4.1** (#3579). `docker/Dockerfile.scanner-adapter` asserts a `GO_MIN_PATCH` floor so a stale builder or a lagging mirror fails the build instead of shipping a vulnerable standard library. #3579 moved the build image from `golang:1.26-alpine` to `golang:1.27-alpine` and left the floor at 1.26.6, which every 1.27.x satisfies, so the check could no longer fail; the backend Dockerfiles had the same gap and #3655 closed it there. The floor now names go1.27.2, Go's October security release (CVE-2026-78667, CVE-2026-78669, CVE-2026-97031, all HIGH). The adapter binary itself scanned clean in the run that failed on those advisories, because the floating tag had already served go1.27.2; the floor makes that a guarantee. The adapter is standard-library only, so there is no `golang.org/x/net` in it to bump.
