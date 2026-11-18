---
section: Fixed
issues: [#6214]
---
- **Go `@v/list`, `@latest` and `.info` answer an upstream outage with a 5xx instead of 404, so `GOPROXY=<ak>,direct` no longer falls through to the internet past the scan gate** (#6214). When a Go Remote could not reach its upstream, or the upstream answered 5xx or 429, these three routes answered `404`, while `.mod` and `.zip` answered `502`/`503`. `go` reads 404 and 410 as "this proxy does not have the module" and moves on to the next `GOPROXY` entry, so an outage turned into direct VCS fetches that skipped scan-on-proxy, or into a not-found build failure with a single entry. They now answer what `.mod` answers: `502` or `503` on a Remote, and `503` with `Retry-After` through a Virtual when no member served and one could not answer. A server-side fault while resolving them (a database pool timeout) is a 5xx too. A module the upstream does not have (`404` or `410`) still answers `404`.
