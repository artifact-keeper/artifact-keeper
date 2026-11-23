---
section: Added
issues: [#5617]
---
- **Detached proxy cache fills are counted, the cap logs at `warn`, and a request waiting on a fill takes the fill's fetch-deadline verdict** (#5617). When `PROXY_UPSTREAM_MAX_DETACHED_FILLS` was exhausted, or a streamed fill whose client went away was abandoned at its deadline, the only trace was a `debug` line, so at the default log level an operator could not tell the cap was too low. New metrics: `ak_proxy_detached_fills_total{kind="buffered"|"stream_drain", outcome="started"|"finished"|"abandoned"|"refused"}`, the gauge `ak_proxy_detached_fills_in_flight{kind}`, and `ak_proxy_detached_fills_limit`. A refused permit and an abandoned drain are also logged at `warn`, at most once a minute per kind of event, with the number held back since the last line. See `docs/operations/proxy-cache-metrics.md`.

  A request that was waiting on a buffered fill whose upstream fetch then hit `PROXY_UPSTREAM_FETCH_DEADLINE_SECS` now answers with that verdict: the stale copy under stale-if-error when there is one, else the `502`. Before, it fetched from the same upstream again and answered after about twice the deadline. A request that arrives after the deadline fetches as before. Counted in `ak_proxy_fill_followers_inherited_total`. Requests waiting on another replica's fill (`PROXY_SINGLEFLIGHT_ADVISORY_LOCKS_ENABLED`) still fetch once themselves.

  **Default change:** such a waiting request no longer starts a second upstream fetch. There is no setting for it; a retry after the deadline fetches again.
