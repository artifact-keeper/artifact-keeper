# Design note: commit proxied bytes to the cache only after the scan gate

Status: proposal, not implemented. Tracks #4514 (item 2 of #4365).

## The gap

`proxy_helpers::serve_scanned_proxy_file` fetches a package through
`ProxyService::fetch_artifact_with_cache_path_capped`, which writes the body to
the proxy cache before `gate_proxy_scan_serve` decides. A refused pull
therefore leaves the refused bytes warm. The format routes re-run the gate on
every read, and the generic download route refuses for scanning repositories
(#4442), so today the exposure is the readers that stream a warm entry without
a verdict check: the Virtual presigned redirect (`try_member_cache_redirect`),
`ProxyService::streaming_cached_artifact_by_path`, and a non-scanning Remote
member of a scanning Virtual addressed directly.

## Options

1. **Publish after the gate.** Add a buffered fetch that does not publish, and
   publish explicitly once the gate serves. The capped fetch already buffers, so
   this is a `ProxyService` change, not a per-format one.
2. **Keep write-through, mark the outcome.** Record the gate outcome in
   `__cache_meta__.json` (or write refused bodies under a key no fast path
   resolves) and make every cache reader refuse a `blocked` entry.

## Trade-offs to settle before building

- **Re-fetch amplification.** Under option 1 a `fail_closed` 423 and a
  `fail_open` background scan both need the bytes again. Without a cached copy
  every retry is a new upstream fetch of up to `PROXY_SCAN_MAX_BYTES` (200 MiB),
  and a client retrying a locked package multiplies upstream traffic. A
  short-lived staging key the fast paths cannot resolve avoids this.
- **TOCTOU.** If the scanned bytes are not the bytes later served (a re-fetch
  after the verdict), the upstream can swap content between the two. Verdicts
  are keyed by SHA-256, so a swapped body misses the verdict and is gated
  again, but only on routes that re-run the gate; the fast paths would serve it.
  Serving must stay tied to the digest that was graded.
- **Warm-cache caveat.** Neither option cleans entries written before the
  change. A refused body already in the cache stays there until eviction, so
  the reader-side check of option 2 (or a one-off sweep) is needed even if
  option 1 is chosen for new writes.
- **Rolling upgrades.** Old replicas ignore new sidecar fields, so under
  option 2 an old replica can still stream a body a new replica marked blocked
  until the rollout completes.

## Recommendation

Option 1 for new writes (publish only after a serve outcome, staging key for
inconclusive results), plus option 2's reader-side refusal for entries that
predate it. Key both by the canonical `(cache_key, scannable)` helper from
#4365 item 1, so the publish and every reader agree on the entry.
