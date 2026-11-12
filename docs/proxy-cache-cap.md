# Capping a remote repository's proxy cache

A remote (proxy) repository caches what it fetches from its upstream. Before
1.12.0 the only way to bound that cache was a lifecycle policy (`max_age_days`
or `no_downloads_days`): `quota_bytes` on a remote only skips a single object
larger than itself, and lifecycle `size_quota_bytes` is refused on a remote
(#4660). A busy remote could fill its disk before any window expired.

## Setting a cap

```bash
# Cap the proxy cache of remote repository "pypi-remote" at 50 GiB.
curl -X PUT -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"cap_bytes": 53687091200}' \
  https://registry.example.com/api/v1/repositories/pypi-remote/proxy-cache-cap

# Read the cap and what the cache holds now.
curl -H "Authorization: Bearer $TOKEN" \
  https://registry.example.com/api/v1/repositories/pypi-remote/proxy-cache-cap
# {"repository_key":"pypi-remote","cap_bytes":53687091200,"at_cap":"evict_lru",
#  "usage":{"bytes":21474836480,"entries":18342},"refusing_fills":false}

# Remove the cap.
curl -X DELETE -H "Authorization: Bearer $TOKEN" \
  https://registry.example.com/api/v1/repositories/pypi-remote/proxy-cache-cap
```

Reading and changing the cap need the repository `admin` action, like the
upstream filter and the cache TTL. A caller who cannot read the repository
gets `404 Repository not found`, the same answer as for a key that names no
repository, on every method and whatever the repository's type (#5610); a
caller who can read it but lacks `admin` gets `403`, and a key that is not a
Remote gets `400`. The cap is stored per repository, so it
applies on every replica; a change made on one replica reaches the others
within 30 seconds.

## What happens at the cap

- **Eviction.** After every cache fill, if the repository's cache holds more
  than the cap, the least recently used entries are evicted until it is back
  at or under it. "Recently used" is the later of the last download served
  from the entry and the last time it was written. Evicting deletes the
  cached objects and the catalogue row, as a lifecycle sweep does, and keeps
  the entry's download history. Usage can be over the cap for a moment: by the
  fill that just completed, until its eviction run finishes. Runs are
  debounced to at most one a second per repository.
- **Objects larger than the cap** are served to the client without being
  cached, like an object larger than `quota_bytes`
  (`ak_proxy_cache_quota_exceeded_total` counts both).
- **When eviction fails.** If eviction cannot get the cache under its cap
  (the storage backend refuses the deletes, for example), new fills are served
  without being cached, so the cache never grows past its cap because eviction
  is failing. `refusing_fills` is `true` in the response, the
  `ak_proxy_cache_cap_refusing_total` counter moves and a `warn` line is
  logged. The next eviction run that gets under the cap clears it.
- **Setting a cap below current usage** evicts at once; the `PUT` response
  shows usage after that eviction.

Usage is the byte count the repository usage ledger keeps for the proxy cache
(`repository_usage_ledger.proxy_bytes`, kept exact by database triggers on the
cache catalogue).

## Metrics

| Metric | Labels | Moves when |
|---|---|---|
| `ak_proxy_cache_cap_evicted_entries_total` | `repository` | entries are evicted to stay under the cap |
| `ak_proxy_cache_cap_evicted_bytes_total` | `repository` | the bytes those entries held |
| `ak_proxy_cache_cap_refusing_total` | `repository` | an eviction run could not get under the cap and fills are refused |

A steady eviction rate means the cap is smaller than the repository's working
set: clients are refetching from upstream what the cap evicts.

## With lifecycle policies

The cap and lifecycle policies are independent. A `no_downloads_days` or
`max_age_days` policy assigned to the remote still evicts by age; the cap
bounds the bytes in between.
