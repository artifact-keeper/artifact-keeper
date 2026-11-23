---
section: Fixed
issues: [#6451]
---
- **A cache-only Debian Remote keeps serving `InRelease` and `Release` after the five-minute dists index TTL** (#6451). `fetch_dists_with_revalidation` treated an index that was past its TTL, or older than the release epoch, as a miss and went to the refill, which the cache-only gate refuses. The request ended in `404 not in cache; repository '<key>' is cache-only` although the entry was held, so `apt-get update` lost every suite five minutes after the last upstream contact while the `.deb` files it indexes were still served. A cache-only Remote now serves the index it holds, as the generic proxy path already does (#5282). A path it does not hold is still a cache-only miss.
