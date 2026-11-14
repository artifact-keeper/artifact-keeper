---
section: Fixed
issues: [#5875]
---
- **A PyPI Remote that scans on proxy serves a fresh cached file without reading the simple index** (#5875). The scan path resolved the download URL from the upstream index before it looked at the cache, so a cached wheel failed with 502 while the index was unreachable, and every cached download paid an index read. A fresh cache entry is now served straight from the cache, through the same digest-keyed scan gate, for direct Remote pulls, Virtual members and the age-gate substitute. A stale or missing entry still resolves through the index as before.
