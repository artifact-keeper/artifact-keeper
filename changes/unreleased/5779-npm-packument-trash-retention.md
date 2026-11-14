---
section: Fixed
issues: [#5779]
---
- **A trash restore or a retention sweep of npm versions now refreshes the cached packument** (#5779). Both changed which versions a package has without dropping the computed packument cache, so the restored version stayed missing, or the swept one stayed listed, in the Local and in every Virtual serving it until the cache entry expired. The trash restore and the lifecycle sweep now invalidate the package the way a publish or a per-artifact delete does, on every replica.
