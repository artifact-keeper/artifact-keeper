---
section: Fixed
issues: [#6504]
---
- **Evicting a proxy cache entry no longer rewrites its download history** (#6504). The history's reference to the cache entry was `ON DELETE SET NULL`, so every eviction updated each history row of the entry inside the `DELETE`, and the most downloaded packages were the most expensive to evict. Migration 439 drops that foreign key. The history rows are kept exactly as before and stay keyed on repository and path, they keep the evicted entry's id, which no longer matches any entry
