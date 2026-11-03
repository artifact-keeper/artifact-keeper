---
section: Fixed
issues: [#5088]
---
- **The Debian backfill counts a merged package once when its destination row is also a candidate** (#5088). When a misfiled copy merges into a live row with the same bytes, the real run writes the control document on that row, so a later candidate page no longer selects it. The dry run writes nothing, so it counted the destination again and could report one more `packages_registered` per merge than the real run. A real run also registered the destination a second time when it sat later on the same page. Both modes now remember such destination rows for the rest of the call and pass over them. A dry run resumed with `after` no longer remembers rows from the earlier call.
