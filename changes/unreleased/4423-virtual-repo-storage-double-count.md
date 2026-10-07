---
section: Fixed
issues: [#4423, #2785]
---
- **Virtual repositories no longer report their members' bytes as their own `storage_used_bytes`** (#4423). Since #2785 a virtual repository's `storage_used_bytes` in `GET /api/v1/repositories` and `GET`/`PATCH /api/v1/repositories/{key}` was the sum of its members, so any per-project or instance total that added up repositories counted those bytes twice. A virtual repository now reports `storage_used_bytes: 0`, and the member total moves to a new `member_storage_used_bytes` field (still scoped to the members the caller can see; `null` for non-virtual repositories). The project quota rollup also skips virtual repositories explicitly. Clients that display a virtual repository's size should read `member_storage_used_bytes`.

  **Upgrade note — deliberate behaviour change for virtual repositories.** Before this release a virtual repository's `storage_used_bytes` was the combined size of its members (#2785); it is now always `0`, and that combined size is in `member_storage_used_bytes` (list, detail, create and PATCH responses). Clients that show a virtual repository's size, including the web UI and the CLI until their follow-up releases ship, will show 0 for every virtual repository until they read `member_storage_used_bytes`. Totals that sum `storage_used_bytes` across repositories need no change: they are now correct.
