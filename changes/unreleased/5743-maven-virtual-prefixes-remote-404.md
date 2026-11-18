---
section: Fixed
issues: [#5743]
---
- **Maven: a virtual repository no longer publishes a prefix file that denies everything behind a Remote member with no prefix file** (#5743). A Remote member whose upstream answers `404` for `.meta/prefixes.txt` publishes no allowlist, so it can serve any groupId. The virtual used to treat that member as contributing nothing and publish the union of the others, which Maven Resolver reads as authoritative and keeps for a day: every path served only by that Remote was then denied client-side ("the prefixes file denies" / "appears stale"). The union is unknowable in that case, so the virtual now answers `404` (no prefix file, so the client does not filter), exactly as it already does when a member errors.
