---
section: Changed
issues: [#5489]
---
- **A Maven GET against a virtual repository issues fewer database queries** (#5489). Serving a virtual repository read its member list twice per request, once for the dependency-confusion guard and again for per-caller authorization, and ran the `artifacts` exact-path and SNAPSHOT lookups that a virtual repository can only miss. The list is now read once and shared (the guard keeps the unnarrowed list), and the lookups run only for hosted repositories. No behaviour change.
