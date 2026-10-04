---
section: Changed
issues: [#2524]
---
- **Storage GC and OCI blob GC now read their deletion candidates in bounded pages instead of loading the whole set at once** (#2524). The orphan storage-key scan and both blob-GC phases (mark and sweep) used to fetch every candidate into memory in one query, so a large deletion wave meant one huge result set and an unbounded memory spike. Each scan now walks the candidates 1000 at a time with a keyset cursor and still reclaims everything in a single pass. What GC deletes, and the row-lock re-check before each deletion, are unchanged.
