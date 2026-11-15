---
section: Fixed
issues: [#5983]
---
- **Concurrent cold PyPI requests for one project read the upstream simple index once** (#5983). The resolver index memo only helped once a read had landed, so `uv` or pip asking for several `.whl.metadata` sidecars or files of one project at the same time read the whole upstream index once per request (4 sidecars of 53 bytes cost 4 index reads, 10.3 MB, in the report). The memo now single-flights the read per repository and project, and still only keeps successful reads
