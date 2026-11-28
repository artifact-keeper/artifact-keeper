---
section: Added
issues: [#5178]
---
- **Conda advisory coverage is now inspectable and refreshable without a restart** (#5178). `GET /api/v1/admin/security/conda-alias-map` reports whether a mapping is loaded, its entry count, provenance, age, load error and last attempt; `POST .../reload` re-reads the configured file or optional URL. A failed load keeps the last good map, an aged map produces a throttled warning, and the settings and air-gapped import path are documented.
