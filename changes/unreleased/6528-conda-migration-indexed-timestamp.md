---
section: Fixed
issues: [#6528]
---
- **Conda packages migrated from Artifactory or Nexus keep their original publish time as `indexed_timestamp`** (#6528). The migration inserted every row at the import time, so each migrated conda package looked brand new and was held back by client `exclude-newer` windows. The initial import of a conda row is now seeded from the source's `created` (Artifactory, else `modified`) or `lastModified` (Nexus), RFC 3339 or a `+0000` offset, clamped to now, with the import time as the fallback. A re-import that revives a soft-deleted row counts it from the revival, unless the conda age gate's sighting ledger already holds the same sha256, which keeps that first sighting. A live row keeps the time it was first indexed at. Other formats are unchanged.
