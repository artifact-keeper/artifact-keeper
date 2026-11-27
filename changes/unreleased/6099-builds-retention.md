---
section: Added
issues: [#6099]
---
- **Build records have a retention** (#6099, artifact-keeper/artifact-keeper-web#618). Two system settings, `build_retention_days` and `build_retention_keep_last` (per build name), both 0 (off) by default, drive an hourly pass that deletes old build records with their artifact lists, set through `POST /api/v1/admin/settings` (`0..=36500` days, `0..=100000` builds). The artifacts in repositories stay, and nothing is deleted until one of them is set
