---
section: Added
issues: [#3066]
---
- **Search results now report each artifact's quarantine state** (#3066). `SearchResultItem` gains `quarantine_status` (always present, `not_quarantined` when the artifact carries no state) and `quarantine_until` (timed holds only), with the same contract as the artifact listing; the quarantine reason stays behind `GET /api/v1/quarantine/{artifact_id}`. Quick, advanced, trending and recent search all carry the fields. On the OpenSearch path the values are read from PostgreSQL for each hit rather than from the index, so they are current without a reindex.
