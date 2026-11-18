---
section: Fixed
issues: [#5772]
---
- **Quick search finds artifacts published through the native format endpoints** (#5772). Only the REST upload API, the migration worker and the MCP remote wrote to the OpenSearch index, so anything from `mvn deploy`, `npm publish`, `cargo publish` and the other format handlers stayed out of `GET /api/v1/search/quick` until a full reindex, and quick search answered an empty list for it. A search indexer now listens for `artifact.uploaded`, which every hosted publish already emits, and upserts the artifact's document with the same fields the REST path indexes. It only runs when OpenSearch is configured. If it falls behind the event bus it logs how many uploads it skipped, and those need a reindex.
