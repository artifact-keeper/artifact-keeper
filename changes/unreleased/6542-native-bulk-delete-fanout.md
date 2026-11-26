---
section: Fixed
issues: [#6542, #6489]
---
- **Deleting a Helm chart or running `conan remove` now does what every other delete does afterwards** (#6542, item 2 of #6489). Both soft-deleted in one bulk statement and skipped the per-artifact delete's follow-up, so peers kept the artifacts, no `ARTIFACT_DELETED` audit row or `artifact.deleted` event was written and the search index kept them. Both now go through the lifecycle sweep's batched step (#6479): the work is recorded in the delete's own transaction and run after it commits, and a restart in between leaves it for the next lifecycle tick
