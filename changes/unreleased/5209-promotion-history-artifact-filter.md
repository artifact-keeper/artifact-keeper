---
section: Fixed
issues: [#5209]
---
- **`GET /api/v1/promotion/repositories/{key}/promotion-history` now honours its `artifact_id` query parameter** (#5209). The parameter was documented and parsed but never applied, so the endpoint returned every entry for the repository and `pagination.total` counted them all. Both the page and the total are now filtered by `artifact_id` when it is given, alongside the existing `status` filter.
