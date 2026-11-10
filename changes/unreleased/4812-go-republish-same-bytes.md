---
section: Fixed
issues: [#4812]
---
- **A deleted Go module version can only be published again with the same bytes** ([#4812]). The hosted Go upload (`PUT .../@v/<version>.zip` and `.mod`) purged the soft-deleted row at that path without looking at it, so once a release was deleted the same version could come back with different content, which `go.sum` and the checksum database then reject on every client. It now goes through the same check as cargo, npm and maven: a deleted release is restored with identical bytes, other bytes answer 409.
