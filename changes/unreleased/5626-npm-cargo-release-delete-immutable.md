---
section: Fixed
issues: [#5626]
---
- **A non-admin can no longer delete a published npm or cargo release through the REST delete** ([#5626]). `DELETE /api/v1/repositories/{key}/artifacts/{path}` refuses a released artifact with `409` for anyone but an administrator, but the check only recognised the upstream URL shapes (npm `<pkg>/-/<file>.tgz`, cargo `crates/…/<crate>-<ver>.crate`). The hosted npm and cargo publish routes store a release as `<name>/<version>/<file>`, and the delete resolves an npm `/-/` path to that stored form before the check, so a writer with the `delete` action got `200` and soft-deleted a published version, whichever path form it sent. The check now also recognises those stored shapes: such a delete answers `409 Cannot delete an immutable/released artifact`, with or without the replication header, and an administrator can still retract a release.
