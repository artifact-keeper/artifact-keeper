---
section: Fixed
issues: [#5885]
---
- **A published hosted Go module version stays immutable on delete and republish** (#5885). Hosted Go stores a version as `<module>/<ver>/<ver>.zip` and `<module>/<ver>/go.mod`, which the release delete gate (it knows the `/@v/` download form) called mutable, so a repository owner who isn't an admin could delete a published module version. Those paths now map to their `@v/` download path before they are classified, so the delete answers 409, and an administrator can still retract. The upload (`PUT .../@v/<version>.zip` and `.mod`) also purged a soft-deleted row at its path without looking at it, so a deleted version could come back with different content, which `go.sum` and the checksum database then reject on every client. It now goes through the same check as cargo, npm and maven: identical bytes restore the version, other bytes answer 409. Contributed by @nicola-preda.
