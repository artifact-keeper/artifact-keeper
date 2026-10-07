---
section: Fixed
issues: [#4555]
---
- **The `unknown` conda subdir is served as an empty index instead of 400, and a virtual channel's remote member that does not publish a subdir contributes nothing instead of failing the merge** (#4555). rattler and pixi request `unknown/repodata.json` when no platform is given (`pixi search` without `-p`), and the registry's subdir validation answered 400, which aborted the client's whole query. `unknown` is now a valid subdir on read paths (uploads still refuse it) and is served as an empty `repodata.json`. In a virtual channel, a remote member whose upstream answers 404 for every encoding of a subdir's repodata (conda-forge has no `unknown/`, most channels lack most platforms) now contributes no records rather than turning the request into a 502; any other member failure still fails the request.
