---
section: Fixed
issues: [#3887]
---
- **Conan v2 API now answers 404 for a missing recipe, revision or package instead of an empty 200** (#3887). The recipe revisions list, a revision's file list, the package search for a revision, the package revisions list and a package revision's file list returned `200` with an empty body when the reference did not exist, so the Conan client treated the remote as authoritative and stopped instead of falling through to the next remote. They now return `404` with the official Conan server's wording (`Recipe not found: '<ref>'`, `Binary package not found: '<ref>:<package_id>'`). A package search on an existing revision with no binaries still returns `200 {}`. Private repositories still answer `401` before the lookup, and virtual repositories only consult members the caller can read, so the 404 reveals nothing about content the caller cannot see.
