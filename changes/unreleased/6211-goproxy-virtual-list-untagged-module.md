---
section: Fixed
issues: [#6211]
---
- **Go virtual repositories list a module that has no tagged version** (#6211). `@v/list` through a Virtual answered `404 module not found` for a module its Remote member resolves with an empty list, so `go list -m -versions` and `go install <module>@latest` failed through the Virtual. It now answers `200` with an empty body when a member resolved the module, and `404` only when none did.
