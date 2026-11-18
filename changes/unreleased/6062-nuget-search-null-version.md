---
section: Fixed
issues: [#6062]
---
- **NuGet search no longer fails with `DATABASE_ERROR` when the repository holds a file uploaded at its root** (#6062). Such a file has no version, which made the package's version list NULL and the whole search response fail to decode. Search now leaves rows without a version out, the same way the registration and autocomplete endpoints already do
