---
section: Fixed
issues: [#6062]
---
- **NuGet packages uploaded through the generic web UI path are now indexed as packages** (#6062). The shared upload finalizer reads the `.nuspec` of a `.nupkg`, stores its identity and metadata, and registers the package and version in the catalog, so the V3 indexes and native clients can find the upload instead of treating it as an unversioned file.
