---
section: Changed
issues: [#5363]
---
- **A NuGet, Chocolatey or PowerShell Remote now caches the files of one package version forever and never revalidates them** (#5363). The cache classifier had no NuGet arm, so a `.nupkg` shared the mutable TTL with the service index and version lists: with the default TTL it was revalidated every five minutes (and removed from the cache when the upstream answered 404), and a TTL long enough to keep packages also froze `{id}/index.json` and the registrations, hiding newly published versions. The flat-container `{id}.{version}.nupkg` and `{id}.nuspec` and the V2 `package/{id}/{version}` download are now immutable, like a Debian `pool/` package; every other NuGet path keeps the repository's TTL.
