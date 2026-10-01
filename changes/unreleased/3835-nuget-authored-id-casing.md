---
section: Fixed
issues: [#3835]
---
- **NuGet V3 search, registration, autocomplete and the V2 feed report a package id with the casing its `.nuspec` declared** (#3835). A push stores the id lowercased for case-insensitive lookups, and every read surface echoed that stored name, so `Some.Package.Id` came back as `some.package.id`. Every surface now reads the id from the package's single catalog row, which keeps the first push's spelling, so a later push with different casing, a deleted version or a version without push metadata no longer changes it. V3 URLs stay lowercased as the protocol requires; the V2 feed's entry and content URLs carry the reported id, as nuget.org's V2 feed does. Packages pushed before this fix report their authored casing too, without republishing.
