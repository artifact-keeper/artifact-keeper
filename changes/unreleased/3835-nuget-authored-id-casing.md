---
section: Fixed
issues: [#3835]
---
- **NuGet V3 search, registration, autocomplete and the V2 feed report a package id with the casing its `.nuspec` declared** (#3835). A push stores the id lowercased for case-insensitive lookups, and every read surface echoed that stored name, so `Some.Package.Id` came back as `some.package.id`. The authored spelling kept in the push metadata is now reported (the earliest push's spelling, matching the single catalog row), while every URL stays lowercased as the V3 protocol requires. Packages pushed before this fix report their authored casing too, without republishing.
