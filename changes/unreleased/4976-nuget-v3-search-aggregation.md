---
section: Fixed
issues: [#4976]
---
- **NuGet V3 search now aggregates package versions across virtual repository members and reports the latest stable SemVer** (#4976). A virtual NuGet repository combining multiple V2 remotes previously kept whichever member's result arrived first and applied V3 package paging to V2 version rows before grouping, so search could show an arbitrary older version and omit versions from other members. Search now groups version rows before paging, merges duplicate package IDs and their version lists, recalculates the root version with the requested prerelease policy, and preserves the available version entries.
