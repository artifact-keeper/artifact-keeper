---
section: Fixed
issues: [#3953]
---
- **A hosted crate name in a Cargo virtual repository no longer shadows every upstream version of that name — only the exact locally-held name@version is shadowed** (#3953). The Virtual download ownership guard fired on the crate name alone, so one internally-published version of a crates.io name made every other version 404 through the virtual while the merged sparse index kept advertising it, failing `cargo build`. The guard now fires on the exact name@version (the npm fix from #3646 / PR #3743 applied to cargo), so upstream versions resolve through the Remote member while the dependency-confusion protection on the locally-owned coordinate is unchanged.
