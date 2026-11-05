---
section: Fixed
issues: [#5227]
---
- **A crate with a renamed dependency builds from a Cargo registry** (#5227). The sparse index now lists a dependency declared as `renamed = { package = "rbase", ... }` as `"name": "renamed", "package": "rbase"`, the index format, instead of copying the publish API's `explicit_name_in_toml` field, which cargo ignores in the index; cargo then looked for the crate under its real name and failed with `cannot find module or crate`. The entry is built from the metadata stored at publish, so crates already published are served correctly without being published again.
