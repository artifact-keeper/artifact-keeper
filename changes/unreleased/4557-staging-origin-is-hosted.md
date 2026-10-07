---
section: Fixed
issues: [#4557, #4152]
---
- **An upload into a staging repository, and every copy promoted from it, records its origin as `hosted` instead of `virtual`** (#4557, #4152). The origin derivation mapped `local` to `hosted`, `remote` to `proxy` and every other repository type to `virtual`, so a package published to a staging repository was stamped `virtual`, and promotion, which carries the source origin over to the copy, then showed the promoted package in the release repository as "stored in a virtual repository", and an `allowed_kinds: ["hosted"]` origin predicate refused it. Migration 284 maps `staging` to `hosted` and re-stamps the rows already recorded wrongly: any origin of kind `virtual` that names a repository that is not virtual becomes `hosted`, with every other key unchanged. It runs in 5000-row batches, admits only that one rewrite through the immutability trigger while it runs, and restores the strict trigger at the end.
