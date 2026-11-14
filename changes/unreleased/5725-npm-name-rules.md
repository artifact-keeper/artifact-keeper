---
section: Fixed
issues: [#5725]
---
- **npm package-name checks now follow npm's own rules, so a hosted scoped package whose scope or name starts with `_`, `.` or `~` can no longer be shadowed by a Remote member of a virtual repository** (#5725). The name check behind the virtual shadowing guard rejected names such as `@_scope/x`, `@.scope/x`, `@~scope/x` and `@scope/_x`, which npm accepts, and for those names the guard skipped the ownership check, so a Remote member could serve a tarball the hosted member owns. Those names are now recognised by the guard, by the GitHub Packages tarball rewrite and by the npm scope allow-list (which now accepts scopes such as `@_private`). Core-module names (`http`, `buffer`, `events`) stay accepted.

  Upgrade: `node_modules` and `favicon.ico` (any case), which npm never publishes, are now refused with `400`, and so is a scoped name whose scope or package part is `.` or `..`, including its percent-encoded forms such as `@scope/%2e` and `@%2e/x`; on the filesystem storage backend such names could share a storage key with another package.
