---
section: Security
issues: [#4513, #4365]
---
- **Scan-on-proxy fails closed on an unreadable config, decides cache key and scannability once per request, and refuses ambiguous upstream paths** (#4513, #4365). Four hardening fixes from the scan-on-proxy reviews:

  - An unreadable `scan_on_proxy` configuration now answers a retryable `503` on every enforced format's Remote download (Maven, Gradle, sbt, npm, PyPI, Cargo, NuGet, VS Code, OCI manifests) and every Virtual walk. Before, a direct Remote pull read a database error as "scanning off" and streamed the package unscanned. Maven curation now derives the package from the cache-normalized path, so a trailing `/` no longer skips a curation rule.
  - VS Code gallery asset types are matched ignoring case and fetched and cached under their canonical spelling. Only display metadata (manifest, details, changelog, license, icons, `.vsixmanifest`, signature, language-pack translations) streams unscanned; the package is always scanned, and any other asset type is `404` while the repository scans on proxy. Before, a re-capitalised package asset type streamed the `.vsix` unscanned.
  - One helper now returns each request's proxy-cache key and scan decision from the same normalized path, for Maven, sbt, NuGet, npm, PyPI, Cargo and VS Code. Cache keys for well-formed paths are unchanged, so no warm entry is orphaned.
  - A Remote fetch whose upstream path contains `#`, `;`, a control character or a `%` that is not a valid escape, or a `?` that does not start a well-formed query, is refused with `400` before any upstream request, for every format. npm's `%2F`, Go's `!`-escaping and absolute URLs from an upstream index are unaffected.
