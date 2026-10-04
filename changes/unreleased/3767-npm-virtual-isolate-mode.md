---
section: Added
issues: [#3767]
---
- **npm virtual repositories can opt into an isolate mode where a hosted package name never resolves from upstream** (#3767). A virtual npm repository merges every member's packument, so an upstream version of a name a hosted member owns (an attacker's `internal@1.0.1` next to your `internal@1.0.0`) is advertised and served. Setting `npm_virtual_isolate_hosted_names: true` on the virtual (create or update repository) serves a name owned by any hosted member exclusively from the members: upstream versions of that name are dropped from the merged packument and refused on the tarball route, so resolution and download agree, matching the PyPI virtual's isolation. Names no hosted member owns still federate from upstream, and the default stays the existing union behaviour. The shadowing-guard database-error log now names the format that hit it instead of a hard-coded label.
