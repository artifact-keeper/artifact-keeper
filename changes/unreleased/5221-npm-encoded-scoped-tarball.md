---
section: Fixed
issues: [#5221]
---
- **npm: a scoped tarball requested with an encoded slash is served** (#5221). `GET /npm/{repo}/@scope%2fname/-/name-1.0.0.tgz`, which yarn sends for some scoped packages, answered 400 ("Scoped package name must have exactly one '/'") while the unencoded `@scope/name/-/…` form returned 200. The encoded name is a single path segment, so the request matched the scoped version route with `-` as the package. That route now recognises the shape and serves the tarball, the same as the unencoded path, on Local, Remote and Virtual repositories.
