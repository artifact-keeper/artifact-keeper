---
section: Fixed
issues: [#4963, #4573]
---
- **Maven jars served through a virtual repository from a remote member now carry `X-Checksum-SHA1`** (#4963, #4573). Maven Resolver skips its separate `.sha1` request when the download carries this header. Direct remote serves already sent it, but a virtual repository's unscanned serve from a remote member did not. The value is the cached `.sha1` of the member that served the bytes, never another member's, and `-SNAPSHOT` files still go without it. A `HEAD` for a released file on a remote or virtual repository now also carries it on a path nothing has cached yet, by fetching the `.sha1` from the upstream once; a `GET` still reads only what is cached.
