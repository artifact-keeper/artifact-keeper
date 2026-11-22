---
section: Fixed
issues: [#6418]
---
- **A `HEAD` of a cached PyPI distribution on a presigned-download deployment answers with the file's headers instead of a redirect the client cannot use** (#6418). The PyPI file routes run their `GET` handler for a `HEAD`, and a fresh proxy-cache hit was answered with a redirect to a URL signed for `GET`. The signature covers the method, so the object store refused the client's `HEAD` with 403. This applied to a Remote's own file route and to a last-known-good substitute served for an age-gated member of a virtual. The PyPI cache redirect now declines a `HEAD`, as the other redirect paths do (#3209), and the streaming path answers it with the cached entry's headers and no body.
