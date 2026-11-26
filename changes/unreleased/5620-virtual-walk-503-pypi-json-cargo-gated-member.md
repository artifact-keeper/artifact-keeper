---
section: Changed
issues: [#5620]
---
- **A virtual repository answers `503` with `Retry-After` on the PyPI JSON API, the Composer package metadata (`p2/` and v1 `p/`) and a Cargo sparse index entry served through an age-gated member when no member has the package and a member could not answer** (#5620). #5620's earlier changes covered the npm packument, the PyPI simple page and files, the Cargo sparse index, Helm charts and OCI manifests, blobs and tags. Three walks still read an unavailable member (an upstream `5xx`, a transport failure or timeout, an open circuit) as a miss and answered `404`: the PyPI JSON API (`/pypi/{virtual}/pypi/{project}/json` and `/pypi/{project}/{version}/json`, which Poetry and other tools read), the Composer `p2/{vendor}/{package}.json` and `p/{vendor}/{package}.json` documents (a `404` tells Composer the package does not exist), and the Cargo sparse index when the member that could not answer has an age gate. A miss or a permanent `4xx` from every member still answers `404`, and a member that answers still serves.

  **Default change:** these routes answer `503` with `Retry-After: 1` during a member outage where they answered `404`. There is no setting for it.
