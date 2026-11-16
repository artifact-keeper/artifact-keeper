---
section: Fixed
issues: [#5933]
---
- **The Package Age Policy no longer holds a Remote's version listings** (#5933). A proxied npm packument, PyPI simple page, `maven-metadata.xml` or Cargo sparse index file took its hold from the upstream `Last-Modified`, which the registry bumps on every publish, so one release inside the window held the whole listing and `npm install` of any version answered 409 "Artifact is quarantined and pending security review". Those listings are now cached with no hold. The young version's own file (tarball, wheel, jar, `.crate`) is still held until the window passes. A listing already cached under a hold keeps it until the window passes or an admin releases it.
