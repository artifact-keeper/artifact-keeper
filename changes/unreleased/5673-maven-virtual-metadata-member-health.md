---
section: Fixed
issues: [#5673]
---
- **A Maven virtual's `maven-metadata.xml` answers an upstream outage in half the time** ([#5673]). When no member listed the artifact, the plugin-prefix second pass of the metadata merge fetched the same path again from every Remote member, including ones the first pass had just found unavailable, so the `503` arrived after twice the upstream connect timeout (about 20 s at the default, up to about 38 s). A member found unavailable is now asked once per request.
