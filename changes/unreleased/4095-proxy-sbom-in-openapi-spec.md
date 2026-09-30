---
section: Fixed
issues: [#4095]
---
- **The proxy-cache SBOM and package-analysis endpoints are now in the OpenAPI spec** (#4095). `GET /api/v1/repositories/{key}/security/proxy-sbom` and `GET /api/v1/artifacts/{id}/package-analysis` were annotated and routed but never registered in the merged spec, so the exported spec and every generated SDK omitted them. A new test fails whenever an annotated handler is missing from the spec.
