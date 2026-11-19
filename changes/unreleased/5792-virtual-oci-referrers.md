---
section: Fixed
issues: [#5792]
---
- **The OCI Referrers API on a Virtual repository now lists the referrers of its members** (#5792). `GET /v2/<virtual>/<image>/referrers/<digest>` always answered an empty index, because the Virtual owns no referrer records and its members were never consulted, so `oras discover` listed nothing and cosign v3 with its default bundle format reported `no signatures found` for an image signed in a hosted member. The Virtual now merges the referrers of every member the caller may read, in member order and each digest once, and applies the `artifactType` filter and the `OCI-Filters-Applied` header to the merged list as a hosted repository does. A member the caller may not read contributes nothing.
