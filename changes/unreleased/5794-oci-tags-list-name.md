---
section: Fixed
issues: [#5794]
---
- **OCI `tags/list` answers `name` as the full repository name from the request path** (#5794). `GET /v2/docker-local/aktest/tags/tags/list` now returns `"name": "docker-local/aktest/tags"`, as the OCI Distribution Spec requires, instead of the image path inside the repository (`aktest/tags`). This applies to hosted, Remote and Virtual repositories, with and without `?n=` pagination. Clients that compared the returned name to the image path alone see the repository key in it now.
