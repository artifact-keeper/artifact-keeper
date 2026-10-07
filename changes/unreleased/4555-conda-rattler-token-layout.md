---
section: Added
issues: [#4555]
---
- **Conda channels accept rattler's token URL layout, `/t/<TOKEN>/conda/<repo>/...`** (#4555). Conda's `.condarc` token channels put the token after the format prefix (`/conda/t/<TOKEN>/<repo>/...`), which the registry already served, but rattler and pixi (`pixi auth login <host> --conda-token`) store the token per host and insert `/t/<TOKEN>` at the front of every request path, so every such request 404'd. The same read, upload and attestation routes are now also mounted under `/t/<TOKEN>/conda/<repo>/...`, with the token resolved by the same visibility middleware. The `Authorization` header remains the recommended form, since a token in a URL can end up in logs and lockfiles.
