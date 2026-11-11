---
section: Fixed
issues: [#5621]
---
- **Virtual metadata merges no longer fail because one member is down or refuses** ([#5621]). For Helm `index.yaml`, conda `repodata.json`/`channeldata.json`/shard index, Maven `maven-metadata.xml` and its checksums, and the CRAN, Hex, Puppet and Bazel indexes:
  - A member answering an upstream `5xx` or a transport error, or not answering within `AK_VIRTUAL_MEMBER_METADATA_TIMEOUT_SECS`, is left out. The merge of the members that answered is served marked partial: `X-AK-Partial-Members`, `Cache-Control: no-store`, `Warning: 199`, no `ETag`. Before, Helm and conda answered `502` and Maven answered `502` for a member past the deadline.
  - A member answering a permanent `401`/`403`/`451` is a miss, as in the artifact walk.
  - With no member able to answer, the response is `503` with `Retry-After`.
  - The conda merge now honours the member deadline. A hung member used to hold the request for the upstream's 60 s timeout.
  - A Maven merge built without a member is no longer kept in the 60 s virtual metadata cache.
  - A member document that does not parse is still a `502` unless the virtual sets `virtual_metadata_partial`. `GET /api/v1/repositories/{key}` and the listing now report `virtual_metadata_partial` on virtual repositories.
