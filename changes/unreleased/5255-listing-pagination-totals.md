---
section: Fixed
issues: [#5255]
---
- **Artifact listings now report an exact `pagination.total` and `total_pages` on `page=N` requests, so a client that pages up to `total_pages` gets every item** (#5255). Without `?count=exact`, `GET /api/v1/repositories/{key}/artifacts` reported a lower bound (the rows seen so far, plus one when another page exists) that looked exact: with 10 cached items in a remote repository at `per_page=3`, page 1 said `total=4, total_pages=2`, and a client that looped to that `total_pages` fetched 6 of the 10. The flat hosted, virtual and remote listings now count by default on `page=N` requests, including the first page of any walk. `?cursor=` pages keep the cheap total by default, so a cursor walk of a large repository stays O(page) per request, and the new `?count=lower_bound` restores it everywhere.

  Every artifact listing response, flat and grouped, now carries `total_is_exact`, so a lower-bound total is machine-detectable; the `group_by=maven_component` and `group_by=docker_tag` listings keep their lower-bound default and say so. A page past the end of any listing no longer inflates the total (page 5 of that 10-item listing said `total=12`): an empty page past the start now runs the count and reports the real total.
