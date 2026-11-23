---
section: Changed
issues: [#6426, #5620]
---
- **RubyGems gem info and quick spec, the Hex package route and conda `.sigs` sidecars answer `503` with `Retry-After` through a virtual repository when no member has the item and a member could not answer** (#6426, #5620). The #5504 rule (a member's upstream `5xx` or `429`, transport failure, timeout or open circuit is not a miss) now covers these walks. They used to answer `404` (`Gem not found`, `Package not found in any member repository`, `Attestation sidecar not found`), which `gem`, `mix` and conda clients report as "not found". The conda sidecar walk already answered `503` in strict member-fallback mode; it now does so in the default mode too. A miss or a permanent `4xx` from every member is still `404`, and a member that answers still serves.

  **Default change:** these routes answer `503` with `Retry-After: 1` during a member outage instead of `404`. There is no setting for this. A member answering `404`, or a permanent `4xx`, keeps the `404`.
