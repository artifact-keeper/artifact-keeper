---
section: Changed
issues: [#6069]
---
- **A warm Maven jar GET from a Remote repository evaluates the origin-policy gate once, not twice** (#6069). The `X-Checksum-SHA1` header added in #4573 is read from the cached `.sha1` alongside the jar, and both reads went through the #4506 origin gate, so every released-jar GET looked the Remote up again and reloaded its scan policies. The two reads now share one gate evaluation: the sidecar read reuses the jar fetch's pass, while a refusal or a lookup error is never reused. The sharing covers only that pair, so whether the jar is served is still decided by its own gate evaluation; the sidecar read decides only the checksum header. A Lean model (`formal/ArtifactKeeper/Proxy/OriginGateMemo.lean`) proves this, and records the one effect: a deny written, or the repository re-pointed, between the two reads no longer drops the checksum header from a jar that was served anyway.
