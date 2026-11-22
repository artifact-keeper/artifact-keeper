---
section: Fixed
issues: [#6345]
---
- **An age-gate review decision on a Maven Remote now shows through the Virtuals over it at once, on every replica** (#6345). A Virtual kept its merged `maven-metadata.xml` for up to 60 s after an approval, rejection or reopen, so a version the gate had just rejected stayed listed and resolvers picked it, then got the `451` on download. A review decision or policy write now drops the merges of every Virtual that reaches the Remote, including through nested Virtuals, and a merge that was in flight during the decision is not kept. The other replicas get the same invalidation over the database notification channel `ak_age_gate_invalidation_v1`, which also drops their 15 s reused age-gate documents for that Remote; a replica that misses it converges within the old windows.
