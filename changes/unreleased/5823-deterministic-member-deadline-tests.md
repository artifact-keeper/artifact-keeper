---
section: Fixed
issues: [#5823]
---
- **The virtual member deadline tests no longer fail CI on a loaded runner** ([#5823]). The conda, Helm and Maven tests added for #5621 gave the healthy member 300 ms to answer and stood in for the stalled one with a delayed wiremock response, so on a busy runner the healthy member could miss the deadline too and the merge answered `503`. The stalled member is now an upstream that accepts connections and never answers, and the deadline is generous, so the outcome no longer depends on timing. Test-only change.
