---
section: Fixed
issues: [#3977]
---
- **A quality gate configured to `warn` now reports its violations on a successful promotion instead of nothing at all** (#3977). `promote_artifact` collected warn-level gate violations into a local vector, but `build_success_response` took only `(source, target, promotion_id)` and hardcoded `policy_violations: vec![]`, so the collected violations were dropped on the way out and every successful promotion returned an empty list no matter what the gate found. A gate set to `warn` was therefore silent to the API, the web UI and `ak`: it recorded an evaluation server-side and told the caller nothing. The builder now takes the accumulated violations and both the single and bulk success paths pass them, so a warning gate is visible where it was meant to be. Blocking gates are unchanged -- they never reached this path.
