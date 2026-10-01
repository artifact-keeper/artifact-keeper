---
section: Fixed
issues: [#4203]
---
- **`skip_policy_check` on the promotion endpoints is honoured for admins only** (#4203). Any non-admin API token with the `promote:artifacts` scope could set the flag and switch off the quality gate, the CVE/licence policy and the promotion rules on both the single and the bulk promote route. A non-admin caller that passes the flag now gets 403 naming it, and when an admin does use the override the `promotion_history` audit record carries a `policy_check_skipped` marker instead of reading like a policy that ran and passed.
