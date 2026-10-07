---
section: Fixed
issues: [#4502]
---
- **A lifecycle preview of a stored policy whose `match.version_pattern` uses `\b` / `\B` now lists the problem in `errors` instead of failing with 400** (#4502). The preview stopped at the `\b` refusal `match.version_pattern` has had since #4459 and returned `400 VALIDATION_ERROR` without its `errors` list, while the documentation said such a policy is reported and still runs. The preview now returns 200 with the problem in `errors` and zero matches, and a live run refuses the policy with 400 before it touches any repository. It is still refused rather than run, because a `\b` that matches nothing does not make a scope safe: inside a negative lookahead such as `^(?!.*\bstable)` it widens the scope to every version. The documentation now says so. Nothing stored is changed; fix the pattern (use `\y` / `\Y`) with `PATCH /api/v1/admin/lifecycle/{id}`.
