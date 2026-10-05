---
section: Added
issues: [#4456, #2024]
---
- **Lifecycle policies can combine several conditions and can be scoped to a tag or version pattern** (#4456, #2024). The new `composite` policy type takes a `conditions` list that is ANDed. For example, `{"conditions": [{"type": "max_age_days", "value": 90}, {"type": "no_downloads_days", "value": 30}]}` deletes only artifacts that are older than 90 days and also have not been downloaded in 30 days.
  - Each condition uses the same SQL as the single-condition policy of the same name.
  - `min_keep`, `match` and `exclude` work on a composite policy exactly as they do on `max_age_days`.
  - Every policy type also accepts `"match": {"version_pattern": "^sha-"}`, which limits the policy to artifacts whose version (the tag, for container images) matches the regex. It is applied before `min_keep` and `max_versions` count their kept versions, so "keep the 5 newest" counts only in-scope versions. The pattern is a PostgreSQL regular expression, checked by PostgreSQL when the policy is saved, and unanchored unless it uses `^`/`$`.
  - The preview and the live run share each definition, so a preview reports exactly what the run deletes.
  - A composite policy, or any policy with `match.version_pattern`, never evicts a Remote repository's proxy cache: cache entries have no version. Assigning one to a non-OCI Remote repository is refused with 422, and a global one skips the cache and reports why.
  - Day windows (`days`, and each condition's `value`) must now be at most 36500. A larger value used to wrap around to a much shorter window; it is now refused when the policy is saved.
