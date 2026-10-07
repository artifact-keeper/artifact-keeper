---
section: Added
issues: [#2024]
---
- **Lifecycle policies can keep the newest N versions under an age rule and can be scoped to a path prefix** (#2024). `max_age_days` accepts an optional `min_keep` (`{"days": 14, "min_keep": 5}`): the newest five artifacts of each package or image, grouped and ordered exactly as `max_versions` groups them, survive even when they are older than the window, and excluded tags do not take one of those slots. Every policy type also accepts `"match": {"path_prefix": "..."}`, which limits it to artifacts whose repository-relative path starts with that literal string. Both are compiled into the same SQL as the dry-run preview, so a preview reports exactly what the run deletes. Other `match` selectors and the composite `conditions` list from the request are still rejected by name until they are implemented.
