---
section: Changed
issues: [#3734]
---
- **Assigning a lifecycle policy that cannot reclaim anything in a Remote repository now returns 422** (#3734). Before, such a policy was accepted and silently matched nothing. The check runs when you create a policy, attach it, or change its config. It covers `max_versions`, `tag_pattern_*` and `size_quota_bytes`, and also `exclude` lists and `min_keep`, which match artifact versions that proxy-cache entries do not have. OCI Remote repositories (Docker, Podman, Helm OCI and the like) are exempt because pulled manifests have `artifacts` rows. Policies that were already assigned keep running and can still be renamed, disabled, or re-sent their unchanged config.
