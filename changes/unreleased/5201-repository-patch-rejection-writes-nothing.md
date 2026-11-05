---
section: Fixed
issues: [#5201]
---
- **A `PATCH /api/v1/repositories/{key}` answered with a 400 or 422 changes nothing** (#5201). The handler saved the repository row (visibility, name, description and the other columns) and the earlier `repository_config` settings before it checked the later fields, so a rejected request could still, for example, switch a repository from `private` to `internal`. Every field is now checked before the first write: the `apt_*` fields, `custom_user_agent`, `virtual_metadata_partial`, `quarantine_enabled`, `quarantine_duration_minutes`, `release_repository_key` (including the release repository lookup), the npm scope policy and the `debian` filter config.
