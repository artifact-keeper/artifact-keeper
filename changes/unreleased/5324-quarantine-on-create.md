---
section: Security
issues: [#5324]
---
- **`POST /api/v1/repositories` now applies `quarantine_enabled` and `quarantine_duration_minutes` instead of silently dropping them** (#5324). The two fields existed only on the update request, so a repository created with the upload-time quarantine period turned on answered 200, stored neither setting, and served its first uploads unheld until a `PATCH`. Create now validates and stores them through the same code as update: the create response reports the stored values as `GET` does, and enabling quarantine on a Virtual repository is refused with 400 on create as it already was on update. `virtual_metadata_partial` is applied on create the same way. The remaining update-only settings that create does not apply (a non-empty `release_repository_key`, `curation_enabled: true`, a `curation_default_action` other than `allow`) are refused with a 400 naming the field instead of being ignored; set them with `PATCH` after creating the repository.
