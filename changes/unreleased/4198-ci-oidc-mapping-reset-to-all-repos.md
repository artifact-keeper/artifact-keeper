---
section: Fixed
issues: [#4198]
---
- **A restricted CI OIDC identity mapping can be reset to all repositories via the admin API** (#4198). `PUT /api/v1/admin/ci-oidc/{id}/mappings/{mid}` treated an omitted `allowed_repo_ids` and an explicit `null` identically ("leave unchanged"), so once a mapping had any repository restriction no API call could clear it — the only way back to unrestricted was deleting and recreating the mapping, which changed its service-account identity. The field is now tri-state: omit it to leave the restriction unchanged, send `"allowed_repo_ids": null` to clear it (all repositories), and send an array to restrict (`[]` still denies every repository).
