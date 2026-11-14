---
section: Fixed
issues: [#5603]
---
- **`PERMISSION_DENIED` audit rows for admin routes record the full request path** (#5603). A non-admin refused on an admin-only route was audited with `details.path` set to what was left after the router nest (`/settings` for `GET /api/v1/admin/settings`), so the row didn't say which API was refused. The denial now records the full path, the one the forced password-change gate already reads.
