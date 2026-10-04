---
section: Added
issues: [#2155]
---
- **System-wide maintenance and downtime banners** (#2155). Administrators can create, update and delete banners through `/api/v1/admin/banners`. Each banner has a title, a message, a severity (`info`, `warning`, `critical`), a target (`all`, `ui`, `api`), an optional `http(s)` link, an optional `starts_at` / `ends_at` window and an enabled flag. Every change is audited. The new public `GET /api/v1/banners` (`?target=ui|api`) returns the banners active now, most severe first. A banner expires on its own when its window ends, so no cleanup job is needed. The endpoint needs no authentication and stays reachable when `AK_GUEST_ACCESS_ENABLED=false`, so the login page can show it. Adds migration `258_system_banners`, which creates a new, empty table. Rendering banners in the web UI and the CLI are follow-ups in those repositories.
