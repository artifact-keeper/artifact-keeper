---
section: Fixed
issues: [#4430]
---
- **The bundled `docker/init-dtrack.sh` grants `VIEW_POLICY_VIOLATION` to the Automation team, so Dependency-Track policy violations load** (#4430). Reading a project's policy violations (`GET /api/v1/violation/project/{uuid}`) needs that permission, which the script did not grant, so every request answered `502 Bad gateway` with Dependency-Track's `403 Forbidden` underneath. A Dependency-Track instance or API key you provisioned yourself must grant it to the key's team too; the permission hint in the error message and `.env.example` now list it with the other five.
