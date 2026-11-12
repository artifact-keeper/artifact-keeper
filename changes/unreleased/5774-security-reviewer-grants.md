---
section: Added
issues: [#5774]
---
- **Admins grant the `security-reviewer` role to users and groups** (#5774). `GET /api/v1/admin/security-reviewers` lists who holds it, and `PUT`/`DELETE` on `/users/{id}` or `/groups/{id}` grant and revoke it, so a SQL insert is no longer the only way to make someone a reviewer. A group grant covers every member, SSO-synced groups included, so the identity provider decides who reviews. The grant lives in two new tables (`user_global_roles`, `group_global_roles`, migration 376) instead of `role_assignments`, so the existing repository access checks are not affected. Service accounts never hold the capability, and only an admin can add members to, or rename, a group that carries a global role (an SSO group is matched to the identity provider by name).
