---
section: Added
issues: [#4297]
---
- **Admins can pre-provision OIDC-managed groups before the first user login** (#4297). This enables declarative and IaC-driven RBAC configuration while keeping the IdP authoritative for membership; the new admin API reuses the existing ownership-safe federated-group provisioning path and does not create users or memberships.
