---
section: Fixed
issues: [#4933]
---
- **The guest-access guard no longer binds against the directory, a rejected package login writes one `LOGIN_FAILED` row, and web LDAP login no longer undoes an administrator's deactivation** (#4933). With guest access off, the guard now answers `/api/v1` and `/v2` from local credentials and leaves the single directory bind to the package-route middleware, so management and OCI requests cause no directory traffic and one rejected package request no longer writes two audit rows. LDAP accounts now keep `is_active` across a federated login, matching the passthrough: an admin-disabled account must be explicitly reactivated.
