---
section: Deprecated
issues: [#3522]
---
- **`POST /api/v1/users/{id}/roles` is deprecated in favour of `POST /api/v1/permissions`** (#3522). Roles assigned through it are written to `user_roles`, which is identity and SSO role-mapping metadata that no authorization gate reads, so the call never granted access to any repository (#3387). The endpoint keeps working unchanged, but it is now flagged `deprecated` in the OpenAPI spec and every successful response carries a `Deprecation: @1791244800` header (RFC 9745) and `Link: </api/v1/permissions>; rel="successor-version"`. To give a user, service account or group access, create a fine-grained grant with `POST /api/v1/permissions` (repository or project targets). No removal date has been set.
