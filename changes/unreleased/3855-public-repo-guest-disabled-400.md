---
section: Changed
issues: [#3855]
---
- **Creating or updating a repository as public while guest access is disabled now fails with `400 Bad Request` instead of silently rewriting the repository to private** (#3855). With `AK_GUEST_ACCESS_ENABLED=false`, a request carrying `is_public: true` (or `allow_anonymous_access: true`) contradicted a deliberate operator policy; the old coercion answered `201`/`200` for a repository the caller never asked for, which produced perpetual Terraform drift and late "why can nobody pull this anonymously" surprises. The API now rejects the request with an error naming the switch (`AK_GUEST_ACCESS_ENABLED=false`) and the two resolutions — enable guest access, or choose a non-public visibility. **Breaking change:** clients that relied on the silent coercion must stop sending `is_public: true` on guest-disabled instances.
