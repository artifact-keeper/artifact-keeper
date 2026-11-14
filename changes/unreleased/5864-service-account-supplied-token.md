---
section: Added
issues: [#5864]
---
- **A service-account token can be created with a value the caller supplies** (#5864). `POST /api/v1/service-accounts/{id}/tokens` takes an optional `token` in the shape of a generated one (8 hex digits, `_`, 32 hex digits), stored hashed like a generated one, so a token managed from Terraform can keep its secret in an external store such as Vault and keep it across a replace. A value whose first 8 characters match a live token is refused with 409, and a value can be minted again once its token is revoked. Leaving `token` out still generates one. Contributed by @nicola-preda.
