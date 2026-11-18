---
section: Fixed
issues: [#5608]
---
- **Deleting a user or group now also deletes its fine-grained permission rules** (#5608). The rules table has no foreign key on its polymorphic principal pair, so the rows used to outlive their principal, list as `principal_name: null`, and keep the repository marked as having rules. A trigger on `users` and `groups` removes them inside the deleting transaction, a migration clears the rows left by earlier deletes, and the permissions listing and its total omit any orphaned rule.
