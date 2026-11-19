---
section: Added
issues: [#6194]
---
- **`artifact-keeper db-migrate` applies the database migrations and exits** (#6194). It runs the same ledger repairs and migrations as server startup and needs only `DATABASE_URL`, so a Kubernetes deployment can run it in a pre-upgrade Job and start the backend with `SKIP_MIGRATIONS=true`. A long migration then no longer runs inside the backend's startup probe budget.
