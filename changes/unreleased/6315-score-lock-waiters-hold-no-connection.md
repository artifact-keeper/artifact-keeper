---
section: Fixed
issues: [#6315]
---
- **Security score recalculations waiting for their repository's lock no longer hold a database connection each** (#6315). Every recalculation took a connection from the request pool and then waited on the per-repository advisory lock with it, so a burst of scans finishing in one repository could hold most of a small pool idle while uploads, downloads and logins timed out with 503 `POOL_EXHAUSTED`. Recalculations of one repository now queue inside the process first, so each replica holds at most one connection per repository for them. The advisory lock still orders recalculations across replicas (#5891). Contributed by @nicola-preda.
