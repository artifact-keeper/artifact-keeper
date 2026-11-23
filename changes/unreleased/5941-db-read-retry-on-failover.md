---
section: Changed
issues: [#5941]
---
- **Reads survive a PostgreSQL switchover or failover: a `GET` or `HEAD` that lost its database connection is replayed once instead of failing** (#5941). A switchover (CloudNativePG, Patroni, a managed database's maintenance) terminates every pooled connection, and every request in flight answered a 5xx, including artifact downloads, metadata and index lookups, and search, so a package client failed its build where a retry a moment later would have worked.

  A bodiless `GET` or `HEAD` that wrote nothing and answers 5xx after a database error classified as a lost connection (a socket error, SQLSTATE class 08, 57P01, 57P02, 57P03, or 25006 when the old primary came back as a standby) is now replayed once, after a jittered 250-500 ms pause, on a fresh connection. Writes are never replayed and keep failing fast, and that includes a `GET` that wrote: every statement a request runs is checked as it runs, so one that filled a proxy cache, queued a download counter or began a transaction is not replayed, and neither are the SSO callbacks, the rest of `/api/v1/auth/` and the OCI token exchange. Query errors, constraint violations, a statement or lock timeout on a live connection, and pool exhaustion are not replayed either, and neither is a download whose body had started. Each replay logs a `WARN` and counts in `ak_db_read_retries_total{outcome="recovered"|"failed"}`, so a database that keeps dropping connections stays visible.

  This is on by default. Set `DATABASE_READ_RETRY=false` to keep the previous behaviour.
