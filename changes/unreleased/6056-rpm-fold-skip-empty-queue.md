---
section: Changed
issues: [#6056]
---
- **The hosted RPM repodata builder no longer writes WAL and catalog rows on every tick when no root is dirty** (#6056). Every replica runs the builder every 2 s, and each tick folded queued dirty marks in a transaction that took an advisory lock and created a temp table, even with nothing queued, which is always the case on an instance with no hosted RPM repository. Temp-table catalog rows are WAL-logged, so an idle instance generated WAL every two seconds, which adds up on a Postgres server shared by many instances. The fold now checks for queued marks first and returns when there are none. Measured on three idle instances sharing one Postgres: WAL down 83%, statements per instance down 35%. A mark committed after the check is folded at the next tick, and a root's `dirty_since` is still the mark's own time, so build timing is unchanged.
