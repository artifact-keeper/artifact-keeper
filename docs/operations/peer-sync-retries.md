# Peer sync retries

The sync worker pushes queued artifacts to every subscribed peer, one row in
`sync_tasks` per artifact and peer. How a failed transfer is counted depends on
what failed.

| Failure | Counts against the task | Charged to the peer |
|---|---|---|
| The peer answered with an error (5xx, 401, a timeout or reset after the request was sent) | one attempt of `SYNC_TASK_MAX_RETRIES` (default 3); the task is failed for good after the last | backoff, `consecutive_failures`, demotion to `degraded` |
| The peer refused this one artifact (checksum mismatch, immutable path taken, quota) | failed for good at once | `transfer_failures_total` only |
| No connection was made (refused, connect timeout, name resolution, TLS handshake) | no attempt (#6134), within `SYNC_TASK_UNREACHABLE_MAX_SECS` | backoff, `consecutive_failures`, demotion to `degraded` |

A failed task with attempts left is retried once its peer is `online` (or
`syncing`) and out of backoff. A write made as its peer drops off the network
therefore waits out the outage and is delivered after the heal, instead of
spending its attempts before the peer is marked down.

Unreachable attempts are bounded in time, not in count. The first unreachable
failure of a task stamps `sync_tasks.unreachable_since`. A delivery, an
answered failure or a re-queue clears it. If the peer is still unreachable
more than `SYNC_TASK_UNREACHABLE_MAX_SECS` later (default `86400`, 24 hours,
minimum `60`), the next attempt fails the task for good. Its `error_message`
then starts with `peer unreachable for more than <N> s:`. This covers a peer
that looks online but never accepts a connection from this instance: a
one-way firewall, a certificate this side refuses, or an unreachable scored
endpoint. Re-queue such a task by changing the artifact, re-evaluating its
sync policy or re-registering the peer.

## Metrics

| Metric | Type | Labels | Incremented when |
|---|---|---|---|
| `ak_sync_task_unreachable_failures_total` | counter | `outcome` = `retrying` or `exhausted` | a transfer could not reach its peer; `exhausted` when that failure made the task permanently failed because of `SYNC_TASK_UNREACHABLE_MAX_SECS` |

A steadily rising `retrying` count with peers shown `online` means this
instance cannot connect to a peer that is otherwise healthy.

## Settings

| Variable | Default | Effect |
|---|---|---|
| `SYNC_TASK_MAX_RETRIES` | `3` | answered failed attempts before a task is failed for good |
| `SYNC_TASK_RETRY_BACKOFF_BASE_SECS`, `SYNC_TASK_RETRY_BACKOFF_MAX_SECS` | `300`, `300` | peer backoff after a failed transfer |
| `SYNC_TASK_UNREACHABLE_MAX_SECS` | `86400` | how long a task may keep failing to reach its peer |
