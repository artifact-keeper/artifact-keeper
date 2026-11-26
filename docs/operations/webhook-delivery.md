# Webhook delivery

How the webhook delivery worker sends queued deliveries, and how to tune it
(#5195, #5661).

## How deliveries are sent

Every replica runs one delivery worker. The producer (enabled with
`WEBHOOKS_V2_PRODUCER_ENABLED=true`) writes a row into `webhook_deliveries` for
each matching webhook and wakes the worker on that replica at once. The worker
also polls every `WEBHOOK_DELIVERY_POLL_SECS` (default 5) for retries that
came due and for rows enqueued on other replicas.

- **One lane per endpoint.** Each claim gives a webhook at most 10 of its
  oldest due deliveries, sent one at a time in `next_retry_at` order. A
  webhook with a delivery in flight on any replica is not claimed again. The
  claim takes a transaction-scoped advisory lock per webhook (class 5195) and
  re-checks in-flight state under a snapshot taken after the lock, so two
  replicas never send to one endpoint at once.
- **Up to 8 lanes per replica**, two of which a claim always keeps for
  endpoints that are not failing.
- **The worker never waits for a send.** A receiver that hangs for the 30 s
  send timeout holds up only its own lane. A finished lane wakes the worker.
  After a database error it does not, and the next poll retries.
- **No double sends.** Rows are locked `FOR UPDATE SKIP LOCKED` and stamped
  with a claim token. The claim is re-extended just before each send, and
  every result is written only under that token. A claim whose owner died
  expires after 120 s.

## Failures and backoff

Each delivery keeps its own retry schedule (30 s, 60 s, 120 s, 300 s, ... up
to 24 h) and `max_attempts` (12 by default). On top of that, the endpoint
backs off as a whole.

| Outcome of a send | Delivery | Endpoint |
|---|---|---|
| 2xx | delivered | backoff cleared |
| 400, 409, 413, 415, 422 (the receiver rejected this payload) | rescheduled on its own schedule | not backed off; the lane goes on to the next delivery, and the endpoint's backoff is cleared because it answered |
| no response (connection error, timeout), 3xx, any other 4xx (401, 403, 404, 408, 410, 429, ...), 5xx | rescheduled on its own schedule | backed off; the lane's other deliveries are released without an attempt |

The endpoint backoff (`webhooks.delivery_backoff_until`) grows with
consecutive endpoint-level failures (`webhooks.delivery_failures`): 30 s,
60 s, 120 s, then `WEBHOOK_ENDPOINT_BACKOFF_MAX_SECS` (default 300), each with
±20% jitter per endpoint. No step is shorter than the poll interval, so an
endpoint that just failed is never claimed again straight away. If the
endpoint answered earlier in the same lane, the count restarts at 1. A
delivered send, a payload rejection, or re-enabling the webhook clears it.

With the defaults, a receiver that is down gets about 12 sends an hour, and a
receiver that comes back gets its queue within 5 minutes.

## Settings

| Variable | Default | Effect |
|---|---|---|
| `WEBHOOK_DELIVERY_POLL_SECS` | `5` | Idle poll interval, at least 1 s. Also the shortest endpoint backoff. |
| `WEBHOOK_ENDPOINT_BACKOFF_MAX_SECS` | `300` | Longest endpoint backoff. `0` leaves only the poll-interval floor: one attempt per poll per failing endpoint. |

For the cadence before 1.13 (a 30 s tick, a failing endpoint tried once per
tick), set `WEBHOOK_DELIVERY_POLL_SECS=30` and
`WEBHOOK_ENDPOINT_BACKOFF_MAX_SECS=0`. New deliveries are still sent as soon
as they are enqueued.

## Metrics

| Metric | Meaning |
|---|---|
| `ak_webhook_deliveries_total{event,status}` | Sends, by outcome |
| `ak_webhook_endpoint_failures_total{webhook_id}` | Endpoint-level failed sends |
| `ak_webhook_endpoint_backoff_seconds{webhook_id}` | The endpoint's current backoff; 0 once it recovered |
| `ak_webhook_delivery_backlog{webhook_id}` | Pending deliveries, refreshed every 60 s |
| `ak_webhook_dead_letter_total{event}` | Deliveries that used up their attempts |

## Cost

One claim runs two short statements: an index-only ordered scan per webhook
on `idx_webhook_deliveries_pending_by_webhook` (migration 417), then primary-key
lookups and locks for the picked rows. `scripts/perf/webhook-claim-cost.sh`
measures it on a seeded database.
