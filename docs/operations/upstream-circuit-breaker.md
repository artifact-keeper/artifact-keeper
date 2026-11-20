# Upstream circuit breaker

A Remote repository whose upstream is down used to pay for it on every
request. A refused connection costs a few milliseconds, but an upstream that
drops packets costs the connect timeout (`PROXY_UPSTREAM_CONNECT_TIMEOUT_SECS`,
10 s by default) and one that accepts the connection and never answers costs
the read timeout (`PROXY_UPSTREAM_READ_TIMEOUT_SECS`, 60 s). Only then can the
request fall back to a stale cached copy, the next member of a virtual
repository, or a `503`. Under CI load those waits pile up into request
timeouts (#5013).

Since 1.13.0 every upstream request a Remote repository makes goes through a
circuit breaker for that repository and upstream host. Once the upstream keeps
failing, requests stop contacting it for a while and are answered as
"upstream unavailable" straight away.

## States

| State | What a request does |
|---|---|
| Closed (normal) | Contacts the upstream. `AK_UPSTREAM_CIRCUIT_FAILURES` failures in a row, each within `AK_UPSTREAM_CIRCUIT_WINDOW_SECS` of the one before, open the circuit. |
| Open | Does not contact the upstream. It is answered as unavailable at once (below). |
| Half-open | Once the open period has passed, one request goes to the upstream as a probe. The others are still answered as unavailable. If the probe gets an answer the circuit closes; if it fails, the circuit opens again for a longer period. |

The first open period is `AK_UPSTREAM_CIRCUIT_OPEN_SECS`. It doubles after
every failed probe, up to `AK_UPSTREAM_CIRCUIT_MAX_OPEN_SECS`, and returns to
the first period once the circuit closes. Every period is jittered by ±20 %, so
replicas and repositories do not all probe at the same moment.

## What counts

| The upstream request | Counts as |
|---|---|
| Connect error, DNS failure, connection reset, timeout | Failure |
| `502`, `503`, `504` | Failure |
| Abandoned (a deadline above it, such as the virtual member deadline, gave up on it) after waiting `AK_UPSTREAM_CIRCUIT_SLOW_CALL_SECS` for response headers | Failure |
| Any other answer: `2xx`, `3xx`, `404`, `410`, `401`, `403`, other `4xx` | Success: closes the circuit and resets the count |
| `429`, `500`, `501` and other `5xx`; a refusal by this server's own outbound policy (SSRF, egress proxy) | Neither |

A `404` or `410` is an answer: the upstream is reachable and does not have the
object. It never trips the circuit, and while the circuit is closed it is
still served as a miss. A `429` is a request to slow down and a `500` is
usually about one object, so neither cuts off every other path of the
upstream.

## What an open circuit answers

The refused request gets the same error class as an upstream outage
(`503 Service Unavailable`), so everything that already handles an outage
handles it the same way:

- A Remote with a cached copy serves it under
  [stale-if-error](../proxy-cache-freshness.md) within its grace window, with
  `Warning: 110` and `X-AK-Stale-Since`, without first waiting for the
  upstream.
- A virtual repository treats the member as unavailable: a lower-priority
  member serves, a metadata merge serves the other members marked partial
  ([`virtual_metadata_partial`](../virtual-metadata-merges.md)), and when no
  member can answer the response is `503` with `Retry-After`, not a cacheable
  `404`. With [strict member fallback](../virtual-downloads.md#strict-member-fallback)
  the `503` comes at once.
- It is never a miss: an open circuit cannot turn into a `404` for the client
  or a negative cache entry, because the upstream was not asked.
- Scan-on-proxy and the other serve gates are unchanged. An open circuit only
  stops the upstream request; it never serves bytes that the gates would not
  serve when the upstream is down.

## Interactions

- **Virtual download member breaker** (`AK_VIRTUAL_MEMBER_BREAKER_*`,
  [virtual downloads](../virtual-downloads.md#the-member-breaker)). That
  breaker is per member and covers only downloads through a virtual, and it
  also counts a missed download deadline. This one sits below it, on every
  upstream request of the Remote, metadata included. A download refused by
  this circuit does not count against the member breaker, so the two do not
  keep each other open once the upstream is back.
- **Go credentialed refusals** (#6238). When a Go Remote's upstream answers
  `401`/`403` to configured credentials, the Go routes answer `502`/`503`.
  The upstream did answer, so the circuit counts it as a success and does not
  open: a credentials problem is not fixed by waiting, the refusal is
  already fast, and the next request should see new credentials at once.
- **Buffered metadata budget** (`AK_PROXY_METADATA_BUDGET_BYTES`). A buffered
  metadata fetch holds its byte reservation while it waits for the upstream.
  With the circuit open the reservation is released at once, so a dead
  upstream no longer ties up the budget other metadata requests are waiting
  for.
- **Several replicas.** The state is in memory on each replica, which learns
  of an outage after its own `AK_UPSTREAM_CIRCUIT_FAILURES` requests. That is
  deliberate: an open circuit only replaces "wait for the upstream" with
  "the upstream is unavailable", so replicas need not agree; sharing the
  state would add a database round trip to every upstream request and make
  the breaker depend on a second system during the partial outages it is for;
  and a replica whose own egress is broken should open on its own. A restart
  closes every circuit.
- Circuits are per repository and host (with port): one dead Remote never
  refuses requests for another Remote on the same host, and a redirect or
  token host has its own circuit.

## Settings

| Variable | Default | Meaning |
|---|---|---|
| `AK_UPSTREAM_CIRCUIT_FAILURES` | `5` | Failures in a row that open the circuit (at least 1). |
| `AK_UPSTREAM_CIRCUIT_WINDOW_SECS` | `120` | A failure more than this long after the previous one starts a new count. |
| `AK_UPSTREAM_CIRCUIT_OPEN_SECS` | `10` | First open period. `0` disables the breaker. |
| `AK_UPSTREAM_CIRCUIT_MAX_OPEN_SECS` | `300` | Longest open period the backoff reaches. |
| `AK_UPSTREAM_CIRCUIT_SLOW_CALL_SECS` | `10` | An abandoned request that waited this long for response headers counts as a failure. `0`: never. |

To keep the behaviour of 1.12 (every request contacts the upstream), set
`AK_UPSTREAM_CIRCUIT_OPEN_SECS=0`.

## Metrics and logs

Labels are `repository_id` (the Remote's id) and `host` (`host:port`).

- `ak_upstream_circuit_state` (gauge): `0` closed, `1` open, `2` half-open.
- `ak_upstream_circuit_opens_total` (counter): openings, a reopen after a
  failed probe included.
- `ak_upstream_circuit_short_circuited_total` (counter): requests answered
  without contacting the upstream.

Opening logs a `WARN` with the reason, the failure count and the open period;
letting a probe through logs an `INFO`, and closing logs an `INFO`.
