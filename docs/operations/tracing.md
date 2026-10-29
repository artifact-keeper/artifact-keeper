# Distributed tracing: `traceparent` and the span reference

With `OTEL_EXPORTER_OTLP_ENDPOINT` set, the backend exports OpenTelemetry spans
over OTLP (the variables, protocols and the log and metric signals are in
[logging.md](logging.md)). This page covers two things operators ask about:
how a request joins the trace of the proxy or client in front of the backend
(`traceparent`), and which spans and attributes the backend exports, so that
dashboards, span metrics and trace searches can be built on them.

Nothing on this page applies while OTLP export is off: the W3C propagator is
installed only on the OTLP path, so `traceparent` is then neither adopted nor
sent upstream (it is still used as a correlation-ID fallback, see below).

## Inbound trace context (`traceparent`, `tracestate`)

The backend honours the [W3C Trace Context](https://www.w3.org/TR/trace-context/)
headers `traceparent` and `tracestate` on every HTTP request. No other
propagation format (B3, Jaeger `uber-trace-id`, X-Ray) is read.

**What a valid header does.** The request's `http_request` span (kind `SERVER`)
becomes a child of the span the header names: it carries the header's trace id,
and its parent span id is the header's parent id. The request's spans and the
caller's are then one trace. The header is valid when it has at least four
fields (exactly four for version `00`), a version other than `ff`, a trace id of
exactly 32 and a parent id of exactly 16 lowercase hex characters, and neither
id is all zeros. A header that is not valid is ignored, and the request starts a
new root trace. A `tracestate` over the W3C limits (32 members or 512
characters) is dropped and `traceparent` is still used.

**Sampling.** The default sampler, `parentbased_always_on`, follows the
header's sampled flag: a request whose `traceparent` ends in `-00` is not
traced. The other samplers and `OTEL_TRACES_SAMPLER_ARG` are described in
`.env.example`, and the startup line `OpenTelemetry tracing enabled` reports the
one in force.

**Who may set the parent.** The header is unauthenticated, and under the
`parentbased_*` samplers its sampled flag decides whether a request is traced.
Once `RATE_LIMIT_TRUSTED_PROXY_CIDRS` lists your reverse proxies (the same list
that decides whether `X-Forwarded-For` is believed), only a request whose TCP
peer is inside one of those ranges may set the parent. Every other request
starts a fresh root trace. With the list empty (the default, kept for backward
compatibility) the header is accepted from any client. The backend then logs a
startup warning when the sampler is `parentbased_always_off` or
`parentbased_traceidratio`, because any caller could force export of a trace
the sampler would drop.

**Correlation ID.** Independently of tracing, the backend gives every request a
correlation ID, echoed in the `X-Correlation-ID` response header and recorded
on the request span and its log lines as `correlation_id`. It is, in this
order: the request's `X-Correlation-ID`; `x-request-id`, but only from a
trusted proxy; the trace id of a `traceparent`; a new UUID. A request with a
valid `traceparent` and no `X-Correlation-ID` therefore answers with its trace
id in `X-Correlation-ID`, even while OTLP export is off.

### Configuring the proxy in front of the backend

To see a request end to end, the reverse proxy or ingress must send
`traceparent` to the backend:

1. **Forward or originate the header.** A proxy that is not instrumented passes
   `traceparent` and `tracestate` through as ordinary request headers, so the
   client's trace continues into the backend. A proxy that is instrumented and
   exports to the same collector should send the `traceparent` of its own span
   (most do this once their tracing is turned on), so the backend's span is a
   child of the proxy's. A proxy that strips unknown headers must be told to
   keep these two.
2. **Trust the proxy.** Set `RATE_LIMIT_TRUSTED_PROXY_CIDRS` to the addresses
   the backend sees the proxy connect from (for an ingress controller in
   Kubernetes, the controller pods' range, not the Service address). Clients
   that reach the backend directly then cannot choose the trace.
3. **Check it.** Send one request with a header you made up, through the
   proxy:

   ```bash
   TID=$(openssl rand -hex 16); SID=$(openssl rand -hex 8)
   curl -s -o /dev/null -D - -H "traceparent: 00-${TID}-${SID}-01" \
     https://registry.example.com/health | grep -i x-correlation-id
   echo "expected ${TID}"
   ```

   An uninstrumented proxy forwards the header, so `X-Correlation-ID` is
   `${TID}`, and in the trace store the backend's `http_request` span has trace
   id `${TID}` and parent `${SID}`. Behind an instrumented proxy the trace id is
   still `${TID}`, and the parent is the proxy's span. If the backend's span is
   a root with a different trace id, the header did not arrive or the proxy is
   not in `RATE_LIMIT_TRUSTED_PROXY_CIDRS`.

### Outbound: upstream requests

Every request the backend sends to an upstream registry (proxy fetches,
metadata revalidation, token exchanges, the repository "test upstream" check,
the curation sync and its popularity lookups) carries the `traceparent` of its
own `CLIENT` span, plus the inbound `tracestate`. An upstream that is itself
instrumented joins the trace. Because an untrusted client's trace id and
`tracestate` are relayed to third-party upstreams while the trusted-proxy list
is empty, set `RATE_LIMIT_TRUSTED_PROXY_CIDRS` if that matters to you. The
values are validated, so this is not a header-injection path.

## Span reference

All spans carry the resource attributes `service.name` (`OTEL_SERVICE_NAME`,
default `artifact-keeper`), `service.version` and `service.instance.id`.
Every span except the database statement spans (which are built directly,
not from a `tracing` span) also carries the attributes the tracing bridge adds:
the code location and thread (`code.file.path`, `code.module.name`,
`code.line.number`, `thread.id`, `thread.name`), the `tracing` target
(`target`), and the time the span was busy and idle in nanoseconds (`busy_ns`,
`idle_ns`). The tables below list the rest.

A span is marked as an error (status `ERROR`) only where its section says so,
and then `error.type` names the cause.

### `http_request` (kind `SERVER`)

The root span of every HTTP request; the parent of everything else in the
request. One per request.

| Attribute | Type | Value |
|---|---|---|
| `method` | string | HTTP method. |
| `uri` | string | Request path and query, with credentials and tokens in the query removed. |
| `correlation_id` | string | The correlation ID (see above). |
| `request_id` | string | A trusted proxy's `x-request-id`, when it differs from the correlation ID. |
| `http.route` | string | The matched route template (`/api/v1/repositories/:key`), the same value as the `path` label of `ak_http_request_duration_seconds`. Absent when no route matched. |
| `http.response.status_code` | integer | Response status. |
| `http.response.body.size` | integer | Response body size, when known before streaming (`Content-Length` or an exact body size). |
| `error.type` | string | On a 5xx the span is an error and this is the status code. A 4xx is the client's error and does not mark the span. |
| `artifact_keeper.repository.key` | string | The repository the request resolved to, once it names an existing repository. |
| `artifact_keeper.cache.outcome` | string | The proxy-cache outcome, see below. |

`artifact_keeper.repository.key` and `artifact_keeper.cache.outcome` are span
attributes only, never metric labels, and are recorded once when the request
completes (the last value wins), so log lines emitted during the request do not
show them. The outcome takes the values of the `result` label of
`ak_proxy_cache_lookups_total`, or those of the streaming cache probe:

| Value | Meaning |
|---|---|
| `hit` | A valid cached copy was served. |
| `miss` | Streaming probe: nothing cached; fetched from upstream. |
| `negative_hit` | A cached "not found" from the upstream was served. |
| `miss_no_metadata` | No cache metadata for the key (first request, or evicted). |
| `miss_expired` | Cached, but past its expiry; revalidated or refetched. |
| `miss_no_content` | Metadata present, content gone (an eviction race). |
| `miss_checksum_mismatch` | Cached content did not match its recorded checksum. |
| `error` | The storage backend failed, so the lookup could not decide. |

### Phase spans (kind `INTERNAL`)

Children of `http_request` around the major phases, at `INFO` so they are not
lost under `RUST_LOG=info`.

| Span | When | Attributes |
|---|---|---|
| `authenticate` | Credential verification for a request that carries credentials. | none |
| `resolve_virtual_members` | A virtual repository probes its members. | `artifact_keeper.virtual.member_count` (integer) |
| `proxy_fetch` | A Remote repository fetches through its cache. | `artifact_keeper.repository.key`, `artifact_keeper.proxy.mode` (`buffered` or `streaming`) |

### Upstream requests (kind `CLIENT`)

One span per request to an upstream registry, named after the HTTP method
(`GET`, `HEAD`, ...) as the HTTP semantic conventions require. Its internal name
`upstream_request` is what stdout shows. It covers DNS, connect, TLS, redirects
and the wait for response headers; the body transfer happens after the span
ends, so for a large file it measures time to first byte.

| Attribute | Type | Value |
|---|---|---|
| `http.request.method` | string | HTTP method. |
| `url.full` | string | The upstream URL without credentials, query or fragment. |
| `server.address` | string | Upstream host. |
| `server.port` | integer | Upstream port (the scheme default when the URL has none). |
| `http.response.status_code` | integer | Upstream status, when a response arrived. |
| `error.type` | string | On error: the status code, or for a request that got no response `timeout`, `connect`, `redirect`, `builder`, `body`, `request` or `_OTHER`. |

The span is an error for any 4xx or 5xx, and for any request that got no
response. One exception: a `401` to a request sent without credentials is the
expected first step of the OCI bearer-token exchange and is not an error. A
`401` to a request that carried credentials is.

Before 1.12.0 `server.port` and `http.response.status_code` were exported as
strings, and the repository "test upstream" check, the curation sync and the
popularity lookups sent no span at all. The scheduled curation sync runs
outside any request, so each of its fetches is the root of a trace of its own.

### Database statements (kind `CLIENT`)

One span per SQL statement, built from the statement sqlx reports when it
finishes and backdated by its duration, as a child of the span the statement
ran under. A statement that runs outside any span (startup, a background job)
produces none. The SQL text is never exported.

| Attribute | Type | Value |
|---|---|---|
| (span name) | | `db.query.summary`: `"<operation> <table>"`, for example `SELECT repositories`, or the operation alone. |
| `db.system.name` | string | `postgresql`. |
| `db.query.summary` | string | As the span name. |
| `db.operation.name` | string | `SELECT`, `INSERT`, `UPDATE`, `DELETE`, ... |
| `db.collection.name` | string | The table, when one is recognised (a best-effort scan, not a SQL parser). |
| `db.response.returned_rows` | integer | Rows returned. |
| `artifact_keeper.db.slow_statement` | boolean | `true` when sqlx flagged the statement as slow (over 1 s). |

Which statements become spans depends on `DB_QUERY_SPANS` (see
[logging.md](logging.md)). The default, `log`, follows `RUST_LOG`, so under the
default filter only slow statements become spans. `all` makes a span of every
statement without logging them on stdout, and `off` turns database spans off.

### Storage operations (kind `CLIENT`; `INTERNAL` for the filesystem backend)

One span per storage call of the filesystem, S3, Azure and GCS backends, named
after the operation's function (`put`, `get`, `exists`, `delete`, ...).

| Attribute | Type | Value |
|---|---|---|
| `storage.system` | string | `filesystem`, `s3`, `azure` or `gcs`. |
| `storage.operation` | string | The operation (`put`, `get`, `get_range`, `get_stream`, `put_stream`, `exists`, `delete`, `copy`, ...). |
| `key` (and the call's other arguments) | string | The storage key the call addressed. |

A failed call records its error message as an `INFO` event on the span.

### Background work (kind `INTERNAL`)

A few background workers open spans of their own, outside any request:

| Span | When | Attributes |
|---|---|---|
| `dispatch_event` | The email notification dispatcher handles one domain event. | `event_type`, `entity_id`, `repository_id`, and `event` (the whole event, debug-formatted) |
| `update_job_status`, `claim_job_running`, `finalize_job_status` | A migration job changes state. | `job_id`, `status` where the call has one |
| `complete_item`, `fail_item`, `skip_item` | A migration item finishes. | `item_id` and the call's other arguments (`target_path`, `checksum_target`, `error_message`, `reason`) |

## Building on the spans

- **Latency breakdown of one request**: the children of `http_request` are the
  phases, upstream requests, statements and storage calls. Gaps between them
  are time in the backend's own code.
- **Span metrics**: group `SERVER` spans by `http.route` and
  `http.response.status_code`. Group upstream `CLIENT` spans by
  `server.address` and `http.response.status_code`, which are integers, so
  `>= 500` works.
- **Finding a request class**: search `http_request` spans by
  `artifact_keeper.repository.key` and `artifact_keeper.cache.outcome` (for
  example `miss_expired` for one repository).
- **Joining logs**: with `OTEL_LOGS_EXPORTER=otlp` every log record emitted
  inside a request carries that request's trace and span ids. On stdout, join
  on `correlation_id`.
